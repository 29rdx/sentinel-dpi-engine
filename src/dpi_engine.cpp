#include "dpi_engine.h"
#include <iostream>
#include <chrono>

namespace SentinelDPI {

DPIEngine::DPIEngine(const DPIConfig& config)
    : config_(config), output_queue_(50000) {}

DPIEngine::~DPIEngine() {
    output_running_ = false;
    output_queue_.stop();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
}

bool DPIEngine::initialize() {
    if (!config_.rules_file.empty()) {
        rule_manager_.loadRulesFromFile(config_.rules_file);
    }

    size_t total_fps = config_.num_lbs * config_.fps_per_lb;
    fp_queues_.clear();
    fast_paths_.clear();

    for (size_t i = 0; i < total_fps; i++) {
        auto fp_q = std::make_unique<ThreadSafeQueue<RawPacket>>(20000);
        auto fp = std::make_unique<FastPath>(i, fp_q.get(), &output_queue_, &rule_manager_, &threat_detector_);
        fp_queues_.push_back(std::move(fp_q));
        fast_paths_.push_back(std::move(fp));
    }

    lb_queues_.clear();
    load_balancers_.clear();

    std::vector<ThreadSafeQueue<RawPacket>*> raw_fp_queues;
    for (const auto& q : fp_queues_) {
        raw_fp_queues.push_back(q.get());
    }

    for (size_t i = 0; i < config_.num_lbs; i++) {
        auto lb_q = std::make_unique<ThreadSafeQueue<RawPacket>>(20000);
        auto lb = std::make_unique<LoadBalancer>(i, lb_q.get(), raw_fp_queues);
        lb_queues_.push_back(std::move(lb_q));
        load_balancers_.push_back(std::move(lb));
    }

    return true;
}

bool DPIEngine::processFile(const std::string& input_pcap, const std::string& output_pcap) {
    PCAPReader reader;
    if (!reader.open(input_pcap)) {
        std::cerr << "[!] Error: Failed to open input PCAP: " << input_pcap << "\n";
        return false;
    }

    writer_ = std::make_unique<PCAPWriter>();
    if (!writer_->open(output_pcap)) {
        std::cerr << "[!] Error: Failed to open output PCAP for writing: " << output_pcap << "\n";
        return false;
    }

    // Start all workers
    output_running_ = true;
    output_thread_ = std::thread(&DPIEngine::outputWorker, this);

    for (auto& fp : fast_paths_) fp->start();
    for (auto& lb : load_balancers_) lb->start();

    auto t_start = std::chrono::high_resolution_clock::now();
    size_t packet_count = 0;
    size_t total_bytes = 0;

    // Stream packets from reader to LBs round-robin
    size_t lb_idx = 0;
    while (auto opt_pkt = reader.readNextPacket()) {
        total_bytes += opt_pkt->data.size();
        packet_count++;
        lb_queues_[lb_idx]->push(std::move(opt_pkt.value()));
        lb_idx = (lb_idx + 1) % lb_queues_.size();
    }

    // Stop LBs once all queues empty
    for (auto& lb : load_balancers_) lb->stop();
    for (auto& q : lb_queues_) q->stop();
    for (auto& lb : load_balancers_) lb->join();

    // Stop FPs once all queues empty
    for (auto& fp : fast_paths_) fp->stop();
    for (auto& q : fp_queues_) q->stop();
    for (auto& fp : fast_paths_) fp->join();

    // Stop output thread
    output_running_ = false;
    output_queue_.stop();
    if (output_thread_.joinable()) output_thread_.join();

    auto t_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = t_end - t_start;

    stats_.total_packets_read = packet_count;
    stats_.elapsed_seconds = elapsed.count();
    stats_.mpps = (stats_.elapsed_seconds > 0) ? (packet_count / stats_.elapsed_seconds / 1e6) : 0.0;
    stats_.mbps = (stats_.elapsed_seconds > 0) ? ((total_bytes * 8.0) / stats_.elapsed_seconds / 1e6) : 0.0;

    for (const auto& fp : fast_paths_) {
        stats_.total_packets_dropped += fp->getDroppedCount();
    }
    stats_.total_packets_forwarded = packet_count - stats_.total_packets_dropped;
    stats_.total_threats_blocked = threat_detector_.getReport().total_threats();

    reader.close();
    writer_->close();
    return true;
}

void DPIEngine::outputWorker() {
    while (true) {
        auto opt_item = output_queue_.pop();
        if (!opt_item.has_value()) {
            break;
        }

        auto [packet, action] = std::move(opt_item.value());
        if (action == PacketAction::FORWARD) {
            if (writer_) {
                writer_->writePacket(packet);
            }
        }
    }
}

} // namespace SentinelDPI
