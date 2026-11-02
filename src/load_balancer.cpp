#include "load_balancer.h"
#include <functional>

namespace SentinelDPI {

LoadBalancer::LoadBalancer(size_t lb_id,
                           ThreadSafeQueue<RawPacket>* input_queue,
                           const std::vector<ThreadSafeQueue<RawPacket>*>& fp_queues)
    : lb_id_(lb_id), input_queue_(input_queue), fp_queues_(fp_queues) {}

LoadBalancer::~LoadBalancer() {
    stop();
    join();
}

void LoadBalancer::start() {
    running_ = true;
    worker_thread_ = std::thread(&LoadBalancer::workerLoop, this);
}

void LoadBalancer::stop() {
    running_ = false;
}

void LoadBalancer::join() {
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void LoadBalancer::workerLoop() {
    if (fp_queues_.empty()) return;

    while (running_) {
        auto opt_packet = input_queue_->pop();
        if (!opt_packet.has_value()) {
            break;
        }

        RawPacket raw = std::move(opt_packet.value());
        size_t hash = computeHash(raw);
        size_t fp_idx = hash % fp_queues_.size();

        fp_queues_[fp_idx]->push(std::move(raw));
        dispatched_count_++;
    }
}

size_t LoadBalancer::computeHash(const RawPacket& packet) {
    // Quick hash over packet IP/Port bytes if available
    if (packet.data.size() >= 34) {
        // Bytes 26-33 are typically IPv4 src/dest in Ethernet frames
        uint32_t src_ip = *reinterpret_cast<const uint32_t*>(packet.data.data() + 26);
        uint32_t dest_ip = *reinterpret_cast<const uint32_t*>(packet.data.data() + 30);
        return std::hash<uint32_t>{}(src_ip ^ dest_ip);
    }
    return std::hash<size_t>{}(packet.packet_number);
}

} // namespace SentinelDPI
