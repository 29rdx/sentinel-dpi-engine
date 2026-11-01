#pragma once

#include "types.h"
#include "thread_safe_queue.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "fast_path.h"
#include "load_balancer.h"
#include "threat_detector.h"
#include "rule_manager.h"
#include <string>
#include <vector>
#include <memory>
#include <chrono>

namespace SentinelDPI {

struct DPIConfig {
    size_t num_lbs = 2;
    size_t fps_per_lb = 2;
    std::string rules_file;
    bool verbose = false;
};

struct DPIStats {
    size_t total_packets_read = 0;
    size_t total_packets_forwarded = 0;
    size_t total_packets_dropped = 0;
    size_t total_threats_blocked = 0;
    double elapsed_seconds = 0.0;
    double mpps = 0.0;
    double mbps = 0.0;
};

class DPIEngine {
public:
    explicit DPIEngine(const DPIConfig& config = DPIConfig());
    ~DPIEngine();

    bool initialize();
    bool processFile(const std::string& input_pcap, const std::string& output_pcap);

    RuleManager& getRuleManager() { return rule_manager_; }
    ThreatDetector& getThreatDetector() { return threat_detector_; }
    DPIStats getStats() const { return stats_; }

private:
    DPIConfig config_;
    DPIStats stats_;

    RuleManager rule_manager_;
    ThreatDetector threat_detector_;

    // Queues
    std::vector<std::unique_ptr<ThreadSafeQueue<RawPacket>>> lb_queues_;
    std::vector<std::unique_ptr<ThreadSafeQueue<RawPacket>>> fp_queues_;
    ThreadSafeQueue<std::pair<RawPacket, PacketAction>> output_queue_;

    // Threads
    std::vector<std::unique_ptr<LoadBalancer>> load_balancers_;
    std::vector<std::unique_ptr<FastPath>> fast_paths_;
    std::unique_ptr<PCAPWriter> writer_;
    std::thread output_thread_;

    std::atomic<bool> output_running_{false};
    void outputWorker();
};

} // namespace SentinelDPI
