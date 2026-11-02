#pragma once

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "threat_detector.h"
#include "rule_manager.h"
#include <thread>
#include <atomic>
#include <memory>

namespace SentinelDPI {

class FastPath {
public:
    FastPath(size_t worker_id,
             ThreadSafeQueue<RawPacket>* input_queue,
             ThreadSafeQueue<std::pair<RawPacket, PacketAction>>* output_queue,
             RuleManager* rule_manager,
             ThreatDetector* threat_detector);
    ~FastPath();

    void start();
    void stop();
    void join();

    size_t getProcessedCount() const { return processed_count_.load(); }
    size_t getDroppedCount() const { return dropped_count_.load(); }
    ConnectionTracker& getConnectionTracker() { return conn_tracker_; }

private:
    [[maybe_unused]] size_t worker_id_;
    ThreadSafeQueue<RawPacket>* input_queue_;
    ThreadSafeQueue<std::pair<RawPacket, PacketAction>>* output_queue_;
    RuleManager* rule_manager_;
    ThreatDetector* threat_detector_;

    ConnectionTracker conn_tracker_;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;

    std::atomic<size_t> processed_count_{0};
    std::atomic<size_t> dropped_count_{0};

    void workerLoop();
    ApplicationType classifyBySNI(const std::string& sni);
};

} // namespace SentinelDPI
