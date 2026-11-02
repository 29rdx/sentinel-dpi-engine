#pragma once

#include "types.h"
#include "thread_safe_queue.h"
#include <thread>
#include <atomic>
#include <vector>

namespace SentinelDPI {

class LoadBalancer {
public:
    LoadBalancer(size_t lb_id,
                 ThreadSafeQueue<RawPacket>* input_queue,
                 const std::vector<ThreadSafeQueue<RawPacket>*>& fp_queues);
    ~LoadBalancer();

    void start();
    void stop();
    void join();

    size_t getDispatchedCount() const { return dispatched_count_.load(); }

private:
    [[maybe_unused]] size_t lb_id_;
    ThreadSafeQueue<RawPacket>* input_queue_;
    std::vector<ThreadSafeQueue<RawPacket>*> fp_queues_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    std::atomic<size_t> dispatched_count_{0};

    void workerLoop();
    size_t computeHash(const RawPacket& packet);
};

} // namespace SentinelDPI
