#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace SentinelDPI {

template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 50000)
        : max_size_(max_size), stopped_(false) {}

    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stopped_) return false;
        not_full_.wait(lock, [this]() { return queue_.size() < max_size_ || stopped_; });
        if (stopped_) return false;

        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this]() { return !queue_.empty() || stopped_; });
        if (queue_.empty()) return std::nullopt;

        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    bool stopped_;
};

} // namespace SentinelDPI
