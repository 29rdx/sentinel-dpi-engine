#include "fast_path.h"
#include <cstring>

namespace Sentinel {

FastPathRing::FastPathRing() : head_(0), tail_(0) {}

bool FastPathRing::enqueue(const uint8_t* packet, size_t len) {
    if (len > 2048) return false;
    size_t current_tail = tail_.load(std::memory_order_relaxed);
    size_t next_tail = (current_tail + 1) % FAST_PATH_RING_SIZE;
    if (next_tail == head_.load(std::memory_order_acquire)) {
        return false; // Ring full
    }
    std::memcpy(slots_[current_tail].data, packet, len);
    slots_[current_tail].length = len;
    tail_.store(next_tail, std::memory_order_release);
    return true;
}

bool FastPathRing::dequeue(uint8_t* out_buffer, size_t& out_len) {
    size_t current_head = head_.load(std::memory_order_relaxed);
    if (current_head == tail_.load(std::memory_order_acquire)) {
        return false; // Ring empty
    }
    out_len = slots_[current_head].length;
    std::memcpy(out_buffer, slots_[current_head].data, out_len);
    head_.store((current_head + 1) % FAST_PATH_RING_SIZE, std::memory_order_release);
    return true;
}

} // namespace Sentinel
