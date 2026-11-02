#pragma once
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <vector>

namespace Sentinel {

constexpr size_t FAST_PATH_RING_SIZE = 1024;

struct PacketSlot {
    uint8_t data[2048];
    size_t length;
};

class FastPathRing {
public:
    FastPathRing();
    bool enqueue(const uint8_t* packet, size_t len);
    bool dequeue(uint8_t* out_buffer, size_t& out_len);

private:
    PacketSlot slots_[FAST_PATH_RING_SIZE];
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
};

} // namespace Sentinel
