#include <iostream>
#include <chrono>
#include "fast_path_ring.h"

int main() {
    Sentinel::FastPathRing ring;
    uint8_t packet[64] = {0};
    uint8_t out[64];
    size_t out_len;
    constexpr size_t ITERATIONS = 1000000;

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < ITERATIONS; ++i) {
        ring.enqueue(packet, 64);
        ring.dequeue(out, out_len);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> ms = end - start;
    std::cout << "Processed " << ITERATIONS << " packets in " << ms.count() << " ms ("
              << (ITERATIONS / ms.count() * 1000.0) << " pkts/sec)" << std::endl;
    return 0;
}
