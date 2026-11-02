#pragma once
#include <cstdint>
#include <string>

namespace Sentinel {

struct FlowMetrics {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t duration_ms;
    double bytes_per_second;
};

class FlowStatsExporter {
public:
    static FlowMetrics compute(uint64_t packets, uint64_t bytes, uint32_t duration_ms);
};

} // namespace Sentinel
