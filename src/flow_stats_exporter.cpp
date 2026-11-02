#include "flow_stats_exporter.h"

namespace Sentinel {

FlowMetrics FlowStatsExporter::compute(uint64_t packets, uint64_t bytes, uint32_t duration_ms) {
    FlowMetrics m;
    m.total_packets = packets;
    m.total_bytes = bytes;
    m.duration_ms = duration_ms;
    m.bytes_per_second = (duration_ms > 0) ? (static_cast<double>(bytes) * 1000.0 / duration_ms) : 0.0;
    return m;
}

} // namespace Sentinel
