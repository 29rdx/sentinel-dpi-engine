#include "heuristic_threats.h"

namespace Sentinel {

bool AdvancedHeuristics::detect_syn_flood(uint32_t syn_count, uint32_t ack_count, double threshold) {
    if (ack_count == 0) return syn_count > 50;
    return (static_cast<double>(syn_count) / ack_count) >= threshold;
}

bool AdvancedHeuristics::detect_null_scan(uint8_t tcp_flags) {
    return tcp_flags == 0;
}

bool AdvancedHeuristics::detect_xmas_scan(uint8_t tcp_flags) {
    // FIN (0x01) | URG (0x20) | PSH (0x08) = 0x29
    return (tcp_flags & 0x29) == 0x29;
}

} // namespace Sentinel
