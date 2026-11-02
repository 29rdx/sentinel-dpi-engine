#pragma once
#include "types.h"

namespace Sentinel {

class AdvancedHeuristics {
public:
    static bool detect_syn_flood(uint32_t syn_count, uint32_t ack_count, double threshold = 5.0);
    static bool detect_null_scan(uint8_t tcp_flags);
    static bool detect_xmas_scan(uint8_t tcp_flags);
};

} // namespace Sentinel
