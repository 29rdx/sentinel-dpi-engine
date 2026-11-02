#pragma once
#include <cstdint>
#include <string>

namespace Sentinel {

class FlowLoadBalancer {
public:
    static uint32_t hash_5tuple(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto);
    static uint32_t select_core(uint32_t hash, uint32_t num_cores);
};

} // namespace Sentinel
