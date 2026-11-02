#include "load_balancer.h"

namespace Sentinel {

uint32_t FlowLoadBalancer::hash_5tuple(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    // MurmurHash3 inspired mixer
    uint32_t h = src_ip ^ dst_ip ^ (static_cast<uint32_t>(src_port) << 16 | dst_port) ^ proto;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

uint32_t FlowLoadBalancer::select_core(uint32_t hash, uint32_t num_cores) {
    if (num_cores == 0) return 0;
    return hash % num_cores;
}

} // namespace Sentinel
