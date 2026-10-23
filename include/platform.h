#pragma once

#include <cstdint>

#if defined(_WIN32)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

namespace SentinelDPI {
namespace Platform {

inline uint16_t netToHost16(uint16_t val) {
    return ntohs(val);
}

inline uint32_t netToHost32(uint32_t val) {
    return ntohl(val);
}

inline uint16_t hostToNet16(uint16_t val) {
    return htons(val);
}

inline uint32_t hostToNet32(uint32_t val) {
    return htonl(val);
}

} // namespace Platform
} // namespace SentinelDPI
