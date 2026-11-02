#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace Sentinel {

struct TlsClientHelloInfo {
    uint16_t tls_version;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t> ec_point_formats;
};

class TlsFingerprinter {
public:
    static std::string calculate_ja3_raw(const TlsClientHelloInfo& info);
};

} // namespace Sentinel
