#pragma once

#include <cstdint>
#include <string>
#include <optional>

namespace SentinelDPI {

class SNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);

private:
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

} // namespace SentinelDPI
