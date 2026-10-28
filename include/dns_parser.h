#pragma once

#include <cstdint>
#include <string>
#include <optional>

namespace SentinelDPI {

class DNSParser {
public:
    static std::optional<std::string> extractQueryDomain(const uint8_t* payload, size_t length);
    static double calculateEntropy(const std::string& domain);
    static bool isSuspiciousTunneling(const std::string& domain, double threshold = 3.8);
};

} // namespace SentinelDPI
