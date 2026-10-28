#include "dns_parser.h"
#include <cmath>
#include <unordered_map>

namespace SentinelDPI {

std::optional<std::string> DNSParser::extractQueryDomain(const uint8_t* payload, size_t length) {
    // DNS header is 12 bytes
    if (length < 13) return std::nullopt;

    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return std::nullopt;

    size_t offset = 12; // Start of Question Section
    std::string domain;

    while (offset < length) {
        uint8_t label_len = payload[offset++];
        if (label_len == 0) {
            break; // End of QNAME
        }

        // Pointer compression check
        if ((label_len & 0xC0) == 0xC0) {
            offset++;
            break;
        }

        if (offset + label_len > length) {
            return std::nullopt; // Truncated label
        }

        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(payload + offset), label_len);
        offset += label_len;
    }

    return domain.empty() ? std::nullopt : std::make_optional(domain);
}

double DNSParser::calculateEntropy(const std::string& domain) {
    if (domain.empty()) return 0.0;
    std::unordered_map<char, size_t> freq;
    for (char c : domain) {
        if (c != '.') freq[c]++;
    }

    size_t total = 0;
    for (const auto& [c, count] : freq) total += count;
    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (const auto& [c, count] : freq) {
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool DNSParser::isSuspiciousTunneling(const std::string& domain, double threshold) {
    // Check if subdomains are unusually long or have high Shannon entropy
    size_t first_dot = domain.find('.');
    if (first_dot != std::string::npos && first_dot > 25) {
        std::string subdomain = domain.substr(0, first_dot);
        if (calculateEntropy(subdomain) >= threshold) {
            return true;
        }
    }
    return false;
}

} // namespace SentinelDPI
