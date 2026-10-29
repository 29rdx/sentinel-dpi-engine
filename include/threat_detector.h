#pragma once

#include "types.h"
#include <unordered_map>
#include <chrono>
#include <mutex>

namespace SentinelDPI {

class ThreatDetector {
public:
    ThreatDetector() = default;

    ThreatType inspectPacket(ParsedPacket& packet);

    struct ThreatReport {
        size_t syn_floods = 0;
        size_t xmas_scans = 0;
        size_t null_scans = 0;
        size_t syn_scans = 0;
        size_t dns_tunnels = 0;
        size_t malicious_signatures = 0;
        size_t total_threats() const {
            return syn_floods + xmas_scans + null_scans + syn_scans + dns_tunnels + malicious_signatures;
        }
    };

    ThreatReport getReport() const;

private:
    mutable std::mutex mutex_;
    ThreatReport report_;

    // Tracking SYN velocity per source IP
    struct SynTrack {
        size_t count = 0;
        uint32_t first_ts = 0;
    };
    std::unordered_map<std::string, SynTrack> syn_velocity_map_;

    bool checkPayloadSignatures(const uint8_t* payload, size_t length, std::string& match_desc);
};

} // namespace SentinelDPI
