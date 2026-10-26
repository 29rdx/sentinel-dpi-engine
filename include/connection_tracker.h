#pragma once

#include "types.h"
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace SentinelDPI {

struct ConnectionState {
    FiveTuple tuple;
    ApplicationType app = ApplicationType::UNKNOWN;
    std::string sni;
    PacketAction action = PacketAction::FORWARD;
    size_t packet_count = 0;
    size_t byte_count = 0;
    uint32_t last_seen_sec = 0;
    bool is_classified = false;
};

class ConnectionTracker {
public:
    ConnectionTracker(size_t max_entries = 100000, uint32_t timeout_sec = 300);

    ConnectionState* getOrCreate(const FiveTuple& tuple, uint32_t current_ts);
    void update(const FiveTuple& tuple, size_t bytes, uint32_t current_ts);
    void setAction(const FiveTuple& tuple, PacketAction action, ApplicationType app, const std::string& sni);
    void evictExpired(uint32_t current_ts);
    size_t activeCount() const;

private:
    size_t max_entries_;
    uint32_t timeout_sec_;
    mutable std::mutex mutex_;
    std::unordered_map<FiveTuple, ConnectionState> table_;
};

} // namespace SentinelDPI
