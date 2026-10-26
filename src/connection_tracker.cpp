#include "connection_tracker.h"

namespace SentinelDPI {

ConnectionTracker::ConnectionTracker(size_t max_entries, uint32_t timeout_sec)
    : max_entries_(max_entries), timeout_sec_(timeout_sec) {}

ConnectionState* ConnectionTracker::getOrCreate(const FiveTuple& tuple, uint32_t current_ts) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(tuple);
    if (it != table_.end()) {
        it->second.last_seen_sec = current_ts;
        return &it->second;
    }

    if (table_.size() >= max_entries_) {
        evictExpired(current_ts);
    }

    ConnectionState state;
    state.tuple = tuple;
    state.last_seen_sec = current_ts;
    auto [inserted_it, _] = table_.emplace(tuple, state);
    return &inserted_it->second;
}

void ConnectionTracker::update(const FiveTuple& tuple, size_t bytes, uint32_t current_ts) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(tuple);
    if (it != table_.end()) {
        it->second.packet_count++;
        it->second.byte_count += bytes;
        it->second.last_seen_sec = current_ts;
    }
}

void ConnectionTracker::setAction(const FiveTuple& tuple, PacketAction action, ApplicationType app, const std::string& sni) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(tuple);
    if (it != table_.end()) {
        it->second.action = action;
        it->second.app = app;
        it->second.sni = sni;
        it->second.is_classified = true;
    }
}

void ConnectionTracker::evictExpired(uint32_t current_ts) {
    for (auto it = table_.begin(); it != table_.end(); ) {
        if (current_ts > it->second.last_seen_sec && (current_ts - it->second.last_seen_sec) > timeout_sec_) {
            it = table_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t ConnectionTracker::activeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}

} // namespace SentinelDPI
