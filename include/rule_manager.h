#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

namespace SentinelDPI {

class RuleManager {
public:
    RuleManager() = default;

    void addBlockedIP(const std::string& ip);
    void addBlockedDomain(const std::string& pattern);
    void addBlockedApp(ApplicationType app);
    bool loadRulesFromFile(const std::string& filepath);

    PacketAction evaluate(const ParsedPacket& packet, std::string& reason) const;

    size_t ipRuleCount() const;
    size_t domainRuleCount() const;
    size_t appRuleCount() const;

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> blocked_ips_;
    std::vector<std::string> blocked_domain_patterns_;
    std::unordered_set<ApplicationType> blocked_apps_;

    bool matchesDomain(const std::string& pattern, const std::string& domain) const;
};

} // namespace SentinelDPI
