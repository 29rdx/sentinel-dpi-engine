#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace SentinelDPI {

void RuleManager::addBlockedIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.insert(ip);
}

void RuleManager::addBlockedDomain(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_domain_patterns_.push_back(pattern);
}

void RuleManager::addBlockedApp(ApplicationType app) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_apps_.insert(app);
}

bool RuleManager::loadRulesFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string type, value;
        if (iss >> type >> value) {
            if (type == "ip") {
                addBlockedIP(value);
            } else if (type == "domain") {
                addBlockedDomain(value);
            } else if (type == "app") {
                if (value == "YouTube") addBlockedApp(ApplicationType::YOUTUBE);
                else if (value == "Netflix") addBlockedApp(ApplicationType::NETFLIX);
                else if (value == "Facebook") addBlockedApp(ApplicationType::FACEBOOK);
                else if (value == "BitTorrent") addBlockedApp(ApplicationType::BITTORRENT);
            }
        }
    }
    return true;
}

PacketAction RuleManager::evaluate(const ParsedPacket& packet, std::string& reason) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // 1. Drop if threat detected
    if (packet.detected_threat != ThreatType::NONE) {
        reason = "THREAT_BLOCKED: " + packet.threat_description;
        return PacketAction::DROP;
    }

    // 2. IP Blocking check
    if (blocked_ips_.find(packet.src_ip) != blocked_ips_.end() ||
        blocked_ips_.find(packet.dest_ip) != blocked_ips_.end()) {
        reason = "BLOCKED_IP: " + packet.src_ip + " -> " + packet.dest_ip;
        return PacketAction::DROP;
    }

    // 3. Domain / SNI Blocking check
    if (!packet.detected_sni.empty()) {
        for (const auto& pattern : blocked_domain_patterns_) {
            if (matchesDomain(pattern, packet.detected_sni)) {
                reason = "BLOCKED_DOMAIN_SNI: " + packet.detected_sni + " (Rule: " + pattern + ")";
                return PacketAction::DROP;
            }
        }
    }

    // 4. DNS Query Blocking check
    if (!packet.dns_query.empty()) {
        for (const auto& pattern : blocked_domain_patterns_) {
            if (matchesDomain(pattern, packet.dns_query)) {
                reason = "BLOCKED_DNS_QUERY: " + packet.dns_query + " (Rule: " + pattern + ")";
                return PacketAction::DROP;
            }
        }
    }

    // 5. Application Blocking check
    if (blocked_apps_.find(packet.app_type) != blocked_apps_.end()) {
        reason = "BLOCKED_APPLICATION";
        return PacketAction::DROP;
    }

    reason = "ALLOWED";
    return PacketAction::FORWARD;
}

bool RuleManager::matchesDomain(const std::string& pattern, const std::string& domain) const {
    if (pattern == domain) return true;
    if (pattern.rfind("*.", 0) == 0) { // Wildcard prefix *.domain.com
        std::string suffix = pattern.substr(2);
        if (domain.length() >= suffix.length()) {
            return domain.compare(domain.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
    }
    return false;
}

size_t RuleManager::ipRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_ips_.size();
}

size_t RuleManager::domainRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_domain_patterns_.size();
}

size_t RuleManager::appRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_apps_.size();
}

} // namespace SentinelDPI
