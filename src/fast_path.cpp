#include "fast_path.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "dns_parser.h"
#include <iostream>

namespace SentinelDPI {

FastPath::FastPath(size_t worker_id,
                   ThreadSafeQueue<RawPacket>* input_queue,
                   ThreadSafeQueue<std::pair<RawPacket, PacketAction>>* output_queue,
                   RuleManager* rule_manager,
                   ThreatDetector* threat_detector)
    : worker_id_(worker_id),
      input_queue_(input_queue),
      output_queue_(output_queue),
      rule_manager_(rule_manager),
      threat_detector_(threat_detector),
      conn_tracker_(50000, 300) {}

FastPath::~FastPath() {
    stop();
    join();
}

void FastPath::start() {
    running_ = true;
    worker_thread_ = std::thread(&FastPath::workerLoop, this);
}

void FastPath::stop() {
    running_ = false;
}

void FastPath::join() {
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void FastPath::workerLoop() {
    while (running_) {
        auto opt_packet = input_queue_->pop();
        if (!opt_packet.has_value()) {
            break;
        }

        RawPacket raw = std::move(opt_packet.value());
        processed_count_++;

        ParsedPacket parsed;
        if (!PacketParser::parse(raw, parsed)) {
            output_queue_->push({std::move(raw), PacketAction::FORWARD});
            continue;
        }

        // Fast-path flow lookup
        FiveTuple tuple = parsed.getFiveTuple();
        ConnectionState* conn = conn_tracker_.getOrCreate(tuple, parsed.timestamp_sec);

        PacketAction action = PacketAction::FORWARD;
        std::string verdict_reason;

        if (conn && conn->is_classified) {
            // Flow already classified!
            action = conn->action;
            parsed.app_type = conn->app;
            parsed.detected_sni = conn->sni;
            conn_tracker_.update(tuple, raw.data.size(), parsed.timestamp_sec);
        } else {
            // Deep Packet Inspection (DPI)
            // 1. Inspect TLS SNI
            if (parsed.dest_port == 443 && parsed.payload_length > 0) {
                auto opt_sni = SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
                if (opt_sni.has_value()) {
                    parsed.detected_sni = opt_sni.value();
                    parsed.app_type = classifyBySNI(parsed.detected_sni);
                } else {
                    parsed.app_type = ApplicationType::GENERIC_HTTPS;
                }
            }
            // 2. Inspect DNS Query
            else if (parsed.dest_port == 53 && parsed.protocol == Protocol::UDP && parsed.payload_length > 0) {
                auto opt_dns = DNSParser::extractQueryDomain(parsed.payload_data, parsed.payload_length);
                if (opt_dns.has_value()) {
                    parsed.dns_query = opt_dns.value();
                    parsed.app_type = ApplicationType::DNS;
                    if (DNSParser::isSuspiciousTunneling(parsed.dns_query)) {
                        parsed.detected_threat = ThreatType::SUSPICIOUS_DNS_TUNNEL;
                        parsed.threat_description = "High entropy DNS tunneling exfiltration: " + parsed.dns_query;
                    }
                }
            }

            // 3. Threat Engine Inspection
            if (threat_detector_) {
                threat_detector_->inspectPacket(parsed);
            }

            // 4. Rule Manager Evaluation
            if (rule_manager_) {
                action = rule_manager_->evaluate(parsed, verdict_reason);
            }

            // Cache decision into connection tracker
            conn_tracker_.setAction(tuple, action, parsed.app_type, parsed.detected_sni);
            conn_tracker_.update(tuple, raw.data.size(), parsed.timestamp_sec);
        }

        if (action == PacketAction::DROP) {
            dropped_count_++;
        }

        output_queue_->push({std::move(raw), action});
    }
}

ApplicationType FastPath::classifyBySNI(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos || sni.find("googlevideo") != std::string::npos) return ApplicationType::YOUTUBE;
    if (sni.find("netflix") != std::string::npos || sni.find("nflxvideo") != std::string::npos) return ApplicationType::NETFLIX;
    if (sni.find("facebook") != std::string::npos || sni.find("fbcdn") != std::string::npos) return ApplicationType::FACEBOOK;
    if (sni.find("instagram") != std::string::npos) return ApplicationType::INSTAGRAM;
    if (sni.find("twitter") != std::string::npos || sni.find("x.com") != std::string::npos) return ApplicationType::TWITTER_X;
    if (sni.find("spotify") != std::string::npos) return ApplicationType::SPOTIFY;
    if (sni.find("telegram") != std::string::npos) return ApplicationType::TELEGRAM;
    if (sni.find("discord") != std::string::npos) return ApplicationType::DISCORD;
    if (sni.find("github") != std::string::npos) return ApplicationType::GITHUB;
    return ApplicationType::GENERIC_HTTPS;
}

} // namespace SentinelDPI
