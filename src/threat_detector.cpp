#include "threat_detector.h"
#include <cstring>
#include <string_view>

namespace SentinelDPI {

ThreatType ThreatDetector::inspectPacket(ParsedPacket& packet) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 1. TCP Port Scan and Flood Checks
    if (packet.protocol == Protocol::TCP && packet.has_transport) {
        // Xmas Scan: FIN + PSH + URG
        if (packet.tcp_flags.isXmasScan()) {
            report_.xmas_scans++;
            packet.detected_threat = ThreatType::PORT_SCAN_XMAS;
            packet.threat_description = "TCP Xmas Tree Scan (FIN+PSH+URG evasion probe)";
            return ThreatType::PORT_SCAN_XMAS;
        }

        // NULL Scan: Zero flags set
        if (packet.tcp_flags.isNullScan()) {
            report_.null_scans++;
            packet.detected_threat = ThreatType::PORT_SCAN_NULL;
            packet.threat_description = "TCP NULL Scan (stealth port enumeration probe)";
            return ThreatType::PORT_SCAN_NULL;
        }

        // SYN Flood detection (velocity threshold > 100 SYN packets / 5 sec from single IP)
        if (packet.tcp_flags.isSynOnly()) {
            auto& track = syn_velocity_map_[packet.src_ip];
            if (track.first_ts == 0 || packet.timestamp_sec - track.first_ts > 5) {
                track.first_ts = packet.timestamp_sec;
                track.count = 1;
            } else {
                track.count++;
                if (track.count > 100) {
                    report_.syn_floods++;
                    packet.detected_threat = ThreatType::SYN_FLOOD;
                    packet.threat_description = "SYN Flood DoS attack vector detected";
                    return ThreatType::SYN_FLOOD;
                }
            }
        }
    }

    // 2. Malicious Payload Signatures
    if (packet.payload_length > 0 && packet.payload_data != nullptr) {
        std::string match_desc;
        if (checkPayloadSignatures(packet.payload_data, packet.payload_length, match_desc)) {
            report_.malicious_signatures++;
            packet.detected_threat = ThreatType::MALICIOUS_SIGNATURE;
            packet.threat_description = match_desc;
            return ThreatType::MALICIOUS_SIGNATURE;
        }
    }

    return ThreatType::NONE;
}

bool ThreatDetector::checkPayloadSignatures(const uint8_t* payload, size_t length, std::string& match_desc) {
    std::string_view p_view(reinterpret_cast<const char*>(payload), length);

    // Shellcode & exploit signatures
    if (p_view.find("/bin/sh") != std::string_view::npos || p_view.find("/bin/bash") != std::string_view::npos) {
        match_desc = "Malicious Payload: Shell spawn executable string (/bin/sh)";
        return true;
    }
    if (p_view.find("cmd.exe") != std::string_view::npos || p_view.find("powershell.exe") != std::string_view::npos) {
        match_desc = "Malicious Payload: Windows interactive shell string";
        return true;
    }
    if (p_view.find("eval(base64_decode") != std::string_view::npos || p_view.find("Runtime.getRuntime().exec") != std::string_view::npos) {
        match_desc = "Malicious Payload: Remote Code Execution (RCE) injection payload";
        return true;
    }
    return false;
}

ThreatDetector::ThreatReport ThreatDetector::getReport() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return report_;
}

} // namespace SentinelDPI
