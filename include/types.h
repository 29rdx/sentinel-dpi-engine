#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace SentinelDPI {

namespace EtherType {
    constexpr uint16_t IPv4       = 0x0800;
    constexpr uint16_t ARP        = 0x0806;
    constexpr uint16_t VLAN_8021Q = 0x8100;
    constexpr uint16_t QINQ       = 0x88A8;
    constexpr uint16_t IPv6       = 0x86DD;
}

enum class Protocol : uint8_t {
    ICMP   = 1,
    TCP    = 6,
    UDP    = 17,
    ICMPv6 = 58,
    UNKNOWN = 255
};

struct TCPFlags {
    bool fin = false;
    bool syn = false;
    bool rst = false;
    bool psh = false;
    bool ack = false;
    bool urg = false;

    bool isSynOnly() const { return syn && !ack && !fin && !rst; }
    bool isNullScan() const { return !fin && !syn && !rst && !psh && !ack && !urg; }
    bool isXmasScan() const { return fin && psh && urg; }
};

enum class ThreatType : uint8_t {
    NONE = 0,
    SYN_FLOOD,
    PORT_SCAN_SYN,
    PORT_SCAN_XMAS,
    PORT_SCAN_NULL,
    SUSPICIOUS_DNS_TUNNEL,
    MALICIOUS_SIGNATURE
};

enum class ApplicationType : uint8_t {
    UNKNOWN = 0,
    GENERIC_HTTP,
    GENERIC_HTTPS,
    DNS,
    YOUTUBE,
    NETFLIX,
    FACEBOOK,
    INSTAGRAM,
    TWITTER_X,
    SPOTIFY,
    TELEGRAM,
    DISCORD,
    BITTORRENT,
    GITHUB
};

enum class PacketAction : uint8_t {
    FORWARD = 0,
    DROP,
    INSPECT
};

struct FiveTuple {
    std::string src_ip;
    std::string dest_ip;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    Protocol protocol = Protocol::UNKNOWN;

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dest_ip == other.dest_ip &&
               src_port == other.src_port &&
               dest_port == other.dest_port &&
               protocol == other.protocol;
    }

    size_t hash() const {
        std::hash<std::string> str_hash;
        return str_hash(src_ip) ^ (str_hash(dest_ip) << 1) ^
               (static_cast<size_t>(src_port) << 16) ^
               (static_cast<size_t>(dest_port) << 24) ^
               static_cast<size_t>(protocol);
    }
};

struct RawPacket {
    struct Header {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    } header;

    std::vector<uint8_t> data;
    size_t packet_number = 0;
};

struct ParsedPacket {
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;
    size_t packet_number = 0;

    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type = 0;
    bool has_vlan = false;
    uint16_t vlan_id = 0;

    bool has_ip = false;
    uint8_t ip_version = 0;
    std::string src_ip;
    std::string dest_ip;
    Protocol protocol = Protocol::UNKNOWN;
    uint8_t ttl = 0;

    bool has_transport = false;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    TCPFlags tcp_flags;

    size_t payload_length = 0;
    const uint8_t* payload_data = nullptr;

    ApplicationType app_type = ApplicationType::UNKNOWN;
    std::string detected_sni;
    std::string dns_query;
    ThreatType detected_threat = ThreatType::NONE;
    std::string threat_description;

    FiveTuple getFiveTuple() const {
        return {src_ip, dest_ip, src_port, dest_port, protocol};
    }
};

} // namespace SentinelDPI

namespace std {
    template<>
    struct hash<SentinelDPI::FiveTuple> {
        size_t operator()(const SentinelDPI::FiveTuple& ft) const {
            return ft.hash();
        }
    };
}
