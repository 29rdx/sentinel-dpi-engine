#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace SentinelDPI {

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket();
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;
    parsed.packet_number = raw.packet_number;

    const uint8_t* data = raw.data.data();
    size_t len = raw.data.size();
    size_t offset = 0;

    // 1. Ethernet layer
    if (!parseEthernet(data, len, parsed, offset)) {
        return false;
    }

    // 2. IP layer
    if (parsed.ether_type == EtherType::IPv4) {
        if (!parseIPv4(data, len, parsed, offset)) {
            return false;
        }
    } else if (parsed.ether_type == EtherType::IPv6) {
        if (!parseIPv6(data, len, parsed, offset)) {
            return false;
        }
    } else {
        return true; // Non-IP packet (ARP, etc.)
    }

    // 3. Transport layer
    if (parsed.protocol == Protocol::TCP) {
        parseTCP(data, len, parsed, offset);
    } else if (parsed.protocol == Protocol::UDP) {
        parseUDP(data, len, parsed, offset);
    }

    // 4. Payload pointer
    if (offset < len) {
        parsed.payload_length = len - offset;
        parsed.payload_data = data + offset;
    }

    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ETH_HEADER_LEN = 14;
    if (len < ETH_HEADER_LEN) return false;

    parsed.dest_mac = macToString(data);
    parsed.src_mac = macToString(data + 6);
    parsed.ether_type = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(data + 12));
    offset = ETH_HEADER_LEN;

    // Handle 802.1Q VLAN tagging (0x8100 or QinQ 0x88A8)
    while ((parsed.ether_type == EtherType::VLAN_8021Q || parsed.ether_type == EtherType::QINQ) && offset + 4 <= len) {
        parsed.has_vlan = true;
        uint16_t tci = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(data + offset));
        parsed.vlan_id = tci & 0x0FFF;
        parsed.ether_type = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(data + offset + 2));
        offset += 4;
    }

    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_IP_HEADER_LEN = 20;
    if (len < offset + MIN_IP_HEADER_LEN) return false;

    const uint8_t* ip_data = data + offset;
    uint8_t version_ihl = ip_data[0];
    parsed.ip_version = (version_ihl >> 4) & 0x0F;
    uint8_t ihl = (version_ihl & 0x0F) * 4;

    if (parsed.ip_version != 4 || ihl < MIN_IP_HEADER_LEN || len < offset + ihl) {
        return false;
    }

    parsed.has_ip = true;
    parsed.ttl = ip_data[8];
    parsed.protocol = static_cast<Protocol>(ip_data[9]);

    uint32_t src_ip_raw = *reinterpret_cast<const uint32_t*>(ip_data + 12);
    uint32_t dest_ip_raw = *reinterpret_cast<const uint32_t*>(ip_data + 16);
    parsed.src_ip = ip4ToString(src_ip_raw);
    parsed.dest_ip = ip4ToString(dest_ip_raw);

    offset += ihl;
    return true;
}

bool PacketParser::parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t IPV6_HEADER_LEN = 40;
    if (len < offset + IPV6_HEADER_LEN) return false;

    const uint8_t* ip_data = data + offset;
    parsed.ip_version = 6;
    parsed.has_ip = true;
    parsed.protocol = static_cast<Protocol>(ip_data[6]); // Next Header
    parsed.ttl = ip_data[7];                             // Hop Limit

    parsed.src_ip = ip6ToString(ip_data + 8);
    parsed.dest_ip = ip6ToString(ip_data + 24);

    offset += IPV6_HEADER_LEN;
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_TCP_HEADER_LEN = 20;
    if (len < offset + MIN_TCP_HEADER_LEN) return false;

    const uint8_t* tcp_data = data + offset;
    parsed.has_transport = true;
    parsed.src_port = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(tcp_data));
    parsed.dest_port = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(tcp_data + 2));

    uint8_t data_offset = ((tcp_data[12] >> 4) & 0x0F) * 4;
    if (data_offset < MIN_TCP_HEADER_LEN || len < offset + data_offset) {
        return false;
    }

    uint8_t flags_byte = tcp_data[13];
    parsed.tcp_flags.fin = (flags_byte & 0x01) != 0;
    parsed.tcp_flags.syn = (flags_byte & 0x02) != 0;
    parsed.tcp_flags.rst = (flags_byte & 0x04) != 0;
    parsed.tcp_flags.psh = (flags_byte & 0x08) != 0;
    parsed.tcp_flags.ack = (flags_byte & 0x10) != 0;
    parsed.tcp_flags.urg = (flags_byte & 0x20) != 0;

    offset += data_offset;
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t UDP_HEADER_LEN = 8;
    if (len < offset + UDP_HEADER_LEN) return false;

    const uint8_t* udp_data = data + offset;
    parsed.has_transport = true;
    parsed.src_port = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(udp_data));
    parsed.dest_port = Platform::netToHost16(*reinterpret_cast<const uint16_t*>(udp_data + 2));

    offset += UDP_HEADER_LEN;
    return true;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::string PacketParser::ip4ToString(uint32_t ip) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&ip);
    std::ostringstream ss;
    ss << static_cast<int>(bytes[0]) << "."
       << static_cast<int>(bytes[1]) << "."
       << static_cast<int>(bytes[2]) << "."
       << static_cast<int>(bytes[3]);
    return ss.str();
}

std::string PacketParser::ip6ToString(const uint8_t* ip6_bytes) {
    std::ostringstream ss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        uint16_t word = (static_cast<uint16_t>(ip6_bytes[i]) << 8) | ip6_bytes[i + 1];
        ss << std::hex << word;
    }
    return ss.str();
}

std::string PacketParser::protocolToString(Protocol proto) {
    switch (proto) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::ICMPv6: return "ICMPv6";
        default: return "UNKNOWN";
    }
}

} // namespace SentinelDPI
