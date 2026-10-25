#pragma once

#include "types.h"

namespace SentinelDPI {

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

    static std::string macToString(const uint8_t* mac);
    static std::string ip4ToString(uint32_t ip);
    static std::string ip6ToString(const uint8_t* ip6_bytes);
    static std::string protocolToString(Protocol proto);

private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
};

} // namespace SentinelDPI
