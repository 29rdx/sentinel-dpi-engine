#include "packet_parser.h"
#include "sni_extractor.h"
#include "dns_parser.h"
#include "threat_detector.h"
#include "rule_manager.h"
#include <iostream>
#include <cassert>
#include <vector>

using namespace SentinelDPI;

void testVlanParsing() {
    // Crafted Ethernet frame with 802.1Q VLAN tag (0x8100, VLAN ID 100) and IPv4
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dest mac
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
        0x81, 0x00,                         // VLAN 802.1Q tag
        0x00, 0x64,                         // Priority 0, VLAN ID 100
        0x08, 0x00,                         // Encapsulated EtherType IPv4
        0x45, 0x00, 0x00, 0x28,             // IPv4 header (IHL 5, len 40)
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,             // TTL 64, Protocol TCP (6)
        0x0a, 0x00, 0x00, 0x01,             // 10.0.0.1
        0x0a, 0x00, 0x00, 0x02,             // 10.0.0.2
        0x04, 0x00, 0x00, 0x50,             // TCP Ports 1024 -> 80
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00,             // Offset 5, Flags: SYN (0x02)
        0x00, 0x00, 0x00, 0x00
    };

    RawPacket raw;
    raw.data = frame;
    raw.header.caplen = frame.size();
    raw.header.len = frame.size();

    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    assert(ok && "Failed to parse VLAN tagged packet");
    assert(parsed.has_vlan && "VLAN tag not detected");
    assert(parsed.vlan_id == 100 && "Incorrect VLAN ID");
    assert(parsed.has_ip && "IPv4 layer not parsed after VLAN stripping");
    assert(parsed.src_ip == "10.0.0.1");
    assert(parsed.dest_ip == "10.0.0.2");
    assert(parsed.protocol == Protocol::TCP);
    assert(parsed.tcp_flags.syn && "TCP SYN flag not detected");
    std::cout << "[✓] testVlanParsing passed\n";
}

void testIPv6Parsing() {
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x86, 0xdd,                         // IPv6 EtherType
        0x60, 0x00, 0x00, 0x00,             // IPv6 version 6, traffic class 0
        0x00, 0x14, 0x06, 0x40,             // Payload len 20, Next Header TCP (6), Hop Limit 64
        // Src: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x1f, 0x90, 0x01, 0xbb,             // Ports 8080 -> 443
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00,             // ACK flag
        0x00, 0x00, 0x00, 0x00
    };

    RawPacket raw;
    raw.data = frame;
    raw.header.caplen = frame.size();

    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    assert(ok && "Failed to parse IPv6 packet");
    assert(parsed.ip_version == 6 && "Expected IPv6 version");
    assert(parsed.protocol == Protocol::TCP);
    assert(parsed.dest_port == 443);
    std::cout << "[✓] testIPv6Parsing passed\n";
}

void testSniExtraction() {
    // Minimal TLS Client Hello payload with SNI extension for "example.com"
    std::vector<uint8_t> tls_hello = {
        0x16, 0x03, 0x03, 0x00, 0x40, // Record: Handshake, TLS 1.2, Len 64
        0x01, 0x00, 0x00, 0x3c,       // Client Hello, Len 60
        0x03, 0x03,                   // Version TLS 1.2
        // 32 bytes random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00,                         // Session ID len 0
        0x00, 0x02, 0x00, 0x2f,       // Cipher suites len 2, TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,                   // Compression len 1, null
        0x00, 0x13,                   // Extensions len 19
        0x00, 0x00, 0x00, 0x0f,       // Ext Type 0 (SNI), Len 15
        0x00, 0x0d,                   // Server Name list len 13
        0x00,                         // Name type 0 (host_name)
        0x00, 0x0a,                   // Host name len 10
        'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm'
    };

    auto sni = SNIExtractor::extract(tls_hello.data(), tls_hello.size());
    assert(sni.has_value() && "Failed to extract SNI");
    assert(sni.value() == "google.com");
    std::cout << "[✓] testSniExtraction passed (extracted: " << sni.value() << ")\n";
}

void testThreatDetection() {
    ThreatDetector detector;

    ParsedPacket xmas_pkt;
    xmas_pkt.protocol = Protocol::TCP;
    xmas_pkt.has_transport = true;
    xmas_pkt.tcp_flags.fin = true;
    xmas_pkt.tcp_flags.psh = true;
    xmas_pkt.tcp_flags.urg = true;

    ThreatType t = detector.inspectPacket(xmas_pkt);
    assert(t == ThreatType::PORT_SCAN_XMAS && "Failed to detect Xmas scan probe");

    ParsedPacket rce_pkt;
    const char malicious_payload[] = "GET /vulnerable?param=eval(base64_decode(XYZ)) HTTP/1.1\r\n";
    rce_pkt.payload_length = sizeof(malicious_payload);
    rce_pkt.payload_data = reinterpret_cast<const uint8_t*>(malicious_payload);

    ThreatType t2 = detector.inspectPacket(rce_pkt);
    assert(t2 == ThreatType::MALICIOUS_SIGNATURE && "Failed to detect RCE signature");
    std::cout << "[✓] testThreatDetection passed\n";
}

void testRuleManager() {
    RuleManager rm;
    rm.addBlockedDomain("*.facebook.com");
    rm.addBlockedIP("192.168.1.50");

    ParsedPacket p1;
    p1.detected_sni = "static.facebook.com";
    std::string reason;
    PacketAction a1 = rm.evaluate(p1, reason);
    assert(a1 == PacketAction::DROP && "Wildcard domain matching failed");

    ParsedPacket p2;
    p2.src_ip = "192.168.1.50";
    PacketAction a2 = rm.evaluate(p2, reason);
    assert(a2 == PacketAction::DROP && "IP rule matching failed");
    std::cout << "[✓] testRuleManager passed\n";
}

int main() {
    std::cout << "\n================ RUNNING SENTINEL-DPI UNIT TESTS ================\n";
    testVlanParsing();
    testIPv6Parsing();
    testSniExtraction();
    testThreatDetection();
    testRuleManager();
    std::cout << "================ ALL TESTS PASSED SUCCESSFULLY! ================\n\n";
    return 0;
}
