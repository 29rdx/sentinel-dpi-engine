#include <iostream>
#include <cassert>
#include "dns_tunneling_detector.h"
#include "http2_frame_parser.h"
#include "tls_fingerprint.h"
#include "flow_stats_exporter.h"
#include "fast_path_ring.h"
#include "flow_load_balancer.h"
#include "heuristic_threats.h"

void test_dns_tunneling() {
    assert(Sentinel::DnsTunnelingDetector::calculate_entropy("aaaaa") < 1.0);
    assert(Sentinel::DnsTunnelingDetector::is_tunneling_suspect("aW5maWx0cmF0aW9uLnNlY3JldC5kYXRhLnZpYXR1bm5lbC5jb20") == true);
    std::cout << "[+] DNS Tunneling tests passed." << std::endl;
}

void test_http2_parser() {
    uint8_t frame[9] = {0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01};
    Sentinel::Http2FrameHeader h;
    assert(Sentinel::Http2Parser::parse_frame_header(frame, 9, h) == true);
    assert(h.length == 4);
    assert(h.type == Sentinel::Http2FrameType::RST_STREAM);
    assert(h.stream_id == 1);
    std::cout << "[+] HTTP/2 Parser tests passed." << std::endl;
}

void test_tls_ja3() {
    Sentinel::TlsClientHelloInfo info;
    info.tls_version = 0x0303;
    info.cipher_suites = {0x1301, 0x1302};
    info.extensions = {0x0000, 0x002b};
    std::string ja3 = Sentinel::TlsFingerprinter::calculate_ja3_raw(info);
    assert(ja3 == "771,4865-4866,0-43");
    std::cout << "[+] TLS JA3 fingerprint tests passed." << std::endl;
}

void test_fast_path() {
    Sentinel::FastPathRing ring;
    uint8_t data[4] = {1, 2, 3, 4};
    assert(ring.enqueue(data, 4) == true);
    uint8_t out[16];
    size_t out_len = 0;
    assert(ring.dequeue(out, out_len) == true);
    assert(out_len == 4);
    assert(out[0] == 1);
    std::cout << "[+] Fast Path Ring tests passed." << std::endl;
}

void test_load_balancer() {
    uint32_t h = Sentinel::FlowLoadBalancer::hash_5tuple(0x0a000001, 0x0a000002, 80, 443, 6);
    uint32_t core = Sentinel::FlowLoadBalancer::select_core(h, 8);
    assert(core < 8);
    std::cout << "[+] Load Balancer tests passed." << std::endl;
}

int main() {
    test_dns_tunneling();
    test_http2_parser();
    test_tls_ja3();
    test_fast_path();
    test_load_balancer();
    std::cout << "[SUCCESS] All new Sentinel DPI subsystems verified!" << std::endl;
    return 0;
}
