#include "pcap_reader.h"
#include <iostream>

namespace SentinelDPI {

PCAPReader::~PCAPReader() {
    close();
}

bool PCAPReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        return false;
    }

    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(GlobalHeader));
    if (file_.gcount() != sizeof(GlobalHeader)) {
        close();
        return false;
    }

    // Check PCAP magic number (standard 0xa1b2c3d4 or swapped 0xd4c3b2a1)
    if (global_header_.magic_number != 0xa1b2c3d4 && global_header_.magic_number != 0xd4c3b2a1) {
        close();
        return false;
    }

    packet_counter_ = 0;
    return true;
}

void PCAPReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

std::optional<RawPacket> PCAPReader::readNextPacket() {
    if (!file_.is_open() || file_.eof()) {
        return std::nullopt;
    }

    struct PacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } p_hdr{};

    file_.read(reinterpret_cast<char*>(&p_hdr), sizeof(PacketHeader));
    if (file_.gcount() != sizeof(PacketHeader)) {
        return std::nullopt;
    }

    RawPacket packet;
    packet.header.ts_sec = p_hdr.ts_sec;
    packet.header.ts_usec = p_hdr.ts_usec;
    packet.header.caplen = p_hdr.incl_len;
    packet.header.len = p_hdr.orig_len;
    packet.packet_number = ++packet_counter_;

    packet.data.resize(p_hdr.incl_len);
    file_.read(reinterpret_cast<char*>(packet.data.data()), p_hdr.incl_len);
    if (static_cast<uint32_t>(file_.gcount()) != p_hdr.incl_len) {
        return std::nullopt;
    }

    return packet;
}

} // namespace SentinelDPI
