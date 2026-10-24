#include "pcap_writer.h"

namespace SentinelDPI {

PCAPWriter::~PCAPWriter() {
    close();
}

bool PCAPWriter::open(const std::string& filename) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        return false;
    }

    struct GlobalHeader {
        uint32_t magic_number = 0xa1b2c3d4;
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        int32_t  thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 1; // LINKTYPE_ETHERNET
    } gh;

    file_.write(reinterpret_cast<const char*>(&gh), sizeof(GlobalHeader));
    return file_.good();
}

void PCAPWriter::close() {
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}

bool PCAPWriter::writePacket(const RawPacket& packet) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (!file_.is_open()) {
        return false;
    }

    struct PacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } p_hdr;

    p_hdr.ts_sec = packet.header.ts_sec;
    p_hdr.ts_usec = packet.header.ts_usec;
    p_hdr.incl_len = packet.header.caplen;
    p_hdr.orig_len = packet.header.len;

    file_.write(reinterpret_cast<const char*>(&p_hdr), sizeof(PacketHeader));
    if (!packet.data.empty()) {
        file_.write(reinterpret_cast<const char*>(packet.data.data()), packet.data.size());
    }
    return file_.good();
}

} // namespace SentinelDPI
