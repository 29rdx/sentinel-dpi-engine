#pragma once

#include "types.h"
#include <string>
#include <fstream>
#include <optional>

namespace SentinelDPI {

class PCAPReader {
public:
    PCAPReader() = default;
    ~PCAPReader();

    bool open(const std::string& filename);
    void close();
    std::optional<RawPacket> readNextPacket();
    bool isOpen() const { return file_.is_open(); }

private:
    struct GlobalHeader {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };

    std::ifstream file_;
    GlobalHeader global_header_{};
    size_t packet_counter_ = 0;
};

} // namespace SentinelDPI
