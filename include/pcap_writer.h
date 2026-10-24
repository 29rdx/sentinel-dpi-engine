#pragma once

#include "types.h"
#include <string>
#include <fstream>
#include <mutex>

namespace SentinelDPI {

class PCAPWriter {
public:
    PCAPWriter() = default;
    ~PCAPWriter();

    bool open(const std::string& filename);
    void close();
    bool writePacket(const RawPacket& packet);
    bool isOpen() const { return file_.is_open(); }

private:
    std::ofstream file_;
    std::mutex write_mutex_;
};

} // namespace SentinelDPI
