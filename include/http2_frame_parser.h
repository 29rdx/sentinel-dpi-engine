#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace Sentinel {

enum class Http2FrameType : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9
};

struct Http2FrameHeader {
    uint32_t length;
    Http2FrameType type;
    uint8_t flags;
    uint32_t stream_id;
};

class Http2Parser {
public:
    static bool parse_frame_header(const uint8_t* data, size_t len, Http2FrameHeader& out_header);
};

} // namespace Sentinel
