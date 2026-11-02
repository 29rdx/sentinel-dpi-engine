#include "http2_frame_parser.h"

namespace Sentinel {

bool Http2Parser::parse_frame_header(const uint8_t* data, size_t len, Http2FrameHeader& out_header) {
    if (len < 9) return false;
    out_header.length = (static_cast<uint32_t>(data[0]) << 16) |
                        (static_cast<uint32_t>(data[1]) << 8)  |
                        (static_cast<uint32_t>(data[2]));
    out_header.type = static_cast<Http2FrameType>(data[3]);
    out_header.flags = data[4];
    out_header.stream_id = ((static_cast<uint32_t>(data[5]) & 0x7F) << 24) |
                           (static_cast<uint32_t>(data[6]) << 16) |
                           (static_cast<uint32_t>(data[7]) << 8)  |
                           (static_cast<uint32_t>(data[8]));
    return true;
}

} // namespace Sentinel
