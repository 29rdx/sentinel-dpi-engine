#include "sni_extractor.h"

namespace SentinelDPI {

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;
    // Record content type 0x16 = Handshake
    if (payload[0] != 0x16) return false;
    // TLS Version: SSL 3.0 (0x0300) to TLS 1.3 (0x0304)
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    // Handshake Type 0x01 = Client Hello
    if (payload[5] != 0x01) return false;
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }

    size_t offset = 5; // Skip TLS Record Header

    // Check Handshake Length
    if (offset + 4 > length) return std::nullopt;
    offset += 4; // Skip Handshake Header

    // Skip Client Version (2 bytes) + Random (32 bytes)
    if (offset + 34 > length) return std::nullopt;
    offset += 34;

    // Session ID length check
    if (offset + 1 > length) return std::nullopt;
    uint8_t session_id_len = payload[offset];
    offset += 1;
    if (offset + session_id_len > length) return std::nullopt;
    offset += session_id_len;

    // Cipher Suites length check
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_len = readUint16BE(payload + offset);
    offset += 2;
    if (offset + cipher_suites_len > length) return std::nullopt;
    offset += cipher_suites_len;

    // Compression Methods length check
    if (offset + 1 > length) return std::nullopt;
    uint8_t comp_len = payload[offset];
    offset += 1;
    if (offset + comp_len > length) return std::nullopt;
    offset += comp_len;

    // Extensions length check
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_len = readUint16BE(payload + offset);
    offset += 2;

    size_t ext_end = offset + extensions_len;
    if (ext_end > length) ext_end = length;

    // Iterate through TLS Extensions safely
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_len = readUint16BE(payload + offset + 2);
        offset += 4;

        if (offset + ext_len > ext_end) break;

        if (ext_type == 0x0000) { // Server Name Indication (SNI)
            if (ext_len < 5) return std::nullopt;
            size_t sni_ptr = offset + 2; // Skip server_name_list_length

            while (sni_ptr + 3 <= offset + ext_len) {
                uint8_t name_type = payload[sni_ptr];
                uint16_t name_len = readUint16BE(payload + sni_ptr + 1);
                sni_ptr += 3;

                if (name_type == 0 && sni_ptr + name_len <= offset + ext_len) {
                    return std::string(reinterpret_cast<const char*>(payload + sni_ptr), name_len);
                }
                sni_ptr += name_len;
            }
        }
        offset += ext_len;
    }

    return std::nullopt;
}

} // namespace SentinelDPI
