#include "tls_fingerprint.h"
#include <sstream>

namespace Sentinel {

std::string TlsFingerprinter::calculate_ja3_raw(const TlsClientHelloInfo& info) {
    std::stringstream ss;
    ss << info.tls_version << ",";
    for (size_t i = 0; i < info.cipher_suites.size(); ++i) {
        ss << info.cipher_suites[i] << (i + 1 < info.cipher_suites.size() ? "-" : "");
    }
    ss << ",";
    for (size_t i = 0; i < info.extensions.size(); ++i) {
        ss << info.extensions[i] << (i + 1 < info.extensions.size() ? "-" : "");
    }
    return ss.str();
}

} // namespace Sentinel
