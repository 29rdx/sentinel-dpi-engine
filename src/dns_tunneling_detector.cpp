#include "dns_tunneling_detector.h"
#include <cmath>
#include <unordered_map>

namespace Sentinel {

double DnsTunnelingDetector::calculate_entropy(const std::string& str) {
    if (str.empty()) return 0.0;
    std::unordered_map<char, int> freq;
    for (char c : str) freq[c]++;
    double entropy = 0.0;
    double len = static_cast<double>(str.length());
    for (const auto& pair : freq) {
        double p = pair.second / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool DnsTunnelingDetector::is_tunneling_suspect(const std::string& query, double entropy_threshold) {
    // Check total length and subdomain length
    if (query.length() > 50) return true;
    double ent = calculate_entropy(query);
    return ent >= entropy_threshold;
}

} // namespace Sentinel
