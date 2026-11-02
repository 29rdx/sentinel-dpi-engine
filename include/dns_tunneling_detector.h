#pragma once
#include <string>
#include <vector>

namespace Sentinel {

class DnsTunnelingDetector {
public:
    static double calculate_entropy(const std::string& str);
    static bool is_tunneling_suspect(const std::string& query, double entropy_threshold = 3.5);
};

} // namespace Sentinel
