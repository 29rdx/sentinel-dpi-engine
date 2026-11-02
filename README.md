# 🛡️ Sentinel DPI Engine
### High-Throughput Deep Packet Inspection & Threat Detection Engine (C++17)

[![CI](https://github.com/29rdx/sentinel-dpi-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/29rdx/sentinel-dpi-engine/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-green.svg)](https://en.cppreference.com/w/cpp/17)

## 📌 Architecture & Subsystems
- **Zero-Copy Fast Path**: Lock-free cache-aligned packet ring buffer (\`FastPathRing\`).
- **5-Tuple Consistent Hashing**: Worker core affinity distribution (\`FlowLoadBalancer\`).
- **Covert Channel Defense**: Shannon entropy DNS tunneling analyzer (\`DnsTunnelingDetector\`).
- **HTTP/2 Binary Dissection**: RFC 7540 frame parsing and Rapid Reset flood defense (\`Http2Parser\`).
- **TLS Fingerprinting**: JA3 client hello signature extraction (\`TlsFingerprinter\`).
- **Advanced Threat Heuristics**: Null scan, Xmas scan, and SYN flood ratio models (\`AdvancedHeuristics\`).

## 🛠️ Build and Test
```bash
cmake -B build
cmake --build build -j4
./build/test_suite
./build/test_subsystems
```
