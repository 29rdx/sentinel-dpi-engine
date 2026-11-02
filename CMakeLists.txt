cmake_minimum_required(VERSION 3.14)
project(sentinel_dpi VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -pthread")

include_directories(include)

set(SOURCES
    src/packet_parser.cpp
    src/dns_parser.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp
    src/threat_detector.cpp
    src/rule_manager.cpp
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/dns_tunneling_detector.cpp
    src/http2_frame_parser.cpp
    src/tls_fingerprint.cpp
    src/flow_stats_exporter.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/heuristic_threats.cpp
)

add_library(sentinel_core STATIC ${SOURCES})

add_executable(sentinel_dpi src/main.cpp)
target_link_libraries(sentinel_dpi PRIVATE sentinel_core)

add_executable(test_suite tests/test_suite.cpp)
target_link_libraries(test_suite PRIVATE sentinel_core)

add_executable(test_subsystems tests/test_new_subsystems.cpp)
target_link_libraries(test_subsystems PRIVATE sentinel_core)
