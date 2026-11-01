cmake_minimum_required(VERSION 3.16)
project(SentinelDPI VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optimization and warning flags
if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O3 -pthread)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(CORE_SOURCES
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/dns_parser.cpp
    src/threat_detector.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
)

# Core static library
add_library(sentinel_core STATIC ${CORE_SOURCES})

# CLI Executable
add_executable(sentinel_dpi src/main.cpp)
target_link_libraries(sentinel_dpi PRIVATE sentinel_core)

# Unit Test Executable
add_executable(test_suite tests/test_suite.cpp)
target_link_libraries(test_suite PRIVATE sentinel_core)

enable_testing()
add_test(NAME SentinelTestSuite COMMAND test_suite)
