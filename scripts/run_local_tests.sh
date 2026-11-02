#!/bin/bash
set -e
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
./build/test_suite
./build/test_subsystems
echo "[PASS] All Sentinel DPI unit tests succeeded."
