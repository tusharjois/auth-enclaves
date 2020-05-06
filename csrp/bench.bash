#!/usr/bin/env bash
set -euo pipefail

# Build
make clean
make

# Run
> results_bench.txt

# No delay
./app > /dev/null 2>> results_bench.txt
./app -u > /dev/null 2>> results_bench.txt
./app -v > /dev/null 2>> results_bench.txt
./app -uv > /dev/null 2>> results_bench.txt

# LAN delay
./app -l > /dev/null 2>> results_bench.txt
./app -lu > /dev/null 2>> results_bench.txt
./app -lv > /dev/null 2>> results_bench.txt
./app -luv > /dev/null 2>> results_bench.txt

# WAN delay
./app -w > /dev/null 2>> results_bench.txt
./app -wu > /dev/null 2>> results_bench.txt
./app -wv > /dev/null 2>> results_bench.txt
./app -wuv > /dev/null 2>> results_bench.txt
