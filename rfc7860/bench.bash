#!/usr/bin/env bash
set -euo pipefail

# Build
make clean
make

# Run
> results_bench.txt

# No delay
./app > /dev/null 2>> results_bench.txt
./app -k > /dev/null 2>> results_bench.txt
./app -i > /dev/null 2>> results_bench.txt
./app -o > /dev/null 2>> results_bench.txt
./app -io > /dev/null 2>> results_bench.txt
./app -ki > /dev/null 2>> results_bench.txt
./app -ko > /dev/null 2>> results_bench.txt
./app -kio > /dev/null 2>> results_bench.txt

# LAN delay
./app -l > /dev/null 2>> results_bench.txt
./app -lk > /dev/null 2>> results_bench.txt
./app -li > /dev/null 2>> results_bench.txt
./app -lo > /dev/null 2>> results_bench.txt
./app -lio > /dev/null 2>> results_bench.txt
./app -lki > /dev/null 2>> results_bench.txt
./app -lko > /dev/null 2>> results_bench.txt
./app -lkio > /dev/null 2>> results_bench.txt

# WAN delay
./app -w > /dev/null 2>> results_bench.txt
./app -wk > /dev/null 2>> results_bench.txt
./app -wi > /dev/null 2>> results_bench.txt
./app -wo > /dev/null 2>> results_bench.txt
./app -wio > /dev/null 2>> results_bench.txt
./app -wki > /dev/null 2>> results_bench.txt
./app -wko > /dev/null 2>> results_bench.txt
./app -wkio > /dev/null 2>> results_bench.txt