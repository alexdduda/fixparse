CXX      ?= clang++
CXXFLAGS ?= -std=c++20 -O3 -Wall -Wextra -Wpedantic -Werror
INC      := -Iinclude
SAN      := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
HDRS     := $(wildcard include/fixparse/*.hpp) tools/build.hpp

.PHONY: all test test-san test-x86 bench fuzz clean

all: test bench

build/test: tests/test_main.cpp $(HDRS) | build
	$(CXX) $(CXXFLAGS) $(INC) $< -o $@

build/test-san: tests/test_main.cpp $(HDRS) | build
	$(CXX) -std=c++20 $(SAN) $(INC) $< -o $@

build/bench: bench/bench_main.cpp bench/naive.hpp $(HDRS) | build
	$(CXX) $(CXXFLAGS) $(INC) $< -o $@

# Standalone mutation fuzzer (works with Apple clang, which ships no libFuzzer).
build/fuzz: fuzz/fuzz_target.cpp fuzz/driver.cpp $(HDRS) | build
	$(CXX) -std=c++20 $(SAN) $(INC) fuzz/fuzz_target.cpp fuzz/driver.cpp -o $@

# libFuzzer build, for Linux clang (used in CI).
build/fuzz-libfuzzer: fuzz/fuzz_target.cpp $(HDRS) | build
	$(CXX) -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined $(INC) $< -o $@

test: build/test build/test-san
	./build/test
	./build/test-san

# On Apple Silicon, run the x86-64 build under Rosetta to exercise the SSE2 path.
test-x86: | build
	$(CXX) $(CXXFLAGS) -arch x86_64 $(INC) tests/test_main.cpp -o build/test-x86
	./build/test-x86

bench: build/bench
	./build/bench

fuzz: build/fuzz
	./build/fuzz 2000000

build:
	mkdir -p build

clean:
	rm -rf build
