#pragma once
#include <chrono>

typedef std::chrono::high_resolution_clock Clock;
typedef std::chrono::microseconds TimeUnit;

constexpr int ITERATION = 20000;
constexpr const char *CSTR = "benchmark";
constexpr double CFLOAT = -3.1415926;
