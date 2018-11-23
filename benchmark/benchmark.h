#pragma once
#include <chrono>

typedef std::chrono::high_resolution_clock Clock;
typedef std::chrono::microseconds TimeUnit;
typedef Clock::time_point TimePoint;

constexpr int ITERATION = 20000;
constexpr const char *CSTR = "benchmark";
constexpr double CFLOAT = -3.1415926;

class CTimer
{
public:
    static long long s_total;
    static void init() {
        s_total = 0;
    }

    CTimer() {
        m_t1 = Clock::now();
    }

    ~CTimer() {
        auto t2 = Clock::now();
        auto dt = std::chrono::duration_cast<TimeUnit>(t2 - m_t1);
        s_total += dt.count();
    }

private:
    TimePoint m_t1;
};