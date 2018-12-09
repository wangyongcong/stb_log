#include <cstdio>
#include "benchmark.h"

extern long long bm_stb_log();
extern long long bm_nanolog();
extern long long bm_alloc();

long long CTimer::s_total = 0;

int main(int argv, char *args[])
{
	CTimer::init();

	long long t0;
	auto t1 = Clock::now();

	t0 = bm_stb_log();
//	t0 = bm_nanolog();

	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	auto total = dt.count();

	printf("producer: %lld\n", t0);
//	printf("I/O: %lld\n", CTimer::s_total);
	printf("total: %lld\n", total);
//	getchar();
	return 0;
}
