#include "nanolog/NanoLog.hpp"
#include "benchmark.h"

long long bm_nanolog()
{
	nanolog::initialize(nanolog::GuaranteedLogger(), "logs/", "bm_nanolog", 256);

	auto t1 = Clock::now();
	for (int i = 0; i < ITERATION; ++i)
	{
		LOG_INFO << "Logging " << i << " " << CSTR << " " << CFLOAT;
	}
	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	auto result = dt.count();

	LOG_INFO << "Nanolog used time: " << result << " microseconds";
	return 0;
}