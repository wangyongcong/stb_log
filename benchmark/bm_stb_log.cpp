#define STB_LOG_IMPLEMENTATION
#include "stb_log.h"
#include "benchmark.h"

long long bm_stb_log()
{
	start_file_logger("log/bm_stb_log.log");

	auto t1 = Clock::now();
	for (int i = 0; i < ITERATION; ++i)
	{
		log_info("Logging %d %s %lf", i, CSTR, CFLOAT);
	}
	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	auto result = dt.count();
	log_info("stb_log used time: %lld microseconds", result);

	close_logger();
	return result;
}



