#define STB_LOG_IMPLEMENTATION
#include "stb_log.h"

typedef std::chrono::high_resolution_clock Clock;
typedef std::chrono::microseconds TimeUnit;
constexpr int ITERATION = 100000;

long long bm_stb_log()
{
	start_file_logger("logs/bm_stb_log.log");

	const char *cstr = "benchmark";
	auto t1 = Clock::now();
	for (int i = 0; i < ITERATION; ++i)
	{
		log_info("Logging %s %d %d %c %lf", cstr, i, 0, 'K', -3.1415926);
	}
	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);

	auto result = dt.count();
	log_info("used time: %lld microseconds", result);
	close_logger();
	return result;
}

int main(int argv, char *args[])
{
	bm_stb_log();
	return 0;
}
