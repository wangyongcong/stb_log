#define STB_LOG_IMPLEMENTATION
#include "stb_log.h"
#include "benchmark.h"

long long bm_stb_log()
{
	start_file_logger("logs/bm_stb_log.log");

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

class CSwapHandler : public CLogHandler
{
public:
	CSwapHandler() {
		m_sum = 0;
	}

	virtual void process_event(const LogEvent *log) override
	{
		const char *message = LOG_EVENT_BUFFER(log);
		int v = *(int*)message;
		m_sum += v;
	};
	
	virtual void on_close() override 
	{
	};

private:
	int64_t m_sum;
};

long long bm_stb_latence()
{
	CSwapHandler *handler = new CSwapHandler();
	start_handler_thread(handler, 1);
	CLogger *logger = get_log_context()->logger;
	assert(logger);

	auto t1 = Clock::now();
	for (int i = 0; i < ITERATION; ++i)
	{
		logger->write(STB_LOG_LEVEL::LOG_INFO, &i, sizeof(int));
	}
	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	auto result = dt.count();
	
	printf("stb_log used time: %lld microseconds\n", result);

	close_logger();
	return result;
}

