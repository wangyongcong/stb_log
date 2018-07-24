#include <stdio.h>
#include <time.h>
#include <random>
#define STB_LOG_IMPLEMENTATION
#include "stb_log.h"

using namespace wyc;

class CLogWriter: public CLogHandler
{
public:
	CLogWriter(int max_size, std::atomic<unsigned> *counter)
		: m_counter(counter)
	{
		m_logs.reserve(max_size);
	}

	virtual void process_event(const LogEvent *log) override
	{
		m_logs.push_back(*(int*)(log->fixed_buffer));
		m_counter->fetch_sub(1, std::memory_order::memory_order_relaxed);
	}

	inline std::vector<unsigned>& get_logs() {
		return m_logs;
	}

private:
	std::vector<unsigned> m_logs;
	std::atomic<unsigned> *m_counter;
};

void thread_test()
{
	printf("stb_log thread test\n");
	printf("core: %d\n", std::thread::hardware_concurrency());

	constexpr int channel_count = 2;
	const StbLogLevel channel_level[channel_count] = {
		LOG_DEBUG,
		LOG_INFO,
	};
	constexpr int max_write_count = 100000;

	alignas(CACHELINE_SIZE) std::atomic<unsigned> ch1_counter = 1;
	alignas(CACHELINE_SIZE) std::atomic<unsigned> ch2_counter = 1;
	alignas(CACHELINE_SIZE) std::atomic<unsigned> max_read_count = max_write_count * 2;

	std::atomic<unsigned> *channel_counter[channel_count] = {
		&ch1_counter, &ch2_counter
	};

	CLogWriter *h1 = new CLogWriter(max_write_count, &max_read_count);
	h1->add_filter([](const LogEvent* log) -> bool {
		return log->level == LOG_DEBUG;
	});
	CLogWriter *h2 = new CLogWriter(max_write_count, &max_read_count);
	h2->add_filter([](const LogEvent* log) -> bool {
		return log->level == LOG_INFO;
	});
	CLogger *logger = new CLogger(256);
	logger->add_handler(h1);
	logger->add_handler(h2);

	std::thread th1([&] {
		while (max_read_count > 0) {
			h1->process();
			std::this_thread::yield();
		}
	});

	std::thread th2([&] {
		while (max_read_count > 0) {
			h2->process();
			std::this_thread::yield();
		}
	});

	std::thread th3([&] {
		std::mt19937 random((unsigned)time(NULL));
		for(int cnt=0; cnt < max_write_count; ++cnt)
		{
			auto i = random() % channel_count;
			auto c = channel_counter[i]->fetch_add(1, std::memory_order::memory_order_relaxed);
			logger->write(channel_level[i], &c, sizeof(c));
		}
	});

	std::thread th4([&] {
		std::mt19937 random((unsigned)time(NULL));
		for (int cnt = 0; cnt < max_write_count; ++cnt)
		{
			auto i = random() % channel_count;
			auto c = channel_counter[i]->fetch_add(1, std::memory_order::memory_order_relaxed);
			logger->write(channel_level[i], &c, sizeof(c));
		}
	});

	printf("please wait...\n");
	th1.join();
	th2.join();
	th3.join();
	th4.join();
	
	// validation
	printf("validate result...\n");
	assert(max_read_count == 0);
	auto &log1 = h1->get_logs();
	auto &log2 = h2->get_logs();
	printf("channel[1] = %d\n", log1.size());
	printf("channel[2] = %d\n", log2.size());
	assert(log1.size() + log2.size() == max_write_count * 2);
	assert(log1.size() == ch1_counter - 1);
	assert(log2.size() == ch2_counter - 1);
	std::sort(log1.begin(), log1.end());
	for (unsigned i = 0; i < log1.size(); ++i) {
		assert(i + 1 == log1[i]);
	}
	std::sort(log2.begin(), log2.end());
	for (unsigned i = 0; i < log2.size(); ++i) {
		assert(i + 1 == log2[i]);
	}

	// clear up
	delete h1;
	delete h2;
	delete logger;
	printf("Success\n");
}

void common_test()
{
	printf("stb_log common test\n");
	CLogger *logger = new CLogger(256);
	CLogHandler *handlers[] = {
		new CLogStdout(),
		new CLogDebugWindow(),
	};
	for (auto h: handlers)
		logger->add_handler(h);

	std::thread th1([&] {
		while (!handlers[0]->is_closed()) {
			handlers[0]->process();
			std::this_thread::yield();
		}
	});

	std::thread th2([&] {
		while (!handlers[1]->is_closed()) {
			handlers[1]->process();
			std::this_thread::yield();
		}
	});

	logger->write(LOG_DEBUG, "DEBUG", "hello, world");
	logger->write(LOG_INFO, "INFO", "common message");
	logger->write(LOG_WARNING, "WARNING", "it's a warning");
	logger->write(LOG_ERROR, "ERROR", "it's an error");
	logger->write(LOG_CRITICAL, "CRITICAL", "fatal error!");
	
	// close and exit
	logger->close();
	th1.join();
	th2.join();
	
	// cleanup up
	for (auto h : handlers)
		delete h;
	delete logger;
	printf("Success\n");
}

void file_rotate_test()
{
	printf("stb_log file rotate test\n");
	CLogFile *h = new CLogFile("logs/exception/test.log");
	assert(h->get_base_name() == "test.log");
#if defined(_WIN32) || defined(_WIN64)
	assert(h->get_directory() == "logs\\exception\\");
#else
	assert(h->get_directory() == "logs/exception/");
#endif
	h->rotate();
	h->rotate();
	h->rotate();
	h->rotate();
	h->rotate();

	delete h;
	printf("Success\n");
}

int main(int args, char *argv[])
{
	//thread_test();
	//common_test();
	file_rotate_test();
	getchar();
	return 0;
}