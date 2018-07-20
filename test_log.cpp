#include <stdio.h>
#include <time.h>
#include <random>
#define STB_LOG_IMPLEMENTATION
#include "stb_log.h"

using namespace wyc;

class CLogWriter: public ILogHandler
{
public:
	CLogWriter(int max_size, unsigned level, std::atomic<int> *counter)
		: m_level(level)
		, m_counter(counter)
	{
		m_logs.reserve(max_size);
	}

	virtual void process_event(const LogEvent *log) override
	{
		if (m_level == log->level)
		{
			m_logs.push_back(*(int*)(log->fixed_buffer));
			m_counter->fetch_sub(1, std::memory_order::memory_order_relaxed);
		}
	}

	inline std::vector<unsigned> get_logs() {
		return m_logs;
	}

private:
	unsigned m_level;
	std::vector<unsigned> m_logs;
	std::atomic<int> *m_counter;
};

void common_test()
{
	printf("stb_log common test\n");
	printf("core: %d\n", std::thread::hardware_concurrency());

	constexpr int channel_count = 2;
	const char* channel_name[channel_count] = {
		"C1", "C2"
	};
	const StbLogLevel channel_level[channel_count] = {
		StbLogLevel::DEBUG,
		StbLogLevel::INFO,
	};
	constexpr int max_write_count = 100000;

	alignas(CACHELINE_SIZE) std::atomic<int> ch1_counter = 1;
	alignas(CACHELINE_SIZE) std::atomic<int> ch2_counter = 1;
	alignas(CACHELINE_SIZE) std::atomic<int> max_read_count = max_write_count * 2;

	std::atomic<int> *channel_counter[channel_count] = {
		&ch1_counter, &ch2_counter
	};

	CLogger *logger = new CLogger(256);
	CLogWriter *h1 = new CLogWriter(max_write_count, channel_level[0], &max_read_count);
	logger->add_handler(h1);
	CLogWriter *h2 = new CLogWriter(max_write_count, channel_level[1], &max_read_count);
	logger->add_handler(h2);

	std::thread t1([&] {
		while (max_read_count > 0) {
			h1->process();
			std::this_thread::yield();
		}
	});

	std::thread t2([&] {
		while (max_read_count > 0) {
			h2->process();
			std::this_thread::yield();
		}
	});

	std::thread t3([&] {
		std::mt19937 random((unsigned)time(NULL));
		for(int cnt=0; cnt < max_write_count; ++cnt)
		{
			auto i = random() % channel_count;
			auto c = channel_counter[i]->fetch_add(1, std::memory_order::memory_order_relaxed);
			logger->write(channel_level[i], channel_name[i], &c, sizeof(c));
		}
	});

	std::thread t4([&] {
		std::mt19937 random((unsigned)time(NULL));
		for (int cnt = 0; cnt < max_write_count; ++cnt)
		{
			auto i = random() % channel_count;
			auto c = channel_counter[i]->fetch_add(1, std::memory_order::memory_order_relaxed);
			logger->write(channel_level[i], channel_name[i], &c, sizeof(c));
		}
	});

	printf("please wait...\n");
	t1.join();
	t2.join();
	t3.join();
	t4.join();
	
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
	logger->remove_handler(h1);
	logger->remove_handler(h2);
	delete h1;
	delete h2;
	delete logger;
	printf("Success\n");
}

int main(int args, char *argv[])
{
	common_test();
	getchar();
	return 0;
}