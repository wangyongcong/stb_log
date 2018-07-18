/* stb_log - v0.0.1
   
*/

#ifndef INCLUDE_STB_LOG_H
#define INCLUDE_STB_LOG_H

#include <array>
#include <vector>
#include <atomic>
#include <new>

#ifdef USE_NAMESPACE
namespace wyc {
#endif

	enum StbLogLevel
	{
		CRITICAL = 50,
		ERROR = 40,
		WARNING = 30,
		INFO = 20,
		DEBUG = 10,
		NOTSET = 0,
	};

	constexpr size_t DefaultLogQueueSize = 1024;
	template<typename T, size_t N = DefaultLogQueueSize >
	class CLogRingBuffer {
		static_assert((N > 0) && (N & (N - 1)) == 0, "CLogRingBuffer size must be positive power of 2");
	
	public:
		T& operator[] (size_t i) {
			return m_events[i & (N - 1)];
		}

		const T& operator[] (size_t i) const {
			return m_events[i & (N - 1)];
		}

	private:
		std::array<T, N> m_events;
	};

#ifndef CACHELINE_SIZE
	#define CACHELINE_SIZE 64
#endif
#define PADDING_SIZE(s, p) (((s + p - 1) / p) * p - s)

	struct LogEvent
	{
		int level;
		char channel[32];
	};

	class ILogFilter
	{
	public:
		virtual ~ILogFilter() {}
	};

	class ILogHandler
	{
	public:
		virtual ~ILogHandler() {}

	private:
		alignas(CACHELINE_SIZE) std::atomic<int64_t> m_seq;
		alignas(CACHELINE_SIZE) ILogFilter *m_filter_list;
	};

	class CLogger
	{
	public:
		CLogger(size_t buf_size);
		~CLogger();
		CLogger(const CLogger&) = delete;
		CLogger& operator = (const CLogger&) = delete;
		void write(int level, const char* channel, const char *message, ...);
		void add_handler(ILogHandler *handler);

	private:
		alignas(CACHELINE_SIZE) std::atomic<int64_t> m_seq_claim;
		alignas(CACHELINE_SIZE) LogEvent * m_event_queue;
		ILogHandler *m_handler_list;
	};

#ifdef USE_NAMESPACE
}
#endif

#endif // NCLUDE_STB_LOG_H

#ifdef STB_LOG_IMPLEMENTATION

#ifdef USE_NAMESPACE
namespace wyc {
#endif

	CLogger::CLogger(size_t buf_size)
	{
	}

	CLogger::~CLogger()
	{
	}

#ifdef USE_NAMESPACE
}
#endif

#endif // STB_LOG_IMPLEMENTATION
