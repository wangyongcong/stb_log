/* stb_log - v0.0.1
   
*/

#ifndef INCLUDE_STB_LOG_H
#define INCLUDE_STB_LOG_H

#include <cstdlib>
#include <cassert>
#include <vector>
#include <atomic>
#include <thread>
#include <new>
#include <emmintrin.h>

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

#ifndef CACHELINE_SIZE
	#define CACHELINE_SIZE 64
#endif
#define ASSERT_ALIGNMENT(ptr, align) assert((uintptr_t(ptr) % (align)) == 0)

	struct alignas(CACHELINE_SIZE) Sequence
	{
		std::atomic<uint64_t> value;
		char _padding[CACHELINE_SIZE - sizeof(std::atomic<uint64_t>)];

		inline void set(uint64_t v) {
			value = v;
		}
		inline uint64_t get() const {
			return value;
		}
		inline uint64_t load() const {
			return value.load(std::memory_order::memory_order_acquire);
		}
		inline void store(uint64_t v) {
			value.store(v, std::memory_order::memory_order_release);
		}
		inline uint64_t fetch_add(uint64_t v) {
			return value.fetch_add(v, std::memory_order::memory_order_relaxed);
		}
	};

	void *aligned_alloc(size_t alignment, size_t size) 
	{
		// [Memory returned][ptr to start of memory][aligned memory][extra memory]
		size_t request_size = size + alignment ;
		void *raw = malloc(request_size + sizeof(void*));
		if (!raw)
			return nullptr;
		void *ptr = (void**)raw + 1;
		ptr = std::align(alignment, size, ptr, request_size);
		if (!ptr) {
			free(raw);
			return nullptr;
		}
		*((void**)ptr - 1) = raw;
		return ptr;
	}

	void aligned_free(void *ptr) 
	{
		void *raw = *((void**)ptr - 1);
		free(raw);
	}

	struct LogEvent
	{
		int level;
		int size;
		char channel[16];
		union {
			void *data;
			char fixed_buffer[1];
		};
		Sequence publish;
	};
	constexpr unsigned log_event_fixed_buffer_size = offsetof(LogEvent, publish) - offsetof(LogEvent, data);

	class ILogFilter
	{
	public:
		virtual ~ILogFilter() {}
	};

	class CLogger;

	class ILogHandler
	{
	public:
		static void* operator new(size_t size) {
			return aligned_alloc(alignof(ILogHandler), size);
		}
		static void operator delete(void *ptr) {
			aligned_free(ptr);
		}

		ILogHandler()
			: m_logger(nullptr)
			, m_filter_list(nullptr)
		{
			ASSERT_ALIGNMENT(this, CACHELINE_SIZE);
			ASSERT_ALIGNMENT(&m_seq, CACHELINE_SIZE);
			m_seq.set(0);
		}
		virtual ~ILogHandler() {}

		inline void follow(const CLogger *seq) {
			m_logger = seq;
		}
		inline uint64_t get_sequence() const {
			return m_seq.get();
		}
		inline uint64_t acquire_sequence() const {
			return m_seq.load();
		}

		void process();
		virtual void process_event(const LogEvent *log) = 0;

	private:
		const CLogger* m_logger;
		ILogFilter *m_filter_list;
		Sequence m_seq;
	};

	class CLogger
	{
	public:
		static void* operator new(size_t size) {
			return aligned_alloc(alignof(CLogger), size);
		}
		static void operator delete(void *ptr) {
			aligned_free(ptr);
		}

		CLogger(size_t buf_size);
		~CLogger();
		CLogger(const CLogger&) = delete;
		CLogger& operator = (const CLogger&) = delete;
		void write(int level, const char* channel, const void *data, size_t size);
		void add_handler(ILogHandler *handler);
		void remove_handler(ILogHandler *handler);
		const LogEvent* get_event(uint64_t seq) const {
			return m_event_queue + (seq & m_size_mask);
		}
		LogEvent* get_event(uint64_t seq) {
			return m_event_queue + (seq & m_size_mask);
		}
		
	private:
		LogEvent * m_event_queue;
		unsigned m_size_mask;
		std::vector<ILogHandler*> m_handler_list;
		uint64_t m_min_seq;
		Sequence m_seq_claim;

		uint64_t _claim(uint64_t count);
	};

#ifdef USE_NAMESPACE
}
#endif

#endif // NCLUDE_STB_LOG_H

#ifdef STB_LOG_IMPLEMENTATION

#ifdef USE_NAMESPACE
namespace wyc {
#endif

	inline size_t get_next_power2(size_t val)
	{
		// val maybe power of 2
		--val;
		// set the bits right of MSB to 1
		val |= (val >> 1);
		val |= (val >> 2);
		val |= (val >> 4);
		val |= (val >> 8);		/* Ok, since int >= 16 bits */
#if (SIZE_MAX != 0xffff)
		val |= (val >> 16);		/* For 32 bit int systems */
#if (SIZE_MAX > 0xffffffffUL)
		val |= (val >> 32);		/* For 64 bit int systems */
#endif // SIZE_MAX != 0xffff
#endif // SIZE_MAX > 0xffffffffUL
		++val;
		assert((val & (val - 1)) == 0);
		return val;
	}

	CLogger::CLogger(size_t size)
	{
		assert(size > 0);
		if (size & (size - 1)) 
			size = get_next_power2(size);
		assert(sizeof(LogEvent) % CACHELINE_SIZE == 0);
		size_t buf_size = sizeof(LogEvent) * size;
		m_event_queue = (LogEvent*)aligned_alloc(CACHELINE_SIZE, buf_size);
		assert(m_event_queue);
		m_size_mask = size - 1;
		for (size_t i = 0; i < size; ++i) {
			LogEvent *log = &m_event_queue[i];
			ASSERT_ALIGNMENT(log, CACHELINE_SIZE);
			ASSERT_ALIGNMENT(&log->publish, CACHELINE_SIZE);
			// initialize LogEvent
			log->size = 0;
			log->publish.set(0);
		}
		m_seq_claim.set(0);
		m_min_seq = 0;
	}

	CLogger::~CLogger()
	{
		for (size_t i = 0; i <= m_size_mask; ++i) {
			// clean up LogEvent
			LogEvent *log = &m_event_queue[i];
			if (log->data) {
				//delete log->data;
				log->data = nullptr;
			}
		}
		aligned_free(m_event_queue);
		m_event_queue = nullptr;
	}

	void CLogger::write(int level, const char* channel, const void *data, size_t size)
	{
		uint64_t seq = _claim(1);
		// write event data
		LogEvent *log = get_event(seq);
		log->level = level;
		unsigned last = sizeof(log->channel) - 1;
		strncpy(log->channel, channel, last);
		log->channel[last] = 0;
		assert(size < log_event_fixed_buffer_size);
		memcpy(&log->fixed_buffer, data, size);
		log->size = size;
		// publish event
		log->publish.store(seq + 1);
	}

	uint64_t CLogger::_claim(uint64_t count) 
	{
		uint64_t request_seq = m_seq_claim.fetch_add(count);
		if (request_seq < m_min_seq)
			return request_seq;
		uint64_t min_seq = ULLONG_MAX, seq;
		for (ILogHandler *handler : m_handler_list) {
			seq = handler->get_sequence();
			while (request_seq > seq + m_size_mask) {
				_mm_pause(); // pause, about 12ns
				seq = handler->get_sequence();
				if (request_seq <= seq + m_size_mask)
					break;
				// if no waiting threads, about 113ns
				// else lead to thread switching
				std::this_thread::yield();
				seq = handler->get_sequence();
			}
			seq = handler->acquire_sequence();
			if (seq < min_seq)
				min_seq = seq;
		}
		m_min_seq = seq;
		return request_seq;
	}

	void CLogger::add_handler(ILogHandler * handler)
	{
		m_handler_list.push_back(handler);
		handler->follow(this);
	}

	void CLogger::remove_handler(ILogHandler * handler)
	{
		for (auto iter = m_handler_list.begin(); iter != m_handler_list.end(); ++iter) {
			if (*iter == handler)
			{
				m_handler_list.erase(iter);
				handler->follow(nullptr);
				return;
			}
		}
	}

	void ILogHandler::process() 
	{
		assert(m_logger);
		uint64_t seq = m_seq.get(), pub;
		const LogEvent *log;
		while (true) {
			log = m_logger->get_event(seq);
			pub = log->publish.load();
			if (pub > seq) {
				process_event(log);
				m_seq.store(pub);
				seq += 1;
				assert(pub == seq);
				continue;
			}
			break;
		}
	}

#ifdef USE_NAMESPACE
}
#endif

#endif // STB_LOG_IMPLEMENTATION
