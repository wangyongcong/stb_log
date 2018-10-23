/* stb_log - v0.0.1
   
*/

#ifndef INCLUDE_STB_LOG_H
#define INCLUDE_STB_LOG_H

#include <cassert>
#include <vector>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <string>

#ifdef USE_NAMESPACE
#ifndef STB_LOG_NAMESPACE
#define STB_LOG_NAMESPACE stb
#endif
namespace STB_LOG_NAMESPACE {
#endif

	// --------------------------------
	// library settings
	// --------------------------------
	enum StbLogLevel {
		LOG_CRITICAL = 50,
		LOG_ERROR = 40,
		LOG_WARNING = 30,
		LOG_INFO = 20,
		LOG_DEBUG = 10,
		LOG_NOTSET = 0,
	};

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif
#define ASSERT_ALIGNMENT(ptr, align) assert((uintptr_t(ptr) % (align)) == 0)
	// default log file rotate size 256 MB
#define LOG_FILE_ROTATE_SIZE (256*1024*1024)
	// define log file rotate count
#define LOG_FILE_ROTATE_COUNT 8
	// logger queue buffer size in log entry count
	// the larger size, the better concurrent performance (less waiting for synchronization)
#define LOG_BUFFER_SIZE 1024
	// logger worker thread sleep time when it's casual
#define LOG_WORKER_SLEEP_TIME 20
	// log severity level
#ifndef LOG_SEVERITY_LEVEL
#define LOG_SEVERITY_LEVEL 0
#endif
	// define LogLevel
#ifdef USE_NAMESPACE
#define STB_LOG_LEVEL STB_LOG_NAMESPACE::StbLogLevel
#else
#define STB_LOG_LEVEL StbLogLevel
#endif
	// write log
#define log_write(lvl, channel, fmt, ...) (get_log_context()->logger->write(lvl, channel, (fmt), ##__VA_ARGS__))
#ifdef LOG_SEVERITY_LEVEL
	// write critical log
#if LOG_SEVERITY_LEVEL <= 50
#define log_critical(fmt,...) (get_log_context()->logger->write(STB_LOG_LEVEL::LOG_CRITICAL, "CRITICAL", (fmt), ##__VA_ARGS__))
#else
#define log_critical(fmt,...)
#endif
	// write error log
#if LOG_SEVERITY_LEVEL <= 40
#define log_error(fmt,...) (get_log_context()->logger->write(STB_LOG_LEVEL::LOG_ERROR, "ERROR", (fmt), ##__VA_ARGS__))
#else
#define log_error(fmt,...)
#endif
	// write warning log
#if LOG_SEVERITY_LEVEL <= 30
#define log_warning(fmt,...) (get_log_context()->logger->write(STB_LOG_LEVEL::LOG_WARNING, "WARNING", (fmt), ##__VA_ARGS__))
#else
#define log_warning(fmt,...)
#endif
	// write info log
#if LOG_SEVERITY_LEVEL <= 20
#define log_info(fmt,...) (get_log_context()->logger->write(STB_LOG_LEVEL::LOG_INFO, "INFO", (fmt), ##__VA_ARGS__))
#else
#define log_info(fmt,...)
#endif
	// write debug log
#if LOG_SEVERITY_LEVEL <= 10
#define log_debug(fmt,...) (get_log_context()->logger->write(STB_LOG_LEVEL::LOG_DEBUG, "DEBUG", (fmt), ##__VA_ARGS__))
#else
#define log_debug(fmt,...)
#endif
#else // skip log macro
#define log_critical(fmt,...)
#define log_error(fmt,...)
#define log_warning(fmt,...)
#define log_info(fmt,...)
#define log_debug(fmt,...)
#endif // LOG_SEVERITY_LEVEL

	// --------------------------------
	// public user interface
	// --------------------------------
	class CLogger;
	class CLogHandler;

	struct LogContext {
		CLogger *logger;
		std::vector<std::unique_ptr<std::thread>> thread_pool;
	};
	typedef std::chrono::milliseconds::rep millisecond_t;

	// get global logger singleton
	inline LogContext* get_log_context() {
		static LogContext s_logger_context;
		return &s_logger_context;
	}

	// close logger
	void close_logger();
	
	// start a logger thread
	void start_handler_thread(CLogHandler *handler, millisecond_t sleep_time);

	// start logging to standard output
	bool start_logger(millisecond_t sleep_time=LOG_WORKER_SLEEP_TIME);
	
	// start logging to file
	bool start_file_logger(const char *log_file_path, 
		bool append_mode = false, 
		int max_rotation = LOG_FILE_ROTATE_COUNT,
		size_t rotate_size = LOG_FILE_ROTATE_SIZE,
		millisecond_t sleep_time = LOG_WORKER_SLEEP_TIME
	);
	
	// start logging to debug console
	bool start_debug_logger(millisecond_t sleep_time = LOG_WORKER_SLEEP_TIME);

	// --------------------------------
	// END of interface declaration
	// --------------------------------

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

	using LogEventTime = std::chrono::system_clock::time_point;

	typedef int (*TupleAccessor) (const char*, ...);
	typedef void (*LogWriter) (TupleAccessor, const void *tuple_data);

	template<class T1, size_t... I>
	inline void unpack_tuple(TupleAccessor accessor, const T1 &t, std::index_sequence<I...>)
	{
		accessor(std::get<I>(t)...);
	}

	template<typename... Args>
	struct GenericLogWriter 
	{
		static void write(TupleAccessor accessor, const void *tuple_data)
		{
			using tuple_type_t = std::tuple<const char*, Args...>;
			constexpr size_t tuple_size = std::tuple_size<tuple_type_t>::value;
			const tuple_type_t &t = *static_cast<const tuple_type_t*>(tuple_data);
			unpack_tuple(accessor, t, std::make_index_sequence<tuple_size>());
		}
	};

	struct LogData {
		mutable std::atomic<unsigned> ref;
		int level;
		LogEventTime time;
		const char *channel;
		LogWriter writer;
	};

	struct LogEvent
	{
		Sequence publish;
		LogData *data;
	};

//	constexpr size_t log_event_fixed_buffer_size = offsetof(LogEvent, publish) - offsetof(LogEvent, buffer);

	typedef bool (*LogFilter)(const LogData*);

	class CLogger;

	class CLogTimeFormatter
	{
	public:
		virtual ~CLogTimeFormatter() {}
		virtual const char* format_time(LogEventTime t) = 0;
	};

	// time string format: "HH:MM:SS", 8 char
	class CTimeFormatter : public CLogTimeFormatter
	{
	public:
		virtual const char* format_time(LogEventTime t) override;
	private:
		static constexpr unsigned MAX_LENGTH = 9;
		char m_buf[MAX_LENGTH];
	};

	// time string format: "HH:MM:SS.xxx", 12 char
	class CMsTimeFormatter : public CLogTimeFormatter
	{
	public:
		virtual const char* format_time(LogEventTime t) override;
	private:
		static constexpr unsigned MAX_LENGTH = 13;
		char m_buf[MAX_LENGTH];
	};

	// time string format: "YYYY-MM-DD HH:MM:SS", 19 char 
	class CDateTimeFormatter : public CLogTimeFormatter
	{
	public:
		virtual const char* format_time(LogEventTime t) override;
	private:
		static constexpr unsigned MAX_LENGTH = 20;
		char m_buf[MAX_LENGTH];
	};

	class CLogHandler
	{
	public:
		static void* operator new(size_t size) {
			return aligned_alloc(alignof(CLogHandler), size);
		}
		static void operator delete(void *ptr) {
			aligned_free(ptr);
		}

		CLogHandler();
		virtual ~CLogHandler();
		void process();
		virtual void process_event(const LogData *data) {};
		virtual void on_close() {};

		inline void follow(CLogger *seq) {
			m_logger = seq;
		}
		inline uint64_t get_sequence() const {
			return m_seq.get();
		}
		inline uint64_t acquire_sequence() const {
			return m_seq.load();
		}
		inline void set_filter(LogFilter filter) {
			m_filter = filter;
		}
		inline bool is_closed() const {
			return m_closed;
		}
		inline void set_time_formatter(std::unique_ptr<CLogTimeFormatter> &&ptr) {
			m_formatter = std::move(ptr);
		}

	protected:
		CLogger* m_logger;
		LogFilter m_filter;
		std::unique_ptr<CLogTimeFormatter> m_formatter;
		bool m_closed;
		Sequence m_seq;
	};

	class CLogStdout : public CLogHandler 
	{
	public:
		virtual void process_event(const LogData *log) override;
	};

	// platform dependence filesystem api
	// It should be replaced by std::filesystem (C++17) if possible
	class CLogFileSystem
	{
	public:
#if defined(_WIN32) || defined(_WIN64)
		static constexpr char seperator = '\\';
		static constexpr char reversed_seperator = '/';
#else
		static constexpr char seperator = '/';
		static constexpr char reversed_seperator = '\\';
#endif
		static void normpath(std::string &path);
		static void split(const std::string &path, std::string &dir, std::string &file_name);
		static void split_ext(const std::string &file_name, std::string &base_name, std::string &ext);
		static bool isdir(const std::string &path);
		static bool isfile(const std::string &path);
		static bool makedirs(const std::string &path);
	};

	class CLogFile : public CLogHandler
	{
	public:
		CLogFile(const char *filepath, bool append = false, int rotate_count = LOG_FILE_ROTATE_COUNT, size_t rotate_size=LOG_FILE_ROTATE_SIZE);
		virtual ~CLogFile();
		virtual void process_event(const LogData *log) override;
		virtual void on_close() override;
		inline bool is_ready() const {
			return m_hfile != nullptr;
		}
		inline const std::string& get_directory() const {
			return m_logpath;
		}
		inline const std::string& get_base_name() const {
			return m_logname;
		}
		inline const std::string& get_file_path() const {
			return m_curfile;
		}
		void rotate();

	private:
		static FILE* _share_open(const char* path, const char* mode);

		FILE * m_hfile;
		std::string m_logpath;
		std::string m_logname;
		std::string m_curfile;
		size_t m_cur_size;
		size_t m_rotate_size;
		int m_rotate_count;
	};

#if defined(_WIN32) || defined(_WIN64)
	class CLogDebugWindow : public CLogHandler
	{
	public:
		CLogDebugWindow();
		virtual void process_event(const LogData *log) override;
	private:
		bool m_is_debugger;
	};
#endif

	class CLogger
	{
	public:
		CLogger(size_t buf_size);
		~CLogger();
		CLogger(const CLogger&) = delete;
		CLogger& operator = (const CLogger&) = delete;

		template<class... Args>
		void write(int level, const char* channel, const char *format, Args... args) {
			using tuple_t = std::tuple<const char*, Args...>;
			constexpr size_t size = sizeof(LogData) + sizeof(tuple_t);
			char *buf = new char[size];
			new(buf + sizeof(LogData)) tuple_t{format, args...};
			LogData *data = reinterpret_cast<LogData*>(buf);
			data->ref = 1;
			data->level = level;
			data->time = std::chrono::system_clock::now();
			data->channel = channel;
			data->writer = &GenericLogWriter<Args...>::write;
			// publish event
			uint64_t seq = _claim(1);
			LogEvent *log = get_event(seq);
			if(log->data) {
				if(1 == log->data->ref.fetch_sub(1))
					delete [] (char*)log->data;
			}
			log->data = data;
			log->publish.store(seq + 1);
		}

		template<class T>
		void write(int level, const char* channel, const T &obj) {
			constexpr size_t size = sizeof(LogData) + sizeof(obj);
			char *buf = new char[size];
			LogData *data = reinterpret_cast<LogData*>(buf);
			data->ref = 1;
			data->level = level;
			data->time = std::chrono::system_clock::now();
			data->channel = channel;
			data->writer = nullptr;
			new(buf + sizeof(LogData)) T(obj);
			// publish event
			uint64_t seq = _claim(1);
			LogEvent *log = get_event(seq);
			if(log->data) {
				if(1 == log->data->ref.fetch_sub(1))
					delete [] (char*)log->data;
			}
			log->data = data;
			log->publish.store(seq + 1);
		}

		void add_handler(CLogHandler *handler);
		void remove_handler(CLogHandler *handler);
		inline void close() {
			uint64_t seq = _claim(1);
			LogEvent *log = get_event(seq);
			log->data = nullptr;
			log->publish.store(seq + 1);
		}
		inline const LogEvent* get_event(uint64_t seq) const {
			return m_event_queue + (seq & m_size_mask);
		}
		inline LogEvent* get_event(uint64_t seq) {
			return m_event_queue + (seq & m_size_mask);
		}

		static void* operator new(size_t size) {
			return aligned_alloc(alignof(CLogger), size);
		}
		static void operator delete(void *ptr) {
			aligned_free(ptr);
		}
		static size_t get_next_power2(size_t val);

	private:
		uint64_t _claim(uint64_t count);

		LogEvent * m_event_queue;
		size_t m_size_mask;
		std::vector<CLogHandler*> m_handler_list;
		uint64_t m_min_seq;
		Sequence m_seq_claim;
	};

#ifdef USE_NAMESPACE
}
#endif
#endif // NCLUDE_STB_LOG_H

#ifdef STB_LOG_IMPLEMENTATION

//#include <emmintrin.h>
#include <sys/stat.h>
#include <cstdarg>
#include <ctime>
#include <string>
#include <algorithm>

#define LOG_EVENT_BUFFER(log) (char*)(((log)->capacity <= log_event_fixed_buffer_size) ? ((log)->fixed_buffer) : ((log)->buffer))

#ifdef USE_NAMESPACE
namespace STB_LOG_NAMESPACE {
#endif

	void start_handler_thread(CLogHandler *handler, millisecond_t sleep_time) 
	{
		LogContext *lc = get_log_context();
		if (!lc->logger)
			lc->logger = new CLogger(LOG_BUFFER_SIZE);
		lc->logger->add_handler(handler);
		std::chrono::milliseconds msec(sleep_time);
		lc->thread_pool.emplace_back(std::make_unique<std::thread>([handler, msec] {
			while (!handler->is_closed()) {
				handler->process();
				std::this_thread::sleep_for(msec);
			}
		}));
	}

	void close_logger()
	{
		LogContext *lc = get_log_context();
		if (!lc->logger)
			return;
		lc->logger->close();
		for (auto &th : lc->thread_pool) {
			th->join();
		}
		lc->thread_pool.clear();
		delete lc->logger;
		lc->logger = nullptr;
	}

	bool start_logger(millisecond_t sleep_time)
	{
		CLogStdout *handler = new CLogStdout();
		handler->set_time_formatter(std::make_unique<CDateTimeFormatter>());
		start_handler_thread(handler, sleep_time);
		return true;
	}

	bool start_file_logger(const char *log_file_path, bool append_mode, 
		int max_rotation, size_t rotate_size, millisecond_t sleep_time)
	{
		CLogFile *handler = new CLogFile(log_file_path, append_mode, max_rotation, rotate_size);
		handler->set_time_formatter(std::make_unique<CDateTimeFormatter>());
		start_handler_thread(handler, sleep_time);
		return true;
	}
	
	bool start_debug_logger(millisecond_t sleep_time)
	{
#if defined(_WIN32) || defined(_WIN64)
		CLogDebugWindow *handler = new CLogDebugWindow(); 
		handler->set_time_formatter(std::make_unique<CDateTimeFormatter>());
		start_handler_thread(handler, sleep_time);
		return true;
#else
		return false;
#endif
	}

	size_t CLogger::get_next_power2(size_t val)
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

	// --------------------------------
	// CLogger implementation
	// --------------------------------

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
			log->data = nullptr;
			log->publish.set(0);
		}
		m_seq_claim.set(0);
		m_min_seq = 0;
	}

	CLogger::~CLogger()
	{
		for (auto handler : m_handler_list)
		{
			handler->follow(nullptr);
		}
		for (size_t i = 0; i <= m_size_mask; ++i) {
			// clean up LogEvent
			LogEvent *log = &m_event_queue[i];
			if (log->data) {
				delete[] log->data;
				log->data = nullptr;
			}
		}
		aligned_free(m_event_queue);
		m_event_queue = nullptr;
	}


	uint64_t CLogger::_claim(uint64_t count) 
	{
		uint64_t request_seq = m_seq_claim.fetch_add(count);
		if (request_seq <= m_min_seq + m_size_mask) {
			return request_seq;
		}
		uint64_t min_seq = ULLONG_MAX, seq = 0;
		// TODO: need a better spin lock
		for (CLogHandler *handler : m_handler_list) {
			seq = handler->get_sequence();
			while (request_seq > seq + m_size_mask) {
//				_mm_pause(); // pause, about 12ns
//				seq = handler->get_sequence();
//				if (request_seq <= seq + m_size_mask)
//					break;
				// if no waiting threads, about 113ns
				// else lead to thread switching
				std::this_thread::yield();
				seq = handler->get_sequence();
			}
			seq = handler->acquire_sequence();
			if (seq < min_seq)
				min_seq = seq;
		}
		m_min_seq = min_seq;
		return request_seq;
	}

	void CLogger::add_handler(CLogHandler * handler)
	{
		m_handler_list.push_back(handler);
		handler->follow(this);
	}

	void CLogger::remove_handler(CLogHandler * handler)
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

	// --------------------------------
	// CLogHandler implementation
	// --------------------------------

	CLogHandler::CLogHandler()
		: m_logger(nullptr)
		, m_filter(nullptr)
		, m_formatter(nullptr)
		, m_closed(false)
	{
		ASSERT_ALIGNMENT(this, CACHELINE_SIZE);
		ASSERT_ALIGNMENT(&m_seq, CACHELINE_SIZE);
		m_seq.set(0);
	}

	CLogHandler::~CLogHandler()
	{
		if (m_logger) {
			m_logger->remove_handler(this);
			m_logger = nullptr;
		}
	}
	
	void CLogHandler::process() 
	{
		assert(m_logger);
		uint64_t seq = m_seq.get(), pub;
		const LogEvent *log;
		const LogData *data = nullptr;
		std::vector<const LogData*> log_entries;
		constexpr unsigned batch_size = 64;
		log_entries.reserve(batch_size);
		while (!m_closed) {
			log = m_logger->get_event(seq);
			pub = log->publish.load();
			if (pub > seq) {
				data = log->data;
				if(!data) {
					m_closed = true;
				}
				else if(!m_filter or m_filter(data)){
					data->ref.fetch_add(1, std::memory_order_relaxed);
					log_entries.push_back(data);
				}
				m_seq.store(pub);
				seq += 1;
				assert(pub == seq);
				if(log_entries.size() < batch_size)
					continue;
			}
			break;
		}
		for(auto iter: log_entries) {
			process_event(iter);
			if(1 == iter->ref.fetch_sub(1)) {
				delete [] (char*)iter;
			}
		}
		if(m_closed)
			on_close();
	}

	// --------------------------------
	// CLogTimeFormatter implementation
	// --------------------------------
#if defined(WIN32) || defined(WIN64)
#define LOCALTIME(datetime, timestam) localtime_s(&(datetime), &(timestamp))
#define S_IFDIR _S_IFDIR
#define S_IFREG _S_IFREG
#else
#define LOCALTIME(datetime, timestamp) localtime_r(&(timestamp), &(datetime))
#endif

	const char* CTimeFormatter::format_time(LogEventTime t)
	{
		time_t timestamp = std::chrono::system_clock::to_time_t(t);
		tm datetime;
		LOCALTIME(datetime, timestamp);
		if (strftime(m_buf, MAX_LENGTH, "%T", &datetime) == 0) {
			m_buf[MAX_LENGTH - 1] = 0;
		}
		return m_buf;
	}

	const char* CMsTimeFormatter::format_time(LogEventTime t) 
	{
		time_t timestamp = std::chrono::system_clock::to_time_t(t);
		tm datetime;
		LOCALTIME(datetime, timestamp);
		auto len = strftime(m_buf, MAX_LENGTH, "%T", &datetime);
		if (len == 0) {
			m_buf[MAX_LENGTH - 1] = 0;
			return m_buf;
		}
		auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch());
		sprintf(m_buf + len, ".%03d", int(msec.count() % 1000));
		return m_buf;
	}

	const char* CDateTimeFormatter::format_time(LogEventTime t) 
	{
		time_t timestamp = std::chrono::system_clock::to_time_t(t);
		tm datetime;
		LOCALTIME(datetime, timestamp);
		if (strftime(m_buf, MAX_LENGTH, "%F %T", &datetime) == 0) {
			m_buf[MAX_LENGTH - 1] = 0;
		}
		return m_buf;
	}

	// --------------------------------
	// Standard logger implementation
	// --------------------------------

	void CLogStdout::process_event(const LogData * log)
	{
		if (m_formatter) {
			const char *stime = m_formatter->format_time(log->time);
			printf("[%s]", stime);
		}
		if (log->channel[0] != 0) {
			printf(" [%s]", log->channel);
		}
		const char *message = (const char*)log + sizeof(LogData);
		log->writer(printf, message);
	}

	// --------------------------------
	// File system implementation
	// --------------------------------
	
	void CLogFileSystem::normpath(std::string & path)
	{
		std::replace(path.begin(), path.end(), char(reversed_seperator), char(seperator));
	}

	void CLogFileSystem::split(const std::string &path, std::string &dir, std::string &file_name)
	{
		size_t pos = path.rfind(seperator);
		if (pos != std::string::npos) {
			pos += 1;
			dir = path.substr(0, pos);
			file_name = path.substr(pos);
		}
		else {
			dir = "";
			file_name = path;
		}
	}

	void CLogFileSystem::split_ext(const std::string &file_name, std::string &base_name, std::string &ext)
	{
		size_t pos = file_name.rfind('.');
		if (pos != std::string::npos) {
			base_name = file_name.substr(0, pos);
			ext = file_name.substr(pos);
		}
		else {
			base_name = file_name;
			ext = "";
		}
	}

	bool CLogFileSystem::isdir(const std::string &path)
	{
		struct stat path_st;
		return stat(path.c_str(), &path_st) == 0 && path_st.st_mode & S_IFDIR;
	}

	bool CLogFileSystem::isfile(const std::string &path)
	{
		struct stat path_st;
		return stat(path.c_str(), &path_st) == 0 && path_st.st_mode & S_IFREG;
	}

	bool CLogFileSystem::makedirs(const std::string &path)
	{
		std::string cmd = "mkdir ";
		cmd += path;
		if (std::system(cmd.c_str())) {
			return false;
		}
		return true;
	}

	// --------------------------------
	// File logger implementation
	// --------------------------------

	FILE * CLogFile::_share_open(const char * path, const char *mode)
	{
#if defined(_WIN32) || defined(_WIN64)
		return _fsopen(path, mode, _SH_DENYWR);
#else
		return fopen(path, mode);
#endif
	}

	CLogFile::CLogFile(const char* filepath, bool append, int rotate_count, size_t rotate_size)
		: m_hfile(nullptr)
		, m_cur_size(0)
		, m_rotate_size(rotate_size)
		, m_rotate_count(rotate_count)
		, m_curfile(filepath)
	{
		CLogFileSystem::normpath(m_curfile);
		CLogFileSystem::split(m_curfile, m_logpath, m_logname);
		if (!CLogFileSystem::isdir(m_logpath) && !CLogFileSystem::makedirs(m_logpath)) {
			printf("Fail to create log director [%s]\n", m_logpath.c_str());
			m_logpath = "";
		}
		if (append)
			m_hfile = _share_open(m_curfile.c_str(), "a");
		else if (CLogFileSystem::isfile(m_curfile))
			rotate();
		else
			m_hfile = _share_open(m_curfile.c_str(), "w");
	}

	CLogFile::~CLogFile() 
	{
		if (m_hfile) {
			fclose(m_hfile);
			m_hfile = 0;
		}
	}

	void CLogFile::process_event(const LogData *log)
	{
//		if (m_formatter) {
//			const char *stime = m_formatter->format_time(log->time);
//			m_cur_size += fprintf(m_hfile, "[%s] ", stime);
//		}
//		if (log->channel[0] != 0) {
//			m_cur_size += fprintf(m_hfile, "[%s] ", log->channel);
//		}
//		const char *message = LOG_EVENT_BUFFER(log);
//		m_cur_size += fprintf(m_hfile, "%s\n", message);
//		fflush(m_hfile);
//		if (m_cur_size >= m_rotate_size) {
//			rotate();
//		}
	}

	void CLogFile::on_close()
	{
		if (m_hfile) {
			fclose(m_hfile);
			m_hfile = 0;
		}
	}

	void CLogFile::rotate()
	{
		if (m_rotate_count < 1)
			return;
		if (m_hfile) {
			fclose(m_hfile);
			m_hfile = 0;
		}
		std::string logfile, ext;
		CLogFileSystem::split_ext(m_curfile, logfile, ext);
		std::string last_file = logfile, cur_file;
		last_file += std::to_string(m_rotate_count);
		last_file += ext;
		if (CLogFileSystem::isfile(last_file)) {
			if (std::remove(last_file.c_str()) != 0)
				return;
		}
		for (int i = m_rotate_count - 1; i >= 0; --i)
		{
			cur_file = logfile;
			cur_file += std::to_string(i);
			cur_file += ext;
			if (CLogFileSystem::isfile(cur_file)) 
				std::rename(cur_file.c_str(), last_file.c_str());
			last_file = cur_file;
		}
		std::rename(m_curfile.c_str(), last_file.c_str());
		m_hfile = _share_open(m_curfile.c_str(), "w");
	}

	// --------------------------------
	// Windows debug logger
	// --------------------------------

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
	
	CLogDebugWindow::CLogDebugWindow()
	{
		m_is_debugger = IsDebuggerPresent();
	}

	void CLogDebugWindow::process_event(const LogData * log)
	{
		if (!m_is_debugger)
			return;
		if (m_formatter) {
			const char *stime = m_formatter->format_time(log->time);
			OutputDebugStringA("[");
			OutputDebugStringA(stime);
			OutputDebugStringA("] ");
		}
		if (log->channel[0] != 0) {
			OutputDebugStringA("[");
			OutputDebugStringA(log->channel);
			OutputDebugStringA("] ");
		}
		const char *message = LOG_EVENT_BUFFER(log);
		OutputDebugStringA(message);
		OutputDebugStringA("\n");
	}
#endif // _WIN32 || _WIN64

#ifdef USE_NAMESPACE
}
#endif
#endif // STB_LOG_IMPLEMENTATION
