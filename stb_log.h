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

#ifndef STB_LOG_NAMESPACE
#define STB_LOG_NAMESPACE namespace stb
#endif

#ifdef USE_NAMESPACE
STB_LOG_NAMESPACE {
#endif

	// --------------------------------
	// library settings
	// --------------------------------

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
#define LOG_BUFFER_SIZE 256
	// logger worker thread sleep time when it's casual
#define LOG_WORKER_SLEEP_TIME 1

	// --------------------------------
	// public user interface
	// --------------------------------

	enum StbLogLevel
	{
		LOG_CRITICAL = 50,
		LOG_ERROR = 40,
		LOG_WARNING = 30,
		LOG_INFO = 20,
		LOG_DEBUG = 10,
		LOG_NOTSET = 0,
		// negative values are reserved for internal ctrl code
		LOG_CODE_CLOSE = -1,  
	};
	
	typedef std::chrono::milliseconds::rep millisecond_t;

	class CLogger;

	struct LoggerContext {
		CLogger *logger;
		std::vector<std::thread*> thread_pool;
	};
	// get global logger singleton
	inline LoggerContext* get_logger() {
		static LoggerContext s_logger_context;
		return &s_logger_context;
	}
	// close logger
	void close_logger();

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

	struct LogEvent
	{
		int level;
		unsigned capacity;
		char channel[16];
		LogEventTime time;
		union {
			void *buffer;
			char fixed_buffer[1];
		};
		Sequence publish;
	};
	constexpr unsigned log_event_fixed_buffer_size = offsetof(LogEvent, publish) - offsetof(LogEvent, buffer);

	typedef bool (*LogFilter)(const LogEvent*);

	class CLogger;

	class CLogTimeFormatter
	{
	public:
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
		virtual void process_event(const LogEvent *log) {};
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
		inline void add_filter(LogFilter filter) {
			m_filters.push_back(filter);
		}
		inline bool is_closed() const {
			return m_closed;
		}
		inline void set_time_formatter(std::unique_ptr<CLogTimeFormatter> &&ptr) {
			m_formatter = std::move(ptr);
		}

	protected:
		CLogger* m_logger;
		std::vector<LogFilter> m_filters;
		std::unique_ptr<CLogTimeFormatter> m_formatter;
		bool m_closed;
		Sequence m_seq;
	};

	class CLogStdout : public CLogHandler 
	{
	public:
		virtual void process_event(const LogEvent *log) override;
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
		virtual void process_event(const LogEvent *log) override;
		virtual void on_close() override;
		inline bool is_ready() const {
			return m_hfile != 0;
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
		virtual void process_event(const LogEvent *log) override;
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
		void write(int level, const void *data = 0, size_t size = 0);
		void write(int level, const char* channel, const char *format, ...);
		void add_handler(CLogHandler *handler);
		void remove_handler(CLogHandler *handler);
		inline void close() {
			write((int)StbLogLevel::LOG_CODE_CLOSE);
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
		static char* ensure_buffer(LogEvent *log, size_t size);

	private:
		uint64_t _claim(uint64_t count);
		
		LogEvent * m_event_queue;
		unsigned m_size_mask;
		std::vector<CLogHandler*> m_handler_list;
		uint64_t m_min_seq;
		Sequence m_seq_claim;
	};

#ifdef USE_NAMESPACE
}
#endif
#endif // NCLUDE_STB_LOG_H

#ifdef STB_LOG_IMPLEMENTATION

#include <emmintrin.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <ctime>
#include <string>

#define LOG_EVENT_BUFFER(log) (char*)(((log)->capacity <= log_event_fixed_buffer_size) ? ((log)->fixed_buffer) : ((log)->buffer))

#ifdef USE_NAMESPACE
STB_LOG_NAMESPACE {
#endif

#define ENSURE_LOGGER(context) if(!(context)->logger) {\
	(context)->logger = new CLogger(LOG_BUFFER_SIZE);\
}

	void start_handler_thread(CLogHandler *handler, millisecond_t sleep_time) 
	{
		LoggerContext *lc = get_logger();
		ENSURE_LOGGER(lc);
		lc->logger->add_handler(handler);
		std::chrono::milliseconds msec(sleep_time);
		std::thread *worker = new std::thread([handler, msec] {
			while (!handler->is_closed()) {
				handler->process();
				std::this_thread::sleep_for(msec);
			}
		});
		lc->thread_pool.push_back(worker);
	}

	void close_logger()
	{
		LoggerContext *lc = get_logger();
		if (!lc->logger)
			return;
		lc->logger->close();
		for (auto th : lc->thread_pool) {
			th->join();
		}
		lc->thread_pool.clear();
		delete lc->logger;
		lc->logger = nullptr;
	}

	bool start_logger(millisecond_t sleep_time)
	{
		CLogStdout *handler = new CLogStdout();
		start_handler_thread(handler, sleep_time);
		return true;
	}

	bool start_file_logger(const char *log_file_path, bool append_mode, 
		int max_rotation, size_t rotate_size, millisecond_t sleep_time)
	{
		CLogFile *handler = new CLogFile(log_file_path, append_mode, max_rotation, rotate_size);
		start_handler_thread(handler, sleep_time);
		return true;
	}
	
	bool start_debug_logger(millisecond_t sleep_time)
	{
		CLogDebugWindow *handler = new CLogDebugWindow(); 
		start_handler_thread(handler, sleep_time);
		return true;
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
			log->capacity = log_event_fixed_buffer_size;
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
			if (log->capacity > log_event_fixed_buffer_size) {
				delete[] log->buffer;
			}
		}
		aligned_free(m_event_queue);
		m_event_queue = nullptr;
	}

	void CLogger::write(int level, const void *data, size_t size)
	{
		uint64_t seq = _claim(1);
		// write header
		LogEvent *log = get_event(seq);
		log->level = level;
		log->channel[0] = 0;
		// write data
		if (data && size > 0) {
			char *buf = ensure_buffer(log, size);
			memcpy(buf, data, size);
		}
		// publish event
		log->publish.store(seq + 1);
	}

	void CLogger::write(int level, const char * channel, const char * format, ...)
	{
		va_list args;
		va_start(args, format);
		int length = vsnprintf(0, 0, format, args);
		va_end(args);
		if (length <= 0)
			return;
		uint64_t seq = _claim(1);
		// write header
		LogEvent *log = get_event(seq);
		log->level = level;
		log->time = std::chrono::system_clock::now();
		constexpr unsigned channel_size = sizeof(log->channel) - 1;
		if (strlen(channel) <= channel_size)
			strcpy(log->channel, channel);
		else {
			strncpy(log->channel, channel, channel_size);
			log->channel[channel_size] = 0;
		}
		// write data
		char *buf = ensure_buffer(log, length + 1);
		va_start(args, format);
		length = vsnprintf(buf, log->capacity, format, args);
		va_end(args);
		if (length == -1) {
			log->level = StbLogLevel::LOG_ERROR;
			const char *err = "Logging fail";
			buf = ensure_buffer(log, strlen(err) + 1);
			strcpy(buf, err);
		}
		// publish event
		log->publish.store(seq + 1);
	}

	uint64_t CLogger::_claim(uint64_t count) 
	{
		uint64_t request_seq = m_seq_claim.fetch_add(count);
		if (request_seq < m_min_seq)
			return request_seq;
		uint64_t min_seq = ULLONG_MAX, seq = 0;
		for (CLogHandler *handler : m_handler_list) {
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

	char * CLogger::ensure_buffer(LogEvent * log, size_t size)
	{
		if (log->capacity < size) {
			if (log->capacity > log_event_fixed_buffer_size) {
				delete[] log->buffer;
			}
			if (size < 256 && (size & (size - 1)) != 0) {
				size = get_next_power2(size);
			}
			log->buffer = new char[size];
			log->capacity = size;
		}
		return log->capacity > log_event_fixed_buffer_size ? (char*)log->buffer : log->fixed_buffer;
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
		, m_formatter(nullptr)
		, m_closed(false)
	{
		ASSERT_ALIGNMENT(this, CACHELINE_SIZE);
		ASSERT_ALIGNMENT(&m_seq, CACHELINE_SIZE);
		m_seq.set(0);
		m_formatter = std::make_unique<CTimeFormatter>();
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
		while (!m_closed) {
			log = m_logger->get_event(seq);
			pub = log->publish.load();
			if (pub > seq) {
				if (log->level == StbLogLevel::LOG_CODE_CLOSE) {
					// process system event
					m_closed = true;
					on_close();
				}
				else { // process user event
					bool b = true;
					for (auto filter : m_filters) {
						if (!filter(log)) {
							b = false;
							break;
						}
					}
					if (b)
						process_event(log);
				}
				m_seq.store(pub);
				seq += 1;
				assert(pub == seq);
				continue;
			}
			break;
		}
	}

	// --------------------------------
	// CLogTimeFormatter implementation
	// --------------------------------

	const char* CTimeFormatter::format_time(LogEventTime t)
	{
		time_t timestamp = std::chrono::system_clock::to_time_t(t);
		tm datetime;
		localtime_s(&datetime, &timestamp);
		if (strftime(m_buf, MAX_LENGTH, "%T", &datetime) == 0) {
			m_buf[MAX_LENGTH - 1] = 0;
		}
		return m_buf;
	}

	const char* CMsTimeFormatter::format_time(LogEventTime t) 
	{
		time_t timestamp = std::chrono::system_clock::to_time_t(t);
		tm datetime;
		localtime_s(&datetime, &timestamp);
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
		localtime_s(&datetime, &timestamp);
		if (strftime(m_buf, MAX_LENGTH, "%F %T", &datetime) == 0) {
			m_buf[MAX_LENGTH - 1] = 0;
		}
		return m_buf;
	}

	// --------------------------------
	// Standard logger implementation
	// --------------------------------

	void CLogStdout::process_event(const LogEvent * log)
	{
		if (m_formatter) {
			const char *stime = m_formatter->format_time(log->time);
			printf("[%s] ", stime);
		}
		if (log->channel[0] != 0) {
			printf("[%s] ", log->channel);
		}
		const char *message = LOG_EVENT_BUFFER(log);
		printf("%s\n", message);
	}

	// --------------------------------
	// File system implementation
	// --------------------------------
	
	void CLogFileSystem::normpath(std::string & path)
	{
		std::replace(path.begin(), path.end(), reversed_seperator, seperator);
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
		return stat(path.c_str(), &path_st) == 0 && path_st.st_mode & _S_IFDIR;
	}

	bool CLogFileSystem::isfile(const std::string &path)
	{
		struct stat path_st;
		return stat(path.c_str(), &path_st) == 0 && path_st.st_mode & _S_IFREG;
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

	void CLogFile::process_event(const LogEvent *log)
	{
		if (m_formatter) {
			const char *stime = m_formatter->format_time(log->time);
			m_cur_size += fprintf(m_hfile, "[%s] ", stime);
		}
		if (log->channel[0] != 0) {
			m_cur_size += fprintf(m_hfile, "[%s] ", log->channel);
		}
		const char *message = LOG_EVENT_BUFFER(log);
		m_cur_size += fprintf(m_hfile, "%s\n", message);
		fflush(m_hfile);
		if (m_cur_size >= m_rotate_size) {
			rotate();
		}
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

	void CLogDebugWindow::process_event(const LogEvent * log)
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
