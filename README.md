# stb_log
Single file async logging library for C++, inspired by [nothings/stb](https://github.com/nothings/stb).

## Feature
1. Multi-threading async logging.
2. *printf* style logging method.
3. Single header file library. Rely on C++14 standard library only.
4. Customized log filter and timestamp formatter.
5. Multiple worker threads can work on log messages simultaneously. For example, different severity messages can be handled by different worker threads, and redirect to different files.
6. Logging method is wrapped by macro which can be stripped according severity level at compile time.
7. Simple fast, low latency.

## Platform
- [x] Windows
- [x] MacOS
- [ ] Linux

## Usage
```C++
// include the implementation in one C++ module
#define STB_LOG_IMPLEMENT
#include "stb_log.h"

// define global severity level
#define LOG_SEVERITY_LEVEL 10
// then include the header anywhere that need it
#include "stb_log.h"

int main(int args, char *argv[])
{
	// start a logger that write to std out
	start_logger();

	// start a logger that write to file "log/test.log"
	start_file_logger("log/test.log");

	// or manually setup a logger
	CLogFile *err = new CLogFile("log/error.log");
	// filter that only accept Error messages
	err->set_filter([](const LogData* log) -> bool {
		return log->level >= LOG_ERROR;
	});
	// start collecting messages
	start_handler_thread(err);

	// now we can write log message at any threads
	// all started handlers will do the I/O jobs
	// the log_xxx macros will be stripped according LOG_SEVERITY_LEVEL

	int i = 255;
	float f = 3.1415926f;
	const char *c = "const chars";
	std::string s = "std::string";

	log_write(LOG_INFO, "TEST", "current log sevirity level is [%d]", log_severity_level);
	log_debug("debug message: %d, %f, '%s', '%s'", i, f, c, s);
	log_info("info message: %d, %f, '%s', '%s'", i, f, c, s);
	log_warning("warning message: %d, %f, '%s', '%s'", i, f, c, s);
	log_error("error message: %d, %f, '%s', '%s'", i, f, c, s);
	log_critical("critical message: %d, %f, '%s', '%s'", i, f, c, s);

	// finnally close the logger
	close_logger();
}
```

## Notice
1. stb_log use a fixed size queue to pass message to backend. When the queue is full, writer will get blocked. So you should adjust the LOG_QUEUE_SIZE to fit your application. 
2. Values that passed to the logger should be **copyable**. *std::string* can be passed directly and print as *%s*. *char\** must be available until it's processed. Note that string literals will be stored in read-only segments of memory. It's valid for the entire duration of the program.
3. Overload *to_printable* function to convert custom data to *printf* format.

## Benchmark

| Logger | Writer | Total |
|--------|--------|-------|
|stb_log| 3682 | 76755 |
|NanoLog| 4596 | 187610 |

Notes:
1. Writing 20K messages on a 6 cores MacBook.
2. Single producer thread which wirte logs, single worker thread which do I/O jobs.
3. **stb_log** LOG_QUEUE_SIZE is set to 20K to prevent producer from blocking.
4. **Writer** time (in microseconds) is the time that cost by log writing method in writer thread.
5. **Total** time (in microseconds) is the time that the benchmark procedure cost. Mostly cost by I/O.
