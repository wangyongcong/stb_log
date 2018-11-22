# stb_log
Single file async logging library for C++, inspired by [nothings/stb](https://github.com/nothings/stb).

## Feature
0. *printf* style logging.
1. Single header file library.
2. Rely on C++11 standard library only.
3. Lock-free async logging. Write log messages in any threads.
4. Logging I/O could take place in backend thread which reduce frondend latency.
5. Use high performance [LMAX Disruptor](https://github.com/LMAX-Exchange/disruptor) pattern.
6. Strip logging call according log severity level at compile time.
7. Super fast fondend log writing. No un-necessary memory copy.

## Platform
- [x] Windows
- [x] MacOS
- [ ] Linux

## TODO
- [x] Log message filtering.
- [x] Log time stamp formatting.
- [x] Logging to standard output.
- [x] Logging to file.
- [x] Logging to Visual Studio debugger output.
- [x] Log file rotation.
- [x] Helper interface and macro.
- [x] Benchmark.
- [x] Reduce client side latence.

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
	// start a logger that write to standard output
	start_logger();
	// start a logger that write to file
	// you can specify write mode, rotation, etc. plz follow the document.
	start_file_logger("logs/test.log");
	// start a logger that write to debug console (Visual Studio)
	start_debug_logger();

	// after initialization, you can write log message in any thread
	// backend I/O take place in seperate thread

	// write log message in printf style
	log_write(LOG_INFO, "channel_name", "current log sevirity level is [%d]", LOG_SEVERITY_LEVEL);

	// write logs with different severity level
	// these macros may be stripped according LOG_SEVERITY_LEVEL definition
	log_debug("a debug message");
	log_info("an infomation message");
	log_warning("a warning message");
	log_error("an error message");
	log_critical("a critical message");

	// finally close logger
	close_logger();
}
```

## Benchmark
Currently client side log writing, which just send message to backend, is faster than nano log. When sending 20000 message, stb_log cost 2700 microseconds, Nanolog cost 4700 microseconds. 

If stb_log's ring queue is full, writing threads get blocked. Under this situation, stb_log is much slower than Nanolog. Nanolog will allocate new ring buffer when it's full and won't block writing threads.

Nanolog's backend has faster I/O then stb_log. It's strange and need futher inspection.