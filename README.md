# stb_log
Single file async logging library for C++, inspired by [nothings/stb](https://github.com/nothings/stb).

## Feature

1. Single header file library.
2. Rely on C++11 standard library only.
3. Lock-free async logging. Write and handl log message in any threads.
4. Use high performance [LMAX Disruptor](https://github.com/LMAX-Exchange/disruptor) pattern.

## More to do

- [x] Log Message formatting.
- [x] Log message filtering.
- [x] Logging to standard output.
- [ ] Logging to file.
- [ ] Log file rotation.
- [ ] Preprocess macro with compile time filtering.

## Usage
```C++
// include the implementation in one C++ module
#define STB_LOG_IMPLEMENT
#include "stb_log.h"

// then include the header anywhere that need it
#include "stb_log.h"
```
