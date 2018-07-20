# stb_log
Single file async logging library for C++, inspired by [nothings/stb](https://github.com/nothings/stb).

Feature:
1. Implemented with C++11 standard library. No 3rd dependence.
2. Lock-free async logging. Writing and handling log message in any threads.
3. Use high performance [LMAX Disruptor](https://github.com/LMAX-Exchange/disruptor) model.

More todo:
1. Log message filtering.
2. Compile time filtering with macro interface.
3. Message formatting.
