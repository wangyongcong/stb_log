cmake_minimum_required(VERSION 3.3)

project(stb_log_benchmark)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

add_definitions("/D_CRT_SECURE_NO_WARNINGS /wd4100 /wd4324")

set(source
	../stb_log.h
	benchmark.cpp
)

add_executable(
	benchmark
	${source}
)
target_include_directories(benchmark PRIVATE ..)
