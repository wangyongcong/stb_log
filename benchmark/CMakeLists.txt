cmake_minimum_required(VERSION 3.3)

project(stb_log_benchmark)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

add_definitions("/D_CRT_SECURE_NO_WARNINGS /wd4100 /wd4324")

set(nanolog
	nanolog/nanolog.hpp
	nanolog/nanolog.cpp
)
source_group(nanolog FILES ${nanolog})

set(stb_log
	../stb_log.h
)
source_group(stb_log FILES ${stb_log})

set(source
	benchmark.h
	benchmark.cpp
	bm_stb_log.cpp
	bm_nanolog.cpp
)

add_executable(
	benchmark
	${source}
	${stb_log}
	${nanolog}
)
target_include_directories(benchmark PRIVATE ..)
