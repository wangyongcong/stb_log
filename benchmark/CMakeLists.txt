message(STATUS "Configuring benchmark")

#message(STATUS ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})

set(nanolog
	nanolog/nanolog.hpp
	nanolog/nanolog.cpp
)
source_group(nanolog FILES ${nanolog})

set(source
	benchmark.h
	benchmark.cpp
	bm_stb_log.cpp
	bm_nanolog.cpp
	bm_alloc.cpp)

add_executable(
	benchmark
	${source}
	${nanolog}
)
target_include_directories(benchmark PRIVATE ..)
