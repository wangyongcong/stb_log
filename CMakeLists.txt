cmake_minimum_required(VERSION 3.3)

PROJECT(stb_log)

set(CMAKE_CXX_STANDARD 14)
set(NAMESPACE_NAME "" CACHE STRING "Wrap log apis with namespace")

if(NOT NAMESPACE_NAME STREQUAL "")
	message(STATUS "use namespace ${NAMESPACE_NAME}")
	add_definitions("-DUSE_NAMESPACE -DSTB_LOG_NAMESPACE=\"${NAMESPACE_NAME}\"")
endif()

add_definitions("-DLOG_SEVERITY_LEVEL=0")

#message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

if(MSVC)
	add_definitions("/Wall /WX /D_CRT_SECURE_NO_WARNINGS /W4 /wd4100 /wd4324")
else()
	add_definitions("-Wno-braced-scalar-init")
endif()

SET(source
	stb_log.h
	test_log.cpp
)

ADD_EXECUTABLE(
	test_log
	${source}
)

add_subdirectory(benchmark)
