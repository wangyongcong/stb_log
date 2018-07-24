cmake_minimum_required(VERSION 3.3)

PROJECT(stb_log)

set(NAMESPACE_NAME "" CACHE STRING "Wrap log apis with namespace")

if(NOT NAMESPACE_NAME STREQUAL "")
	message(STATUS "use namespace ${NAMESPACE_NAME}")
	add_definitions("-DUSE_NAMESPACE -DNAMESPACE_NAME=\"${NAMESPACE_NAME}\"")
endif()

if(MSVC)
	add_definitions("/Wall /WX /D_CRT_SECURE_NO_WARNINGS /W4 /wd4100 /wd4324")
endif()

SET(source
	stb_log.h
	test_log.cpp
)

ADD_EXECUTABLE(
	test_log
	${source}
)
