PROJECT(stb_log)

add_definitions(-DSTB_LOG_IMPLEMENTATION -DUSE_NAMESPACE)

SET(source
	stb_log.h
	test_log.cpp
)

ADD_EXECUTABLE(
	test_log
	${source}
)
