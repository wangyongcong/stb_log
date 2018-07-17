PROJECT(stb_log)

SET(source
	stb_log.h
	test_log.cpp
)

ADD_EXECUTABLE(
	test_log
	${source}
)
