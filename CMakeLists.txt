PROJECT(stb_log)

add_definitions(-DUSE_NAMESPACE)

if(MSVC)
	add_definitions("/Wall /WX /D_CRT_SECURE_NO_WARNINGS")
endif()

SET(source
	stb_log.h
	test_log.cpp
)

ADD_EXECUTABLE(
	test_log
	${source}
)
