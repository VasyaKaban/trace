cmake_minimum_required(VERSION 3.5)

project(trace LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(
	trace_lib
	    src/ICMPEchoRequest.h
		src/ICMPResponse.h
		src/Host.h
		src/Host.cpp
		src/Socket.h
		src/Socket.cpp
		src/Sample.h
		src/Sample.cpp
		src/Trace.h
		src/Trace.cpp)

add_executable(
	${PROJECT_NAME}
	    src/main.cpp
		src/Config.h
		src/Config.cpp)

target_link_libraries(
	${PROJECT_NAME}
	    PRIVATE trace_lib)

add_executable(
	trace_lib_test
	    test/tests.cpp)

#target_compile_definitions(trace_lib_test PRIVATE "BOOST_TEST_DYN_LINK=1")

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

target_link_libraries(
	trace_lib_test
	    PRIVATE trace_lib
		PRIVATE ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

enable_testing()
add_test(test, trace_lib_test)
