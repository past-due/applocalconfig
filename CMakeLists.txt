cmake_minimum_required(VERSION 3.5)
project(applocalconfig)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

add_subdirectory(src)
