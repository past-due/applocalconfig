cmake_minimum_required(VERSION 3.5...3.31)
project(applocalconfig)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

add_subdirectory(src)
