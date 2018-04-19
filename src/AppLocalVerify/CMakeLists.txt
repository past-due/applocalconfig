cmake_minimum_required(VERSION 3.5)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

if (NOT MSVC)
	message( WARNING "This tool is designed to work with MSVC, and may not work with other toolchains." )
endif()

set(CMAKE_CXX_STANDARD 11)

# applocalverify.exe
add_executable(applocalverify "AppLocalVerify.cpp" "codesignextract.cpp" "stdafx.cpp" "applocalverify.rc" "${CMAKE_CURRENT_BINARY_DIR}/../runtime_libs.h")
target_compile_definitions(applocalverify PRIVATE "UNICODE" "_UNICODE")
set_target_properties(applocalverify PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalverify PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalverify PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalverify PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
	set_property(TARGET applocalverify APPEND_STRING PROPERTY LINK_FLAGS " /MANIFEST:NO")
endif()

install(TARGETS applocalverify COMPONENT "Core" DESTINATION ".")
