cmake_minimum_required(VERSION 3.5)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

if (NOT MSVC)
	message( WARNING "This tool is designed to work with MSVC's app-local CRT config, and may not work with other toolchains." )
endif()

set(CMAKE_CXX_STANDARD 11)
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories(".")

# Get a list of all of the required system libraries
# (ex. the VC runtime when linking dynamically via MSVC)
set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
set(CMAKE_INSTALL_DEBUG_LIBRARIES FALSE)
set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
include(InstallRequiredSystemLibraries)
# CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS should now contain the runtime files
# Output to a .h file
set(_runtime_libs_count 0)
if (CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
	list(LENGTH CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS _runtime_libs_count)
else()
	message( WARNING "CMake did not detect any required system runtime libraries. This probably isn't accurate." )
endif()
set(_runtimeListH "#pragma once\n\n#define RUNTIME_LIBS_COUNT ${_runtime_libs_count}\nstatic WCHAR runtimeLibs[][265] {")
set(_addedFirstLib FALSE)
foreach (lib ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS})
	get_filename_component(lib_name "${lib}" NAME)
	if(_addedFirstLib)
		set(_runtimeListH "${_runtimeListH},\n\tL\"${lib_name}\"")
	else()
		set(_runtimeListH "${_runtimeListH}\n\tL\"${lib_name}\"")
		set(_addedFirstLib TRUE)
	endif()
endforeach()
set(_runtimeListH "${_runtimeListH}\n};\n")
file(WRITE "${PROJECT_BINARY_DIR}//runtime_libs.h" "${_runtimeListH}")

#actually install the system runtime libs
install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
		DESTINATION "."
		COMPONENT "Core"
)
if (CMAKE_INSTALL_SYSTEM_RUNTIME_DIRECTORIES)
	message( STATUS "Also installing system runtime directories: ${CMAKE_INSTALL_SYSTEM_RUNTIME_DIRECTORIES}" )
	install(DIRECTORY ${CMAKE_INSTALL_SYSTEM_RUNTIME_DIRECTORIES}
			DESTINATION "."
			COMPONENT "Core"
	)
endif()

#################################################
# applocalverify

add_subdirectory(AppLocalVerify)

#################################################
# applocalconfig

if (MSVC)
	# Suppress all the standard libraries - the only ones needed are added later
	set(CMAKE_CXX_STANDARD_LIBRARIES "")
	set(CMAKE_C_STANDARD_LIBRARIES "")
endif()

set(SOURCE_FILES AppLocalConfig.cpp)

# applocalconfig.exe
add_executable(applocalconfig ${SOURCE_FILES} "${PROJECT_BINARY_DIR}//runtime_libs.h")
target_compile_definitions(applocalconfig PRIVATE "UNICODE" "_UNICODE")
set_target_properties(applocalconfig PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalconfig PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalconfig PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(applocalconfig PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
	# Do not link the CRT (or any default libs)
	set_target_properties(applocalconfig PROPERTIES LINK_FLAGS "/NODEFAULTLIB /ENTRY:main")
	# Do not use /GS (it requires the CRT)
	target_compile_options(applocalconfig PRIVATE "/GS-")
	# *Do* explicitly link to the required libs
	target_link_libraries(applocalconfig PRIVATE kernel32 user32 Shell32.lib Shlwapi.lib)
endif()

install(TARGETS applocalconfig COMPONENT "Core" DESTINATION ".")
