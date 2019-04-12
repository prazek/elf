cmake_minimum_required(VERSION 3.7)
project(elf)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
            "Choose the type of build, options are: Debug Release
            RelWithDebInfo MinSizeRel."
            FORCE)

    message(STATUS "No build type selected, default to Debug")
    set(CMAKE_BUILD_TYPE "Debug")
endif()

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fno-omit-frame-pointer ")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -fomit-frame-pointer -ffast-math")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing -Wall -Wextra")


set(SOURCE_FILES crossld.h crossld.cc elf_utils.h elf_utils.cc trampolines.h trampolines.cc mmap_utils.h)


add_library(crossld SHARED
        ${SOURCE_FILES})
set_target_properties(crossld PROPERTIES PUBLIC_HEADER crossld.h elf_utils.h trampolines.h)
target_include_directories(crossld PRIVATE .)

