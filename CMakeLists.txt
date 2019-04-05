cmake_minimum_required(VERSION 3.9)
project(elf)

set(CMAKE_CXX_STANDARD 11)


set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fno-omit-frame-pointer ")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -fomit-frame-pointer -ffast-math-optimizations ")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")


set(SOURCE_FILES crossld.h crossld.cc elf_utils.h elf_utils.cc)


add_library(crossld SHARED
        ${SOURCE_FILES})
set_target_properties(crossld PROPERTIES PUBLIC_HEADER crossld.h)
target_include_directories(crossld PRIVATE .)

add_executable(test test.cc)
target_link_libraries(test crossld)