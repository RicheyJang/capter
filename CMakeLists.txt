cmake_minimum_required(VERSION 3.21)
project(capter)

set(CMAKE_CXX_STANDARD 11)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_EXE_LINKER_FLAGS "-static")

#include(FindPCAP.cmake)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

add_executable(capter main.cpp
        device.cpp
        device.h
        worker.cpp
        worker.h)
#set_target_properties(capter PROPERTIES LINK_SEARCH_START_STATIC 1)
#set_target_properties(capter PROPERTIES LINK_SEARCH_END_STATIC 1)
target_include_directories(capter PRIVATE include)
target_link_libraries(capter PRIVATE -static
    libpcap.a
    Threads::Threads
    spdlog::spdlog
    $<$<BOOL:${MINGW}>:ws2_32>
)