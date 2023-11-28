cmake_minimum_required(VERSION 3.21)
project(capter)

set(CMAKE_CXX_STANDARD 11)
set(THREADS_PREFER_PTHREAD_FLAG ON)

include(FindPCAP.cmake)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

add_executable(capter main.cpp
        device.cpp
        device.h
        worker.cpp
        worker.h)
target_include_directories(capter PRIVATE include)
target_link_libraries(capter PRIVATE Threads::Threads)
target_link_libraries(capter PRIVATE spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)
target_link_libraries(capter PRIVATE ${PCAP_LIBRARY})