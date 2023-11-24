cmake_minimum_required(VERSION 3.21)
project(capter)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)
find_package(spdlog REQUIRED)

add_executable(capter main.cpp)
target_include_directories(capter PRIVATE include)
target_link_libraries(capter PRIVATE spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)
target_link_libraries(capter PRIVATE ${PCAP_LIBRARY})