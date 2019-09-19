cmake_minimum_required(VERSION 3.1)

add_library(organic_dump_network SHARED Fd.cpp)
target_link_libraries(organic_dump_network gflags::gflags)
target_link_libraries(organic_dump_network glog::glog)
target_link_libraries(organic_dump_network ssl crypto)
