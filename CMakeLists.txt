cmake_minimum_required(VERSION 3.1)

add_library(organic_dump_network STATIC
  Fd.cpp
  NetworkUtilities.cpp
  TlsConnection.cpp
  TlsClient.cpp
  TlsClientFactory.cpp
  TlsServer.cpp
  TlsServerFactory.cpp
  TlsUtilities.cpp)

include_directories(
  ../../../external/boringssl/repo/include
  ../../../external/protobuf/repo/src
)

#set_property(TARGET organic_dump_network PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(organic_dump_network glog::glog)
target_link_libraries(organic_dump_network ssl crypto)

