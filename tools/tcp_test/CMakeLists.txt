cmake_minimum_required(VERSION 3.10)
project(tcp_test)

set(CMAKE_CXX_STANDARD 17)

# TCP Server
add_executable(tcp_server tcp_server.cpp)
target_link_libraries(tcp_server ws2_32)

# TCP Client
add_executable(tcp_client tcp_client.cpp)
target_link_libraries(tcp_client ws2_32)
