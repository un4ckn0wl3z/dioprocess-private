cmake_minimum_required(VERSION 3.10)
project(network_test)

set(CMAKE_CXX_STANDARD 17)

# TCP tools
add_executable(tcp_server tcp_server.cpp)
add_executable(tcp_client tcp_client.cpp)

target_link_libraries(tcp_server ws2_32)
target_link_libraries(tcp_client ws2_32)

# UDP tools (better for testing packet resend - stateless protocol)
add_executable(udp_server udp_server.cpp)
add_executable(udp_client udp_client.cpp)

target_link_libraries(udp_server ws2_32)
target_link_libraries(udp_client ws2_32)

# Multi-client TCP server (for testing TCP resend)
add_executable(tcp_server_multi tcp_server_multi.cpp)
target_link_libraries(tcp_server_multi ws2_32)
