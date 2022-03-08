cmake_minimum_required(VERSION 3.21)
project(shell)

set(CMAKE_CXX_STANDARD 11)

add_executable(shell main.cpp PEParser.h PEParser.cpp)
add_executable(test test.cpp PEParser.h PEParser.cpp)