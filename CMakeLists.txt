cmake_minimum_required(VERSION 3.0)
project(cryptoSQLite)

# include
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/)

# add sqlite amalgamation subdirectory
add_subdirectory(sqlite)

# glob files
file(GLOB_RECURSE CS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*)
file(GLOB_RECURSE CS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*)

# flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra")

# set up library target
add_library(cryptosqlite ${CS_INCLUDES} ${CS_SOURCES})