cmake_minimum_required(VERSION 3.1)

project (mdnscpp)

option(BUILD_TESTS "Build test" OFF)
option(BUILD_UTILS "Build utils" OFF)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX14_EXTENSION_COMPILE_OPTION -std=c++14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")

set (MDNS_LIBRARY_NAME "mdnscpp")
set (MDNS_LIBRARY_TYPE SHARED)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/")

find_package (libuv REQUIRED)
if (NOT LIBUV_FOUND)
    include (libuv)
    include_directories( ${libuv_INCLUDE_DIR} )
endif()

set (MDNS_LIBRARY_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/Logger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/DnsPacket.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/Client.cpp
)

add_library(
    # Specifies the name of the library.
    ${MDNS_LIBRARY_NAME}
    # Sets the library as a shared or static library.
    ${MDNS_LIBRARY_TYPE}
    ${MDNS_LIBRARY_SOURCES}
)

target_include_directories(
    ${MDNS_LIBRARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include/)

add_dependencies (
    ${MDNS_LIBRARY_NAME}
    libuv
)

target_include_directories (
    ${MDNS_LIBRARY_NAME} 
    PRIVATE ${LIBUV_INCLUDE_DIRS}
)

target_link_libraries (
    ${MDNS_LIBRARY_NAME}
    PRIVATE ${LIBUV_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

if (BUILD_TESTS)
    add_subdirectory ("${CMAKE_CURRENT_LIST_DIR}/tests" tests)
endif()

if (BUILD_UTILS)
    add_subdirectory ("${CMAKE_CURRENT_LIST_DIR}/utils" utils)
endif()

