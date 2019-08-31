cmake_minimum_required(VERSION 3.1)

# TEST Compilation

set(utils_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/nhlookup.cpp
)

add_executable (
    nhlookup
    ${utils_sources}
)

target_include_directories(
    nhlookup PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include/)

find_package (Threads)

target_link_libraries (
    nhlookup
#     LINK_PUBLIC
    mdnscpp
    ${LIBUV_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)



