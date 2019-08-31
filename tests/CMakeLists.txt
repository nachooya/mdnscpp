cmake_minimum_required(VERSION 3.1)

# TEST Compilation

set(test_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/tests.cpp
)

add_executable (
    tests
    ${test_sources}
)

target_include_directories(
    tests PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include/)

find_package (Threads)

target_link_libraries (
    tests
#     LINK_PUBLIC
    mdnscpp
    ${CMAKE_THREAD_LIBS_INIT}
)



