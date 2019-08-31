include (ExternalProject)

set(libuv_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/libuv/src/libuv/include)
set(libuv_URL https://github.com/libuv/libuv)
set(libuv_TAG v1.31.0)
set(libuv_BUILD ${CMAKE_CURRENT_BINARY_DIR}/libuv/src/libuv-build)

set(LIBUV_LIBRARIES
    ${libuv_BUILD}/libuv_a.a
)

# Forward Android CMake cross compile args to ExternalProject.
set(ANDROID_CMAKE_ARGS
  -DANDROID_ABI=${ANDROID_ABI}
  -DANDROID_PLATFORM=${ANDROID_PLATFORM}
  -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
  -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  -DANDROID_NDK=${ANDROID_NDK}
  -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
  -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
  -DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
  -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
# For iOS
  -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
  -DCMAKE_OSX_SYSROOT=${CMAKE_OSX_SYSROOT}
  -G${CMAKE_GENERATOR})

ExternalProject_Add(libuv
    PREFIX libuv
    GIT_REPOSITORY ${libuv_URL}
    GIT_TAG ${libuv_TAG}
    DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
    #--Update/Patch step----------
    BUILD_ALWAYS 0
#     UPDATE_DISCONNECTED 1
#     UPDATE_COMMAND ${CMAKE_COMMAND} -E copy
#                    ${CMAKE_CURRENT_LIST_DIR}/../cmake/libuv/CMakeLists.txt
#                    ${CMAKE_CURRENT_BINARY_DIR}/libuv/src/libuv/CMakeLists.txt
    # BUILD_IN_SOURCE 1
#     BUILD_BYPRODUCTS ${libuv_STATIC_LIBRARIES}
    INSTALL_COMMAND ""
#     CMAKE_ARGS ${ANDROID_CMAKE_ARGS}
    CMAKE_CACHE_ARGS
        -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
#         -DCMAKE_BUILD_TYPE:STRING=Release
        -DCMAKE_VERBOSE_MAKEFILE:BOOL=OFF
        -Dlibuv_buildtests:BOOL=OFF
)
