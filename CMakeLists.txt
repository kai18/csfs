cmake_minimum_required(VERSION 3.6)
project(csfs)

include(FindPkgConfig)
pkg_check_modules(FUSE REQUIRED "fuse")
pkG_check_modules(OPENSSL REQUIRED "openssl")
include_directories(${FUSE_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIRS})

set(CMAKE_CXX_FLAGS "${OPENSSL_CFLAGS} ${FUSE_CFLAGS} ${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    config.h.in
    crypto.c
    crypto.h
    csfs.c
    csfs.h
    fuse.h
    log.c
    log.h
    mkcert.c
    params.h
    test.c)

add_executable(csfs ${SOURCE_FILES})

target_link_libraries(${CMAKE_PROJECT_NAME}
        ${FUSE_LDFLAGS} ${FUSE_LIBRARIES} ${FUSE_CLFAGS}
        ${OPENSSL_LDFLAGS} ${OPENSSL_LIBRARIES} ${OPENSSL_CFLAGS})