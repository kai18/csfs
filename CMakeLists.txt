cmake_minimum_required(VERSION 3.4)
project(csfs)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

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