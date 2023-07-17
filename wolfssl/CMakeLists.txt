# set project name
project(tlslib-wolfssl LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

set(WOLFSSL_SOURCE "" CACHE PATH "Path to wolfSSL sources")
option(WOLFSSL_USER_IO "" OFF)
option(WOLFSSL_DEBUG "" ON)

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(TLSLIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/Impl.c
)
