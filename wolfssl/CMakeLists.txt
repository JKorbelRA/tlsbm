# set project name
project(tlslib-wolfssl LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

add_definitions(-Wno-error=cpp)

# require C99 standard
set(C_STANDARD 99)

set(WOLFSSL_USER_SETTINGS "yes" CACHE STRING "")

set(WOLFSSL_SOURCE "C:/share/gitlab/wolfssl-5.6.3-stable" CACHE PATH "Path to wolfSSL sources")
option(WOLFSSL_USER_IO "" OFF)
option(WOLFSSL_DEBUG "" ON)

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${WOLFSSL_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR})

set(TLSLIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/TlsLib.c
)

add_subdirectory("${WOLFSSL_SOURCE}" wolfssl)

add_library(${PROJECT_NAME} STATIC ${TLSLIB_SRC})
target_link_libraries(${PROJECT_NAME} wolfssl)
