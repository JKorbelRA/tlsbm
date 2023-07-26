# set project name
project(tlslib-mbedtls LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(MBEDTLS_SOURCE "C:/share/gitlab/mbedtls-3.4.0" CACHE PATH "Path to mbedTLS sources")

# require C99 standard
set(C_STANDARD 99)

if (CW_ENV_DEBUG_ENABLE)
add_definitions(-DMBEDTLS_DEBUG_C)
endif()

add_definitions(-DMBEDTLS_CONFIG_FILE="mbed_settings.h")
#add_definitions(-DMBEDTLS_CHACHA20_C)
#add_definitions(-DMBEDTLS_CHACHAPOLY_C)

option(ENABLE_PROGRAMS "" OFF)
option(ENABLE_TESTING "" OFF)

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${MBEDTLS_SOURCE}/include ${CMAKE_CURRENT_SOURCE_DIR})

set(TLSLIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/TlsLib.c
)

add_subdirectory("${MBEDTLS_SOURCE}" mbedtls)

add_library(${PROJECT_NAME} STATIC ${TLSLIB_SRC})
target_link_libraries(${PROJECT_NAME}  crazywolf-common mbedtls crazywolf-common)
