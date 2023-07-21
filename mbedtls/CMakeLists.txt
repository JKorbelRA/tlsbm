# set project name
project(tlslib-mbedtls LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

if (CW_ENV_DEBUG_ENABLE)
add_definitions(-DMBEDTLS_DEBUG_C)
endif()

set(MBEDTLS_SOURCE "C:/share/gitlab/mbedtls-3.4.0" CACHE PATH "Path to mbedtls sources")

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${MBEDTLS_SOURCE}/include ${CMAKE_CURRENT_SOURCE_DIR})

set(TLSLIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/TlsLib.c
)

add_subdirectory("${MBEDTLS_SOURCE}" mbedtls)

add_library(${PROJECT_NAME} STATIC ${TLSLIB_SRC})
target_link_libraries(${PROJECT_NAME}  crazywolf-common mbedtls crazywolf-common)
