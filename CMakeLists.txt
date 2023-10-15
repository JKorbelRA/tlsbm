# 
# MIT License
# 
# Copyright (c) 2023 Rockwell Automation, Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# set project name
project(tlsbm LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

# OPTIONS

option(BUILD_SHARED_LIBS "" OFF)
option(TLSBM_ENV_DEBUG_ENABLE "Enables debugging features, DISABLE for performance." OFF)


# SOURCES

list(APPEND CLIENT_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Client.c
)
list(APPEND SERVER_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Server.c
)

list(APPEND COMMON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/Common.c)

if ("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    add_definitions(-Wno-error=cpp)
    list(APPEND COMMON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/platform/Linux.c)
elseif ("${CMAKE_SYSTEM_NAME}" MATCHES "Windows")
    list(APPEND COMMON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/platform/Windows.c)
endif()

add_library(${PROJECT_NAME}-common ${COMMON_SRC})

# INCLUDES

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include)

# LIBRARIES

add_subdirectory(wolfssl)

add_executable(${PROJECT_NAME}-wolfssl-client ${CLIENT_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-client ${PROJECT_NAME}-common tlslib-wolfssl ${PROJECT_NAME}-common)

add_executable(${PROJECT_NAME}-wolfssl-server ${SERVER_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-server ${PROJECT_NAME}-common tlslib-wolfssl ${PROJECT_NAME}-common)

# ------------------------------------------------------------------------------

add_subdirectory(mbedtls)

add_executable(${PROJECT_NAME}-mbedtls-client ${CLIENT_SRC} ${COMMON_SRC})

target_link_libraries(${PROJECT_NAME}-mbedtls-client tlslib-mbedtls)

add_executable(${PROJECT_NAME}-mbedtls-server ${SERVER_SRC} ${COMMON_SRC})

target_link_libraries(${PROJECT_NAME}-mbedtls-server tlslib-mbedtls)

# ------------------------------------------------------------------------------
## 
## 
## add_subdirectory(cyclonessl)
## 
## add_executable(${PROJECT_NAME}-cyclonessl-client ${CLIENT_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-cyclonessl-client tlslib-cyclonessl)
## 
## add_executable(${PROJECT_NAME}-cyclonessl-server ${SERVER_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-cyclonessl-server tlslib-cyclonessl)
## 
## 
## # ------------------------------------------------------------------------------
## 
## 
## add_subdirectory(sharkssl)
## 
## add_executable(${PROJECT_NAME}-sharkssl-client ${CLIENT_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-sharkssl-client tlslib-sharkssl)
## 
## add_executable(${PROJECT_NAME}-sharkssl-server ${SERVER_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-sharkssl-server tlslib-sharkssl)
## 
## # ------------------------------------------------------------------------------


# CONFIG FILE GENERATION
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/tlsbm/Environment.h.in
               ${CMAKE_BINARY_DIR}/include/tlsbm/Environment.h)
