# set project name
project(tlslib-wolfssl LANGUAGES C)

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

# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

# require C99 standard
set(C_STANDARD 99)

set(WOLFSSL_SOURCE "C:/share/gitlab/wolfssl-5.6.3-stable" CACHE PATH "Path to wolfSSL sources")
option(WOLFSSL_USER_IO "" OFF)
option(WOLFSSL_DEBUG "" OFF)
set(WOLFSSL_DTLS "yes" CACHE STRING "")
set(BUILD_DTLS_COMMON "yes" CACHE STRING "")
set(BUILD_SP "yes" CACHE STRING "")
set(BUILD_SP_C "yes" CACHE STRING "")
set(WOLFSSL_ECCSHAMIR "no" CACHE STRING "")
set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "")
set(WOLFSSL_EXAMPLES "no" CACHE STRING "")

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${WOLFSSL_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR})

set(TLSLIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/TlsLib.c
)

add_subdirectory("${WOLFSSL_SOURCE}" wolfssl)

add_library(${PROJECT_NAME} STATIC ${TLSLIB_SRC})
target_link_libraries(${PROJECT_NAME}  tlsbm-common wolfssl tlsbm-common)
