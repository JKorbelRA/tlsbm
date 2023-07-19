# set project name
project(crazywolf LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

# OPTIONS

option(CW_ENV_DEBUG_ENABLE "Enables debugging features, DISABLE for performance." OFF)


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

# INCLUDES

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include)

# LIBRARIES

add_subdirectory(wolfssl)

add_executable(${PROJECT_NAME}-wolfssl-client ${CLIENT_SRC} ${COMMON_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-client tlslib-wolfssl)

add_executable(${PROJECT_NAME}-wolfssl-server ${SERVER_SRC} ${COMMON_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-server tlslib-wolfssl)

## # ------------------------------------------------------------------------------
## 
## add_subdirectory(mbedtls)
## 
## add_executable(${PROJECT_NAME}-mbedtls-client ${CLIENT_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-mbedtls-client tlslib-mbedtls)
## 
## add_executable(${PROJECT_NAME}-mbedtls-server ${SERVER_SRC} ${COMMON_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-mbedtls-server tlslib-mbedtls)
## 
## # ------------------------------------------------------------------------------
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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/crazywolf/Environment.h.in
               ${CMAKE_BINARY_DIR}/include/crazywolf/Environment.h)
