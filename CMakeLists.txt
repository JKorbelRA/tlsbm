# set project name
project(crazywolf LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

# OPTIONS

option(CW_ENV_DEBUG_ENABLE "Enables debugging features, DISABLE for performance." OFF)


# SOURCES

set(CLIENT_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Common.c
)
set(SERVER_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Common.c
)

# INCLUDES

include_directories(${CMAKE_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include)

# LIBRARIES

add_subdirectory(wolfssl)

add_executable(${PROJECT_NAME}-wolfssl-client ${CLIENT_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-client tlslib-wolfssl)

add_executable(${PROJECT_NAME}-wolfssl-server ${SERVER_SRC})

target_link_libraries(${PROJECT_NAME}-wolfssl-server tlslib-wolfssl)

## # ------------------------------------------------------------------------------
## 
## add_subdirectory(mbedtls)
## 
## add_executable(${PROJECT_NAME}-mbedtls-client ${CLIENT_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-mbedtls-client tlslib-mbedtls)
## 
## add_executable(${PROJECT_NAME}-mbedtls-server ${SERVER_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-mbedtls-server tlslib-mbedtls)
## 
## # ------------------------------------------------------------------------------
## 
## 
## add_subdirectory(cyclonessl)
## 
## add_executable(${PROJECT_NAME}-cyclonessl-client ${CLIENT_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-cyclonessl-client tlslib-cyclonessl)
## 
## add_executable(${PROJECT_NAME}-cyclonessl-server ${SERVER_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-cyclonessl-server tlslib-cyclonessl)
## 
## 
## # ------------------------------------------------------------------------------
## 
## 
## add_subdirectory(sharkssl)
## 
## add_executable(${PROJECT_NAME}-sharkssl-client ${CLIENT_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-sharkssl-client tlslib-sharkssl)
## 
## add_executable(${PROJECT_NAME}-sharkssl-server ${SERVER_SRC})
## 
## target_link_libraries(${PROJECT_NAME}-sharkssl-server tlslib-sharkssl)
## 
## # ------------------------------------------------------------------------------


# CONFIG FILE GENERATION
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/crazywolf/Environment.h.in ${CMAKE_BINARY_DIR}/include/crazywolf/Environment.h)
