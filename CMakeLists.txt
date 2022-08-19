# set project name
project(crazywolf LANGUAGES C)


# cmake minimum version
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)


# require C99 standard
set(C_STANDARD 99)

set(WOLFSSL_SOURCE "" CACHE PATH "Path to wolfSSL sources")


if (EXISTS "${WOLFSSL_SOURCE}")

    list(APPEND CMAKE_MODULE_PATH "${WOLFSSL_SOURCE}/../CMake/Modules")
    include(PathSetter)

    set( WOLFSSL_CMAKE_DEFINITIONS ON )
    add_subdirectory("${WOLFSSL_SOURCE}" wolfssl)

    #GenerateWolfSSLEnvironment()
else()
    message(SEND_ERROR "WOLFSSL_SOURCE not set to a proper source location")
endif()

include_directories("${WOLFSSL_SOURCE}/3rdparty/wolfssl" ${CMAKE_BINARY_DIR})

# user-created
add_executable(${PROJECT_NAME}-client
                "Client.c"
                "Common.c"
               )

target_link_libraries(${PROJECT_NAME}-client wolfSSL)

add_executable(${PROJECT_NAME}-server
                "Server.c"
                "Common.c"
               )

target_link_libraries(${PROJECT_NAME}-server wolfSSL)
