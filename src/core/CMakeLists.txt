CMAKE_MINIMUM_REQUIRED(VERSION 2.9)
MESSAGE(STATUS "CMake version: ${CMAKE_VERSION}")

PROJECT(sgeextproto)

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build Type ${CMAKE_BUILD_TYPE}")

SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-fPIC -fvisibility=hidden")

SET(SRC
    compressor.c
    decoder.c
    rax.c
    encoder.c
    parser.c
    protocol.c

)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${SRC})
