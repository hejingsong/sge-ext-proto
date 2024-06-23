CMAKE_MINIMUM_REQUIRED(VERSION 2.9)
MESSAGE(STATUS "CMake version: ${CMAKE_VERSION}")

PROJECT(sgeextproto)

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build Type ${CMAKE_BUILD_TYPE}")

SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-fPIC -fvisibility=hidden")

INCLUDE_DIRECTORIES(../utils/src)

SET(SRC
    ../utils/src/array.c
    ../utils/src/rax.c
    compressor.c
    decoder.c
    encoder.c
    parser.c
    protocol.c
    result.c
)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${SRC})
