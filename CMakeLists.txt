cmake_minimum_required(VERSION 3.12)
PROJECT (grpc_test VERSION 1.0.0)

include(CheckIncludeFile)

SET (CMAKE_CXX_STANDARD 11)
SET (CMAKE_CXX_STANDARD_REQUIRED ON)
SET (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/deploy/bin)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${PROJECT_SOURCE_DIR}/deploy/bind)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-ddebug -d_debug)
else ()
    set (CMAKE_BUILD_TYPE "Release")
    add_definitions(-DNODEBUG)
endif()

message(status "current platform is:${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
message(status "Building ${PROJECT_NAME}.${PROJECT_VERSION} [${CMAKE_BUILD_TYPE}]")

LINK_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/third_party/grpc/lib
    ${PROJECT_SOURCE_DIR}/third_party/grpc/lib64
)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include(server)

include(client)