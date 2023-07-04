project(server)

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/interface
    ${PROJECT_SOURCE_DIR}/interface/server
    ${PROJECT_SOURCE_DIR}/interface/client
    ${PROJECT_SOURCE_DIR}/interface/grpc_gen
    #grpc header
    ${PROJECT_SOURCE_DIR}/third_party/grpc/include
)

set (SRC_LIST
    #grpc list
    ${PROJECT_SOURCE_DIR}/interface/grpc_gen/message.grpc.pb.cc
    ${PROJECT_SOURCE_DIR}/interface/grpc_gen/message.pb.cc
    ${PROJECT_SOURCE_DIR}/interface/server/server.cpp
    ${PROJECT_SOURCE_DIR}/interface/server/message/message.cpp
    ${PROJECT_SOURCE_DIR}/src/server.cpp
    
)

add_executable(${PROJECT_NAME} ${SRC_LIST})

#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")

#grpc库
target_link_libraries(${PROJECT_NAME}
    grpc++
    grpc
    address_sorting
    re2
    upb
    cares
    z
    absl_bad_optional_access
    gpr
    absl_str_format_internal
    absl_time
    absl_time_zone
    absl_civil_time
    absl_strings
    absl_strings_internal
    absl_throw_delegate
    absl_int128
    absl_base
    absl_spinlock_wait
    absl_raw_logging_internal
    absl_log_severity
    absl_dynamic_annotations
    ssl
    crypto
    absl_base
    absl_spinlock_wait
    absl_raw_logging_internal
    absl_log_severity
    absl_dynamic_annotations
    ssl
    crypto
    grpc++_reflection
    protobuf
    # gcc libraries
    c
    pthread

)