rm -rf ../grpc_gen/*.cc
rm -rf ../grpc_gen/*.h
GRPC_PATH=../../third_party/grpc
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${GRPC_PATH}/lib:${GRPC_PATH}/lib64

${GRPC_PATH}/bin/protoc -I./ --cpp_out=../grpc_gen ./message.proto
${GRPC_PATH}/bin/protoc -I./ --grpc_out=../grpc_gen --plugin=protoc-gen-grpc=${GRPC_PATH}/bin/grpc_cpp_plugin ./message.proto
