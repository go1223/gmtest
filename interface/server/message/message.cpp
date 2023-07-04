#include "server/message/message.h"
#include "grpcpp/grpcpp.h"

CMessageServer::CMessageServer()
{

}

CMessageServer::~CMessageServer()
{

}

grpc::Status CMessageServer::QueryInfo(::grpc::ServerContext* context, const ::message::in* request, ::message::out* response)
{
    std::cout << "recv message from client ,content is " << request->message().c_str() << std::endl;
    auto now = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(now);
    std::string result = std::ctime(&end_time);
    result = result + "recv from client message.";
    response->set_result(result);
    grpc::Status status;
    return status;

}

