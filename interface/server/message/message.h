#ifndef __MESSAGE_SERVER_H__
#define __MESSAGE_SERVER_H__

#include "grpc_gen/message.grpc.pb.h"

class CMessageServer final : public message::MessageTran::Service
{
public:
    //virtual ::grpc::Status QueryInfo(::grpc::ServerContext* context, const ::message::in* request, ::message::out* response);
    virtual ::grpc::Status QueryInfo(::grpc::ServerContext* context, const ::message::in* request, ::message::out* response);
    CMessageServer();
    ~CMessageServer();
};


#endif