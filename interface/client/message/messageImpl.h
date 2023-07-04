#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include "grpc_gen/message.grpc.pb.h"
#include <grpcpp/grpcpp.h>

class CGRPCChannel;

class CMessageClient final
{
private:
    CGRPCChannel * m_channels;
public:
    CMessageClient(CGRPCChannel * channels);
    ~CMessageClient();
    bool queryInfo(const std::string ip,const std::string port,std::string inMsg,std::string &outMsg);
};

#endif