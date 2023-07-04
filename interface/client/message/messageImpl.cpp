#include "client/message/messageImpl.h"
#include "client/channel.h"

CMessageClient::CMessageClient(CGRPCChannel * channels)
{
    m_channels = channels;
}

CMessageClient::~CMessageClient()
{
}

bool CMessageClient::queryInfo(const std::string ip,const std::string port,std::string inMsg,std::string& outMsg)
{
    //获取通道
    std::shared_ptr<grpc::ChannelInterface> channel;
    if(!m_channels->GetChannel(ip+":"+port,channel))
    {
        std::cout << ip.c_str() << ":" << port.c_str() << "get channel fail!" << std::endl;
    }
    grpc::ClientContext contex;
    message::in in;
    message::out out;
    in.set_message(inMsg);
    grpc::Status status = message::MessageTran::NewStub(channel)->QueryInfo(&contex,in,&out);
    if(status.ok())
    {
        outMsg = out.result();
        return true;
    }
    else
    {
        return false;
    }
}