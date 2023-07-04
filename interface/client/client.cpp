#include "client/client.h"
#include "client/channel.h"
#include "client/message/messageImpl.h"

CGRPCClient::CGRPCClient()
{

}

CGRPCClient::~CGRPCClient()
{
    if(m_channel)
    {
        delete m_channel;
        m_channel = nullptr;
    }

    if (m_messageClient)
    {
        delete m_messageClient;
    }
    
}

bool CGRPCClient::init()
{
    m_channel = new CGRPCChannel(10);
    if(m_channel == nullptr)
    {
        return false;
    }
    m_messageClient = new CMessageClient(m_channel);
    return true;
}

CMessageClient& CGRPCClient::GetMessageClient()
{
    return *m_messageClient;
}