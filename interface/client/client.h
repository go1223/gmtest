#ifndef __CLINET_H__
#define __CLIENT_H__

class CGRPCChannel;
class CMessageClient;

class CGRPCClient final
{
private:
    CGRPCChannel * m_channel;
    CMessageClient * m_messageClient;
public:
    CGRPCClient(/* args */);
    ~CGRPCClient();
    CMessageClient& GetMessageClient();
    bool init();
};

#endif