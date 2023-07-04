#include <iostream>
#include "client/client.h"
#include "client/message/messageImpl.h"

int main(int argc,char ** argv)
{
    std::string ip;
    std::string port;
    std::string message;
    // ./client -ip 127.0.0.1 -port 20000 -msg "hello,world!"
    if(argc != 7)
    {
        std::cout << "args error\n like:./client -ip 127.0.0.1 -port 20000 -msg hello,world!" << std::endl;
        return -1;
    }
    ip = argv[2];
    port = argv[4];
    message = argv[6];
    CGRPCClient * client = new CGRPCClient();
    if(!client)
    {
        std::cout << "client create error\n" << std::endl;
        return -1;
    }
    client->init();
    std::string outMsg;
    if(client->GetMessageClient().queryInfo(ip,port,message,outMsg))
    {
        std::cout << "call query interface success,recv from server message is:" << outMsg.c_str() << std::endl;
    }
}