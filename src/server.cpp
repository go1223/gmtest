#include<iostream>
#include "server/server.h"

int main(int argc,char ** argv)
{
    CGRPCServer * server = new CGRPCServer("20000");
    if(!server)
    {
        std::cout << "create grpc server failed!" <<std::endl;
        return -1;
    }
    server->RunServer();
    return 0;
}