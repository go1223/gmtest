#ifndef __SERVER_H__
#define __SERVER_H__

#include "grpc_gen/message.grpc.pb.h"

class CMessageServer;
class CGRPCServer final
{
private:
    CMessageServer * m_messageServer;
    std::string m_port;
    std::string m_root_ca_pem;
	std::string m_server_cert_pem;
	std::string m_server_key_pem;

    std::string m_server_sign_cert_pem;
	std::string m_server_sign_key_pem;
public:
    bool RunServer();
    CGRPCServer(const std::string &port);
    ~CGRPCServer();
    std::string ReadFile(const std::string &path);
};


#endif