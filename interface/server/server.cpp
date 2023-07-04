#include "server/server.h"
#include "grpc_gen/message.grpc.pb.h"
#include "grpcpp/grpcpp.h"
#include "server/message/message.h"

#include <stdio.h>
#include <unistd.h>
#define OLD 1 // 是否为低版本grpc
#define SSL 1

CGRPCServer::CGRPCServer(const std::string &port)
{
    m_messageServer = new CMessageServer();
    m_port = port;
    std::string app_path = getcwd(NULL ,0);
    std::cout << "app_path:"<< app_path.c_str() << std::endl;
	m_root_ca_pem = app_path +"/certs" + "/ca.pem";
	m_server_cert_pem = app_path +"/certs" + "/server_encipher.pem";
	m_server_key_pem = app_path + "/certs" + "/server_encipher.key";
	m_server_sign_cert_pem = app_path +"/certs" + "/server_sign.pem";
	m_server_sign_key_pem = app_path + "/certs" + "/server_sign.key";
	m_root_ca_pem = ReadFile(m_root_ca_pem);
	std::cout << "m_root_ca_pem:\n"<< m_root_ca_pem.c_str() << std::endl;
	
	m_server_cert_pem = ReadFile(m_server_cert_pem);
	m_server_key_pem = ReadFile(m_server_key_pem);

	m_server_sign_cert_pem = ReadFile(m_server_sign_cert_pem);
	m_server_sign_key_pem = ReadFile(m_server_sign_key_pem);
}

CGRPCServer::~CGRPCServer()
{
    if (m_messageServer)
    {
        delete m_messageServer;
        m_messageServer = nullptr;
    }
    
}

bool CGRPCServer::RunServer()
{
    ::grpc::ServerBuilder builder;
#if OLD
#if SSL
	//SSL
	grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
	ssl_opts.pem_root_certs = m_root_ca_pem;
	ssl_opts.pem_key_cert_pairs.push_back(grpc::SslServerCredentialsOptions::PemKeyCertPair{ m_server_sign_key_pem, m_server_sign_cert_pem });
	ssl_opts.pem_key_cert_pairs.push_back(grpc::SslServerCredentialsOptions::PemKeyCertPair{ m_server_key_pem, m_server_cert_pem });
	//ssl_opts.force_client_auth = true;
	auto creds = grpc::SslServerCredentials(ssl_opts);
	builder.AddListeningPort("[::]:"+m_port, creds);
#else
    builder.AddListeningPort("[::]:"+m_port,grpc::InsecureServerCredentials());
#endif
#else
#if SSL
	 grpc::SslServerCredentialsOptions ssl_opts;
	ssl_opts.pem_root_certs = m_root_ca_pem;
	auto sign = grpc::SslServerCredentialsOptions::PemKeyCertPair{m_server_sign_key_pem, m_server_sign_cert_pem};
	auto encrypt = grpc::SslServerCredentialsOptions::PemKeyCertPair{{ m_server_key_pem, m_server_cert_pem}};
	ssl_opts.pem_key_cert_pairs.push_back(encrypt);
	ssl_opts.pem_key_cert_pairs.push_back(sign);
	auto creds = grpc::SslServerCredentials(ssl_opts);
	builder.AddListeningPort("[::]:"+m_port, creds);
#else
	builder.AddListeningPort("[::]:"+m_port,grpc::InsecureServerCredentials());
#endif
#endif
    builder.RegisterService(m_messageServer);
    std::unique_ptr <::grpc::Server> server(builder.BuildAndStart());
    std::cout<< "grpc server running ,listening port ["<< m_port.c_str() << "]" <<std::endl;
    server->Wait();
}

std::string CGRPCServer::ReadFile(const std::string &path)
{
	std::string data;
	FILE *f = fopen(path.c_str(), "r");
	if (f == nullptr)
		std::cout << "read " << path.c_str() << " fail!" << std::endl;
	char buf[1024];
	for (;;) {
		size_t n = fread(buf, 1, sizeof(buf), f);
		if (n <= 0)
			break;
		data.append(buf, n);
	}
	if (ferror(f)) {
		std::cout << "read " << path.c_str() << std::endl;
	}
	fclose(f);
	return data;
}