#include "client/channel.h"

#include <stdio.h>
#include <unistd.h>

#include <grpcpp/security/credentials.h>

#define FLAGS_target_override "localhost"
#define OLD 1
#define SSL 1
CGRPCChannel::CGRPCChannel(const time_t &timeout)
{
    this->n_timeout = timeout;
    std::string app_path = getcwd(NULL ,0);;
    m_root_ca_pem = app_path + "/certs/" + "ca.pem";

    m_client_cert_pem = app_path + "/certs/" + "server_encipher.pem";
    m_client_key_pem = app_path + "/certs/" + "server_encipher.key";

    m_client_sign_cert_pem = app_path + "/certs/" + "client.pem";
    m_client_sign_key_pem = app_path + "/certs/" + "client.key";

    
    m_root_ca_pem = ReadFile(m_root_ca_pem);
	m_client_cert_pem = ReadFile(m_client_cert_pem);
	m_client_key_pem = ReadFile(m_client_key_pem);

    m_client_sign_cert_pem = ReadFile(m_client_sign_cert_pem);
	m_client_sign_key_pem = ReadFile(m_client_sign_key_pem);
}

CGRPCChannel::~CGRPCChannel()
{
}

bool CGRPCChannel::GetChannel(const std::string &conn,std::shared_ptr<grpc::ChannelInterface> & channel)
{
    gpr_timespec tm_out{n_timeout,0,GPR_TIMESPAN};
    std::lock_guard<std::mutex> lock(m_mutex);
   
    if(m_channels.find(conn) == m_channels.end())
    {
#if OLD
#if SSL
        ::grpc::ChannelArguments channelArgs;
        auto key_materials =
            std::make_shared<grpc_impl::experimental::TlsKeyMaterialsConfig>();
        key_materials->set_pem_root_certs(m_root_ca_pem);
        //客户端只用sign的证书即可
        //key_materials->add_pem_key_cert_pair({ m_client_key_pem, m_client_cert_pem});
        key_materials->add_pem_key_cert_pair({ m_client_sign_key_pem, m_client_sign_cert_pem});
        auto tls_opts = grpc_impl::experimental::TlsCredentialsOptions(
            GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY,
            GRPC_TLS_SERVER_VERIFICATION, key_materials, nullptr, nullptr);
        auto creds = grpc::experimental::TlsCredentials(tls_opts);
    
        channelArgs.SetSslTargetNameOverride(FLAGS_target_override);
        m_channels[conn] = ::grpc::CreateCustomChannel(conn, creds, channelArgs);
		//ssl end
#else
    m_channels[conn] = ::grpc::CreateCustomChannel(conn, ::grpc::InsecureChannelCredentials(),channelArgs);
#endif
#else
#if SSL
        ::grpc::ChannelArguments channelArgs;
        ::grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = m_root_ca_pem;
        ssl_opts.pem_cert_chain = m_client_sign_cert_pem;
        ssl_opts.pem_private_key = m_client_sign_key_pem;
        std::shared_ptr<grpc::ChannelCredentials> creds =  grpc::SslCredentials(ssl_opts);
        channelArgs.SetSslTargetNameOverride(FLAGS_target_override);
        m_channels[conn] = ::grpc::CreateCustomChannel(conn, creds, channelArgs);
		//ssl end
#else
		m_channels[conn] = ::grpc::CreateCustomChannel(conn, ::grpc::InsecureChannelCredentials(),channelArgs);
#endif
#endif
    }
   channel = m_channels[conn];
   if(channel->WaitForConnected(tm_out))
   {
        return true;
   }
   else
   {
        return false;
   }

}

std::string CGRPCChannel::ReadFile(const std::string &path) 
{
	std::string data;
	FILE *f = fopen(path.c_str(), "r");
	if (f == nullptr)
		std::cout << "read "<<path.c_str() << " fail!" << std::endl;
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
