#ifndef __CHANNEL_H__
#define __CHANNEL_H__

#include<map>
#include<iostream>
#include<string>
#include<mutex>
#include "grpcpp/grpcpp.h"

class CGRPCChannel
{
private:
    //存放主机和通道对应关系
    std::map<const std::string,std::shared_ptr<grpc::ChannelInterface>> m_channels;
    std::mutex m_mutex;
    //通道超时时间
    unsigned int n_timeout;

    //证书
    std::string m_root_ca_pem;
    std::string m_client_cert_pem;
    std::string m_client_key_pem;

    std::string m_client_sign_cert_pem;
    std::string m_client_sign_key_pem;
public:
    CGRPCChannel(const time_t &timeout = 5);
    ~CGRPCChannel();
    bool GetChannel(const std::string &conn,std::shared_ptr<grpc::ChannelInterface> & channel);
    std::string ReadFile(const std::string &path);
};
#endif