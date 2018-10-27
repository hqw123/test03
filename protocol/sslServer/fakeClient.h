#ifndef FAKE_CLIENT_H
#define FAKE_CLIENT_H

#include<openssl/ssl.h>

#ifndef SSL_CLIENT_STR
#define SSL_CLIENT_STR
struct SSLclientStr{
	SSL_CTX* ctx;
	SSL* ssl;
	int sockfd;
	int flag;
};
#endif

struct SSLverifyStr{
	int verifymod;
	char* CAF;
	char* CAP;
	int certifMod;
	char* certifFile;
	int keyMod;
	char* keyFile;
	
};


typedef struct SSLclientStr SSLclient;
typedef struct SSLverifyStr SSLverify;
#ifdef __cplusplus
extern "C"{
#endif

SSLclient* getSSLclient(struct SSLverifyStr* vrfyStr,unsigned int ip,short port);
SSLclient* getSSLclientB(unsigned int ip ,short port);
//int connectServer(SSLclient* client,unsigned int ip,int port); 
int closeSSLclient(SSLclient* client);

int getCommSocket(unsigned int ip,short port);
SSLclient* getSSLclientB2(int fd ,int flg);
int closeSSLclientB(SSLclient* client);
#ifdef __cplusplus
}
#endif



#endif





