
#include <openssl/ssl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "fakeClient.h"
#include "Analyzer_log.h"

SSLclient* getSSLclient(SSLverify* vrfy,unsigned int ip,short port){
	SSLclient* sslclit=NULL;
	sslclit=(SSLclient*)malloc(sizeof(SSLclient));
	memset(sslclit,0,sizeof(SSLclient));
	SSL_library_init();
	sslclit->ctx=SSL_CTX_new(SSLv23_client_method());

	SSL_CTX_set_verify(sslclit->ctx,vrfy->verifymod,NULL);
	SSL_CTX_load_verify_locations(sslclit->ctx,vrfy->CAF,vrfy->CAP);
	// return value should greater than 0
	SSL_CTX_use_certificate_file(sslclit->ctx,vrfy->certifFile,vrfy->certifMod);
	// return value should greater than 0
	SSL_CTX_use_PrivateKey_file(sslclit->ctx,vrfy->keyFile,vrfy->keyMod);
	SSL_CTX_check_private_key(sslclit->ctx);

	sslclit->ssl=SSL_new(sslclit->ctx);
	int sockfd=-1;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in sa;
	sa.sin_family=AF_INET;
	sa.sin_addr.s_addr=ip;
	sa.sin_port=port;
	sslclit->sockfd=sockfd;
	int conret=connect(sockfd,(struct sockaddr*)&sa,sizeof(sa));
	SSL_set_fd(sslclit->ssl,sockfd);
	SSL_connect(sslclit->ssl);
	X509* serverCert;
	serverCert=SSL_get_peer_certificate(sslclit->ssl);
	char* sname=X509_NAME_oneline(X509_get_subject_name(serverCert),0,0);
	char* cname=X509_NAME_oneline(X509_get_issuer_name(serverCert),0,0);
	X509_free(serverCert);

	//check here///////////////
	//SSL_get_verify_result(sslclit->ssl);
	///////////////////////////
//	printf("ca:%s\n server:%s\n",cname,sname);
	OPENSSL_free(sname);
	OPENSSL_free(cname);
	return sslclit;
}

SSLclient* getSSLclientB(unsigned int ip ,short port){
	SSLclient* sslclit=NULL;
	sslclit=(SSLclient*)malloc(sizeof(SSLclient));
	if(!sslclit)
		return sslclit;
	memset(sslclit,0,sizeof(SSLclient));
	SSL_library_init();
	sslclit->ctx=SSL_CTX_new(SSLv23_client_method());
	sslclit->ssl=SSL_new(sslclit->ctx);
	int sockfd=-1;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in sa;
	sa.sin_family=AF_INET;
	sa.sin_addr.s_addr=ip;
	sa.sin_port=port;
	sslclit->sockfd=sockfd;
//	printf("IN SSL CLIENT 3\n");
	int conret=connect(sockfd,(struct sockaddr*)&sa,sizeof(sa));
	if(conret<0){
		LOG_ERROR("ssl connect to %08x on port %04x fail,return %d errno %d\n",ip,port,conret,errno);
		closeSSLclient(sslclit);
		return NULL;
	}
//	printf("IN SSL CLIENT 4\n");
	SSL_set_fd(sslclit->ssl,sockfd);
	SSL_connect(sslclit->ssl);
	
	X509* serverCert;
	serverCert=SSL_get_peer_certificate(sslclit->ssl);
	char* sname=X509_NAME_oneline(X509_get_subject_name(serverCert),0,0);
	char* cname=X509_NAME_oneline(X509_get_issuer_name(serverCert),0,0);
	X509_free(serverCert);
	//check here///////////////
	//SSL_get_verify_result(sslclit->ssl);
	///////////////////////////
	//printf("ca:%s\n sever:%s\n",cname,sname);
	OPENSSL_free(sname);
	OPENSSL_free(cname);
	
	return sslclit;
}

int closeSSLclient(SSLclient* client){
		SSL_shutdown(client->ssl);
		if(close(client->sockfd))
			LOG_ERROR("close ssl client fail: %d\n",errno);
		SSL_free(client->ssl);
		SSL_CTX_free(client->ctx);
		free(client);
	return 1;
}

int getCommSocket(unsigned int ip,short port){
	int sockfd=0;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	if(sockfd<0){
		LOG_ERROR("get socket fail\n");
		return -1;
	}
	struct sockaddr_in addr;
	memset(&addr,0,sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=ip;
	addr.sin_port=port;
	
	if(connect(sockfd,(struct sockaddr*)&addr,sizeof(addr))<0){
		//printf("connet to server fail\n");
		LOG_ERROR("common connect to %08x on port %04x fail, errno %d\n",ip,port,errno);
		return -1;
	}
	return sockfd;
}



SSLclient* getSSLclientB2(int fd ,int flg){
	SSLclient* sslclit=NULL;
	sslclit=(SSLclient*)malloc(sizeof(SSLclient));
	if(!sslclit)
		return sslclit;
	memset(sslclit,0,sizeof(SSLclient));
	SSL_library_init();
	sslclit->ctx=SSL_CTX_new(SSLv23_client_method());
	sslclit->ssl=SSL_new(sslclit->ctx);
	sslclit->sockfd=fd;
	SSL_set_fd(sslclit->ssl,fd);
#ifdef SSL_TEST_F
						LOG_INFO("WILL SHAKE HANDS sock:%d\n",fd);
#endif
	int scrt=SSL_connect(sslclit->ssl);
#ifdef SSL_TEST_F
						LOG_INFO("SHAKE HANDS OVER sock:%d\n");
#endif
	if(scrt!=1){
		LOG_ERROR("ssl_connect fail: %d\n",scrt);
		LOG_ERROR("ssl err: %d\n",SSL_get_error(sslclit->ssl,scrt));
		closeSSLclientB(sslclit);
		return NULL;
	}
	X509* serverCert;
	serverCert=SSL_get_peer_certificate(sslclit->ssl);
	char* sname=X509_NAME_oneline(X509_get_subject_name(serverCert),0,0);
	char* cname=X509_NAME_oneline(X509_get_issuer_name(serverCert),0,0);
	X509_free(serverCert);
	//check here///////////////
	//SSL_get_verify_result(sslclit->ssl);
	///////////////////////////
	//printf("ca:%s\n sever:%s\n",cname,sname);
	OPENSSL_free(sname);
	OPENSSL_free(cname);
	
	return sslclit;
}

int closeSSLclientB(SSLclient* client){
		SSL_shutdown(client->ssl);
		SSL_free(client->ssl);
		SSL_CTX_free(client->ctx);
		free(client);
	return 1;
}










