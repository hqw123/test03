
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "fakeSocket.h"
#include "Analyzer_log.h"


// add something


FakeSocket* getFakeSocket(int type,unsigned int ip,unsigned short port){
	//printf("GET INTO GET_FAKE_SOCKET\n");
	FakeSocket* fs=NULL;
	fs=(FakeSocket*)malloc(sizeof(FakeSocket));
	if(fs==NULL){
		LOG_ERROR("malloc FakeSocket fail \n");
		return NULL;
	}
	memset(fs,0,sizeof(FakeSocket));	
	fs->type=type;
	if(type==FAKE_SOCK_SSL){
		//printf("GET SSL SOCKET %04x \n",port);
		SSLclient* sslclit=getSSLclientB(ip,port);
		if(sslclit==NULL){
			LOG_ERROR("get sslclient fail ip:%08x port:%d\n",ip,port);
			free(fs);
			return NULL;
		}		
		fs->sslClit=sslclit;
		fs->sockfd=sslclit->sockfd;
	}
	else if(type==FAKE_SOCK_COM){
		//printf("GET COMM SOCKET\n");
		int tfd=getCommSocket(ip,port);
		if(tfd<0){
			LOG_ERROR("get comm sock fail ip:%08x port:%d\n",ip,port);
			free(fs);
			return NULL;
		}
		fs->sockfd=tfd;
	}
	else if(type==FAKE_SOCK_SET){
		fs->sockfd=ip;
	}
	//printf("GET OUTOF GET_FAKE_SOCKET\n");
	return fs;
}

// add something
int recvData(FakeSocket* fs,char* buf,int size,int flag,int t){
//printf("get into fackSocke->recvData\n");
//printf("type: %d\n",fs->type);
	int rlen=0;
	if(fs->type==FAKE_SOCK_SSL){
		rlen=SSL_read(fs->sslClit->ssl,buf,size);
		if(rlen<0)
			if(errno==104)
				LOG_INFO("SSL CONNECTION RESET .......\n");
			else
				LOG_INFO("SSL_READ FAIL:%d READ %d ERRNO:%d\n",fs->sockfd,rlen,errno);
	}
	else{
	//	printf("IN FAKE SOCKET: FD: %d\n",fs->sockfd);
		rlen=recv(fs->sockfd,buf,size,flag);
		if(rlen<0)
			if(errno==104)
				LOG_INFO("COM CONNECTION RESET ............\n");
			else
				LOG_ERROR("COM RECEIVE FAIL:%d RECEIVE %d ERRNO: %d\n",fs->sockfd,rlen,errno);
	}
	return rlen;
}


//add something
int sendData(FakeSocket* fs,char* buf,int size,int flag){//if(buf != NULL && !memcmp(buf,"GET /",5)){printf("\nbuf=%s\n",buf);}
	int slen=0;
	if(fs->type==FAKE_SOCK_SSL){
		slen=SSL_write(fs->sslClit->ssl,buf,size);
	}
	else{
		slen=send(fs->sockfd,buf,size,flag);	
	}
	//printf("FAKESOCKET %d SEND %d\n",fs->sockfd,slen);
	return slen;
}


int closeFakeSocket(FakeSocket* fs){
	if(!fs)
		return 0;
	if(fs->type==FAKE_SOCK_SSL){
		closeSSLclient(fs->sslClit);
		free(fs);
	}
	else{
		if(close(fs->sockfd))
			LOG_ERROR("close fake socket com %d:\n",errno);
		free(fs);
	}
	return 1;
}

int getFakeSocketType(FakeSocket* fs){
	return fs->type;
}



FakeSocket* getFakeSocketB(int type,int fd,int flg){
	//printf("GET INTO GET_FAKE_SOCKET B\n");
	FakeSocket* fs=NULL;
	fs=(FakeSocket*)malloc(sizeof(FakeSocket));
	if(fs==NULL){
		LOG_ERROR("malloc FakeSocket fail \n");
		return NULL;
	}
	memset(fs,0,sizeof(FakeSocket));	
	fs->type=type;

	if(type==FAKE_SOCK_SSL){
#define SSL_TEST_F
#ifdef SSL_TEST_F
		LOG_INFO("GET SSL SOCKET %04x \n",fd);
#endif
		SSLclient* sslclit=getSSLclientB2(fd,flg);
		if(sslclit==NULL){
			LOG_INFO("get sslclient fail fd:%d\n",fd);
			free(fs);
			return NULL;
		}		
		fs->sslClit=sslclit;
		fs->sockfd=fd;
#ifdef SSL_TEST_F
		LOG_INFO("GET SSL SOCKET OK %04x \n",fd);
#endif
	}

	else if(type==FAKE_SOCK_COM){
		fs->sockfd=fd;
	}
	else if(type==FAKE_SOCK_SET){
		fs->sockfd=fd;
	}
	//printf("GET OUTOF GET_FAKE_SOCKET\n");
	return fs;
}



