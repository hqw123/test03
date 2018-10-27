#ifndef FAKE_SOCKET_H
#define FAKE_SOCKET_H

#ifndef SOCK_MODE_T
#define SOCK_MODE_T
#define FAKE_SOCK_COM 1
#define FAKE_SOCK_SSL 2
#define FAKE_SOCK_SET 3
#endif

#include "fakeClient.h"

struct FakeSocketStr{
	int type;
	int sockfd;
	SSLclient* sslClit;
};

typedef struct FakeSocketStr FakeSocket;

#ifdef __cplusplus
extern "C"{
#endif
int getFakeSocketType(FakeSocket* fs);
FakeSocket* getFakeSocket(int type,unsigned int ip,unsigned short port);
int recvData(FakeSocket* fs,char* buf,int size,int flag,int t);
int sendData(FakeSocket* fs,char* buf,int size,int flag);
int closeFakeSocket(FakeSocket* fs);
FakeSocket* getFakeSocketB(int type,int sockfd,int flg);
#ifdef __cplusplus
}
#endif
 
#endif


