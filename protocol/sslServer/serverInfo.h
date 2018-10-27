#ifndef GET_SERVER_IP_H
#define GET_SERVER_IP_H 
#ifndef SOCK_MODE_T
#define SOCK_MODE_T
#define FAKE_SOCK_COM 1
#define FAKE_SOCK_SSL 2
#define FAKE_SOCK_SET 3
#endif

#ifndef SERVER_INFO_SIZE
#define SERVER_INFO_SIZE 100
#endif

#ifndef SERVER_INFO_STR
#define SERVER_INFO_STR
struct ServerInfoStr{
	int type;
	unsigned int ip;
	unsigned short port;
	char* domain;
	unsigned int msk;
};
typedef struct ServerInfoStr ServerInfo;
#endif

#ifdef __cplusplus
extern "C"{
#endif

unsigned int getSIp(int sock);
int getServerInfo(int sock,ServerInfo* sif);
int initServerInfo(int* array);
int getServerInfoB(char* data,int len,ServerInfo* sif);
#ifdef __cplusplus
}
#endif



#endif


