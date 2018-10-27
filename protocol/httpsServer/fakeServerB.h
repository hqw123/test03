#ifndef FAKE_SERVER_H
#define FAKE_SERVER_H

struct ReqProcessParaStr{
	int fd;
	int ip;
	short port;
};
typedef struct ReqProcessParaStr RPP;

#ifdef __cplusplus
extern "C" {
#endif

int startServer(int port,int max);
int processRequest(RPP* para);
int processResponse();

#ifdef __cplusplus
}
#endif

#endif



 
