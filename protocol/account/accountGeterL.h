#ifndef LZ_ACCOUNT_GET_H
#define LZ_ACCOUNT_GET_H

#ifdef __cplusplus
extern "C"{
#endif

#ifdef VPDNLZ
int GetAccount(unsigned int ipCli,unsigned int ipSer,unsigned short portCli,unsigned short port,
			   short objId,char* mac,const char* hostUrl,void* dat,unsigned int timeval,char *pppoe);
#else
int GetAccount(unsigned int ipCli,unsigned int ipSer,unsigned short portCli,unsigned short port,
			   short objId,char* mac,const char* hostUrl,void* dat,unsigned int timeval);
#endif

#ifdef __cplusplus
}
#endif

#endif
