#ifndef LZ_ACCOUNT_GET_H
#define LZ_ACCOUNT_GET_H

#ifdef __cplusplus
extern "C"{
#endif

int GetAccount(unsigned int ipCli,unsigned int ipSer,unsigned short portCli,unsigned short port,
			   short objId,char* mac,void* dat,unsigned int timeval);

#ifdef __cplusplus
}
#endif

#endif
