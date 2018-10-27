
#ifndef HTTPS_FAKESERVER_H
#define HTTPS_FAKESERVER_H

#include "fakeSocket.h"
#include "maskFlags.h"
#include "opsRegister.h"
#include "Analyzer_log.h"

#define CONNECT_STAT_MSK	0x0000F00F
#define FLAG_CONEC_OK			0x00000001
#define FLAG_BUDDY_OK			0x00000002
#define FLAG_ENQUE_OK			0x00000004
#define FLAG_RES_TRANS_OK		0x00000008
#define FLAG_REQ_TRANS_OK		0x00001000

#define FLAG_BUDDY_CONEC_OK	0x00002000	

#define FLAG_CT_MSK	0x000000F0
#define FLAG_CT_CLI	0x00000010
#define FLAG_CT_SER	0x00000020
#define FLAG_CT_FREE	0x00000040

#define FLAG_FRAM_STATUS_MSK	0x00000F00
#define FLAG_FIRST_FRAM_OK		0x00000100
#define FLAG_SECOND_FRAM_OK	0x00000200



#ifndef INTERNAL_ERR_SHOW
#define INTERNAL_ERR_SHOW

#define ERR_EPOLL_CREATE			0
#define ERR_EPOLL_WAIT				2
#define ERR_EPOLL_ENQUEUE			4

#define ERR_EPOLL_MALLOC_LOOPEVENT	1
#define ERR_EPOLL_MALLOC_PUNIT		3
#define ERR_EPOLL_MALLOC_PUNIT_S	5

#define ERR_EPOLL_SET_FAKESOCKET	6
#define	ERR_EPOLL_RECV				8
#define ERR_EPOLL_GET_FAKESOCKET	7
#define ERR_EPOLL_GET_OPS	9
#define ERR_INTERIM	10
#define ERR_EPOLL_MAX	11
#define EPOLL_ERR_SHOW(i)	\
	do{switch(i){\
	case 0:	LOG_ERROR("CREATE EPOLL FD FAIL ERRNO:%d\n",errno);break;\
	case 1:	LOG_ERROR("MALLOC EPOLL LOOPEVENT FAIL ERRNO:%d\n",errno);break;\
	case 2:	LOG_ERROR("EPOLL WAIT FAIL ERRNO:%d\n",errno);break;\
	case 3:	LOG_ERROR("MALLOC PROXYUNIT FAIL ERRNO:%d\n",errno);break;\
	case 4:	LOG_ERROR("ENQUEUE EPOLL FD FAIL ERRNO:%d\n",errno);break;\
	case 5:	LOG_ERROR("MALLOC THE SECOND PROXYUNIT FAIL ERRNO:%d\n",errno);break;\
	case 6:	LOG_ERROR("GET SET_FAKESOCKET FAIL ERRNO:%d\n",errno);break;\
	case 7:	LOG_ERROR("GET GET_FAEKSOCKET FAIL ERRNO:%d\n",errno);break;\
	case 8:	LOG_ERROR("EPOLL RECV FAIL ERRNO:%d\n",errno);break;\
	case 9:	LOG_ERROR("EPOLL GET OPS FAIL:%d\n");break;\
	case 10: LOG_ERROR("wangyi\n");break;\
	default:	break;\
	}\
	}while(0)

#endif

 




#include<sys/epoll.h>
struct ReplaceStat{
	char* sub;
	int subLen;
	int state;
	int offset;
	struct SubstrState* next;
};

struct ProxyUnit{
	int fd;
	int fd_type;
	int tryTimes;
	FakeSocket* ffd;
	int sitMask;
	int status;
	int cflags;
	int flags;
	int contentLen;
	int contentSend;
	
	void* tmp;//will be removed;
	struct DataOperation* ops;
	char* data; //[4096];
	char* next;
	char* first;
	char* second;
#define PU_BUF_MAX_LEN 8182	
	int nextLen;
	int firstLen;
	int secondLen;
	int firstSend;
	int secondSend;
	struct ProxyUnit* buddy;
	int headLen;
#define PROXY_DEBUG
#ifdef PROXY_DEBUG
	int reqs;
	int rec;
#endif
};

#define SET_PROXYUNIT_CFD(x,f) do{(x)->fd=f;(x)->flags|=FLAG_CONEC_OK|FLAG_CT_CLI;}while(0)
#define SET_PROXYUNIT_SFD(x,f) do{(x)->fd=f,(x)->flags|=FLAG_CONEC_OK|FLAG_CT_SER;}while(0)


#define SET_SER_TRANS_FLAG(x)	do{																		\
										if((x)->flags&FLAG_CT_SER &&										\
											(x)->status&(TRANS_ENCOD_COMM|TRANS_ENCOD_ECOMM) &&	\
											(x)->status&CONTENT_LEN_SET &&								\
											(x)->contentSend==(x)->contentLen)						\
											(x)->flags|=FLAG_RES_TRANS_OK;\
										}while(0)

#define SET_CLI_TRANS_FLAG(x) do{																		\
											if((x)->flags&FLAG_CT_CLI &&									\
												(x)->contentSend==(x)->contentLen) 						\
												(x)->flags|=FLAG_REQ_TRANS_OK;							\
										}while(0)

#define IS_CLIENT_WITHOUTBUDDY(x) (x->flags&FLAG_CT_CLI && !(x->flags&FLAG_BUDDY_OK))
#define PROXYUNIT_LEN(x) ((x)->firstLen+(x)->secondLen)
#define SET_PROXYUNIT_BUDDY(x,y) do{(x)->buddy=(y);(y)->buddy=(x);(x)->flags|=FLAG_BUDDY_OK;\
									(y)->flags|=FLAG_BUDDY_OK;}while(0)

#define SET_PROXYUNIT_BUDDY_CONNECT_OK(x) do{x->flags|=FLAG_BUDDY_CONEC_OK;\
														if(x->buddy) x->buddy->flags|=FLAG_BUDDY_CONEC_OK;\
														}while(0)

#define PU_HEAD_FRAM_READY(x)	do{(x)->flags|=FLAG_FIRST_FRAM_OK;(x)->secondSend=(x)->secondLen;\
											(x)->firstSend=(x)->firstLen;\
											}while(0)									
#define PU_FIRST_FRAM_READY(x)	do{(x)->flags|=FLAG_FIRST_FRAM_OK;\
											(x)->firstSend=(x)->firstLen;\
											(x)->contentSend+=(x)->firstSend;}while(0)
#define PU_SECOND_FRAM_READY(x) do{(x)->flags|=FLAG_SECOND_FRAM_OK;\
											(x)->secondSend=(x)->secondLen;\
											(x)->contentSend+=(x)->secondSend;}while(0)
#define IS_FIRST_FRAM_READY(x) ((x)->flags&FLAG_FIRST_FRAM_OK)
#define IS_SECOND_FRAM_READY(x) ((x)->flags&FLAG_SECOND_FRAM_OK)

#define	IS_BYTE_STREAM_FRAM(x)	((x)->status&(CONT_T_BYTE_STREAM)) 


#define PROXYUNIT_RESET_DATA(x,l,m) resetProxyunitData(x,l,m)
#define PROXYUNIT_RESET(x) resetProxyunit(x)
#define PROXYUNIT_PROCESS_DATA(x)	do{processData((x));}while(0)

int resetProxyunitData(struct ProxyUnit* pu,int len,int m);
int resetProxyunit(struct ProxyUnit* pu);
int freeProxyUnit(struct ProxyUnit* pu);
struct ProxyUnit* mallocProxyUnit(int flg);
int recvProxyData(struct ProxyUnit* pu);
int sendProxyData(struct ProxyUnit* pu);
int splitHead(struct ProxyUnit* pu);
int processData(struct ProxyUnit* pu);
int initPubHeadOperations();
int registerDataOperation(int domainFlag,struct DataOperation* dopt);
struct ProxyUnit* mallocProxyUnit2(void* data,int flg);
int freeProxyUnit2(struct ProxyUnit* pu);
#endif
