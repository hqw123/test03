
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <signal.h>

#include "proxyUnit.h"
#include "serverInfo.h"
#include "opsRegister.h"
#include "fakeSocket.h"
#include "siteTab.h"
#include "req_filter.h"
#include "Analyzer_log.h"

#define SELECT_TIME_OUT 20
#define HTTPS_MAX_CONN 200

#define SSL_TEST_F

int getServerSocket(int port,int max);
int run(int sfd);
static int setNONblock(int fd);
static int setBlock(int fd);
int startServer(unsigned short port,int max){
	initOps();
	if(signal(SIGPIPE,SIG_IGN)==SIG_ERR){
		LOG_ERROR("set signal fail...\n");
		exit(1);
	}
	int sfd=getServerSocket(port,max);
	if(sfd<0)
	{LOG_ERROR("SOMETHING HAPPEND .getServerSocket fail........\n");exit(1);}
	run(sfd);
}
	
int getServerSocket(int port,int max){
	struct sockaddr_in sa;
	int sfd=socket(AF_INET,SOCK_STREAM,0);
	if(sfd<0){
		LOG_ERROR("SOCKET FAIL ERRNO:%d\n",errno);
		return sfd;
	}	
	int reuse=1;
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
	sa.sin_family=AF_INET;
	sa.sin_port=htons(port);
	sa.sin_addr.s_addr=htonl(INADDR_ANY);
	int bid=bind(sfd,(struct sockaddr*)&sa,sizeof(sa));
	if(bid<0){
		LOG_ERROR("BIND FAIL ERRNO:%d\n",errno);
		close(sfd);
		return -1;
	}
	int lis=listen(sfd,max);
	if(lis<0){
		LOG_ERROR("LISTEN FAIL ERRNO:%d\n",errno);
		close(sfd);
		return -1;
	}
//	printf("LISTEN ON PORT %d\n",port);
	return sfd;
}	

int run(int sfd){
	int addrlen;
	struct sockaddr_in ca;
	int internalErrno=ERR_EPOLL_MAX; 
	int epollfd=epoll_create(HTTPS_MAX_CONN);
	if(epollfd==-1){
		LOG_ERROR("EPOLL CREATE FAIL: ERRNO %d\n",errno);
		exit(1);
	}
	
	int evtlen=sizeof(struct epoll_event)*HTTPS_MAX_CONN;
	struct epoll_event* loopevent=(struct epoll_event*)malloc(evtlen);
	if(!loopevent){
		LOG_ERROR("MALLOC LOOP EVENT FAIL :ERRNO %d\n",errno);
		exit(1);
	}
	
	struct epoll_event tmpEvt;
	tmpEvt.events=EPOLLIN;
	tmpEvt.data.fd=sfd;
	struct ProxyUnit* tUnit=NULL;
	struct ProxyUnit* tUnit2=NULL;
	int looprt=0;
	int epollrt=epoll_ctl(epollfd,EPOLL_CTL_ADD,sfd,&tmpEvt);
	while(1){
//		printf("epoll while...\n");
#ifdef SSL_TEST_F
						//printf("EPOLL WAIT.........\n");
#endif
		looprt=epoll_wait(epollfd,loopevent,HTTPS_MAX_CONN,-1);
		int i=0;
		if(looprt==-1){
			LOG_ERROR("EPOLLWAIT RETURN -1 ERRNO %d\n",errno);
			continue;
		}
 		//printf("epoll_wait : %d\n",looprt);
		while(i<looprt){
#ifdef SSL_TEST_F
//						printf("EPOLL LOOP %d of %d .........\n",i,looprt);
#endif
			if(loopevent[i].data.fd==sfd){//accpet new connection
				i++;
				socklen_t addrlen2=sizeof(ca);
				int nsf=accept(sfd,(struct sockaddr*)&ca,&addrlen2);
				if(nsf==-1){LOG_ERROR("ACCEPT FAIL :%d\n",errno);continue;}
				int firstchar=ca.sin_addr.s_addr&0xff;
				if(firstchar==127){
					close(nsf);
					continue;
				}
				tUnit=mallocProxyUnit(0);
				//tUnit=mallocProxyUnit2(0,0);
				if(!tUnit){
					LOG_ERROR("MALLOC PROXY UNIT FAIL\n");
					close(nsf);
					continue;
				}
				tUnit->ffd=getFakeSocket(FAKE_SOCK_SET,nsf,0);
				if(!tUnit->ffd){
					internalErrno=ERR_EPOLL_SET_FAKESOCKET;
					goto doCleanMass;
				}
				SET_PROXYUNIT_CFD(tUnit,tUnit->ffd->sockfd);
				tUnit->ops=getPublicHeadOps(0);
				tmpEvt.events=EPOLLIN;
				tmpEvt.data.ptr=tUnit;
				epollrt=epoll_ctl(epollfd,EPOLL_CTL_ADD,nsf,&tmpEvt);
				if(epollrt){
					LOG_ERROR("epoll ctl add fail: %d\n",epollrt);
					internalErrno=ERR_EPOLL_ENQUEUE;
					goto doCleanMass;
				}
				tUnit->flags|=FLAG_ENQUE_OK;
				continue;
			}
			else{
				//printf("EPOLL LOOP : %d\n",i);
				tUnit=(struct ProxyUnit*)loopevent[i].data.ptr;
//				printf("epoll event type: %04x\n",loopevent[i].events);
#ifdef SSL_TEST_F
//						printf("EPOLL LOOP %d of %d  sock: %d.........\n",i,looprt,tUnit->fd);
#endif
				i++;
				if(tUnit->flags&FLAG_CT_FREE){
#ifdef SSL_TEST_F
						printf("BUDDY IS FREEED.........\n");
#endif
					goto doCleanMass;
				}

				if(tUnit->flags&FLAG_CONEC_OK){
					int rlen=recvProxyData(tUnit);
					if(rlen==0){
#ifdef SSL_TEST_F
						LOG_INFO("EPOLL WILL CLOSE SOCK FD: %d\n",tUnit->fd);
#endif
						internalErrno=ERR_EPOLL_MAX;
						goto doCleanMass;
					}
					else if(rlen<0){
						internalErrno=ERR_EPOLL_RECV;
//						printf("REQUEST SIDE: %d %s\n",
//								!(tUnit->flags&FLAG_CT_SER),errno==104 ? "RESET" : "");
						goto doCleanMass;
					}	
				}
///////////////////////////////////////BBBBBBBBBBBBBBBBBBBBBBB/////////////////////
//if(tUnit->first != NULL && !memcmp(tUnit->first,"GET /",5))
//{printf("tUnit->flags%d &FLAG_CT_CLI=%d  &FLAG_BUDDY_OK=%d",tUnit->flags,tUnit->flags&FLAG_CT_CLI,tUnit->flags&FLAG_BUDDY_OK);printf("\n%s\n",tUnit->first);}
				if(IS_CLIENT_WITHOUTBUDDY(tUnit)){
#ifdef SSL_TEST_F
						printf("THIS NEED BUDDY .........\n");
#endif
					ServerInfo sif;
					int rt=getServerInfoB(tUnit->first,tUnit->firstLen,&sif);
					if(rt==1){
						if(do_filter(tUnit,sif.msk))
							goto doCleanMass;
					}
					if(rt==1){
						tUnit2=mallocProxyUnit(0);
						//tUnit2=mallocProxyUnit2(0,0);
						if(!tUnit2){
#ifdef SSL_TEST_F
						LOG_DEBUG("EPOLL MALLOC PROXYUNIT FAIL:\n");
#endif
							internalErrno=ERR_EPOLL_MALLOC_PUNIT_S;
							goto doCleanMass;
						}
						SET_PROXYUNIT_BUDDY(tUnit,tUnit2);
						tUnit2->ops=getResponseOps(sif.msk);
						tUnit->ops=getRequestOps(sif.msk);
						int tmpfd=socket(AF_INET,SOCK_STREAM,0);	
						if(!setNONblock(tmpfd)){
#ifdef SSL_TEST_F
						LOG_WARN("EPOLL SET SET NONBLOCK FAIL\n");
#endif
								goto doCleanMass;
						}

#ifdef SSL_TEST_F
						if(sif.msk==0x00030000&&sif.type==FAKE_SOCK_SSL)
							LOG_INFO("EPOLL WILL CONNECT TO GMAIL sock:%d................\n",tmpfd);
#endif
						tUnit2->fd=tmpfd;
						tUnit2->fd_type=sif.type;
						tmpEvt.events=EPOLLOUT;
						tmpEvt.data.ptr=tUnit2;
						epollrt=epoll_ctl(epollfd,EPOLL_CTL_ADD,tUnit2->fd,&tmpEvt);
						if(epollrt==-1){
#ifdef SSL_TEST_F
						LOG_ERROR("EPOLL ENQUEUE FAIL\n");
#endif
							tUnit->buddy=NULL;
							free(tUnit2);
							internalErrno=ERR_EPOLL_ENQUEUE;
							goto doCleanMass;
						}
						tUnit2->flags|=FLAG_ENQUE_OK;	
						struct sockaddr_in addr;
						memset(&addr,0,sizeof(addr));
						addr.sin_family=AF_INET;
						addr.sin_addr.s_addr=sif.ip;
						addr.sin_port=sif.port;
						int cflg=connect(tmpfd,(struct sockaddr*)&addr,sizeof(addr));
						if(cflg==-1){
							if(errno!=EINPROGRESS){
								LOG_ERROR("CONNECT ERRNO: %d\n",errno);
								goto doCleanMass;
							}
							continue;
						}
						else{
							tUnit=tUnit2;
							goto CONNECT_OK;
						}
					}
					continue;
				}

////////////////////////////////////////CCCCCCCCCCCCCCCCCCCCCC/////////////////////
				if(!(tUnit->flags&FLAG_CONEC_OK)){
					struct tcp_info info;
					int infoLen=sizeof(info);
					int so=getsockopt(tUnit->fd,SOL_TCP,TCP_INFO,&info,&infoLen);
					if(!(info.tcpi_state&TCP_ESTABLISHED)){
#ifdef SSL_TEST_F
						LOG_INFO("EPOLL EVENT ......... %08x num:\n",loopevent[i-1].events);
#endif

//						printf(" TCP STAT ........: %d sock:%d  try:%d\n"
//						,info.tcpi_state,tUnit->fd,tUnit->tryTimes);
						tUnit->tryTimes++;
						if(tUnit->tryTimes<3)
							continue;
						goto doCleanMass;
					}
			CONNECT_OK:	
#ifdef SSL_TEST_F
						LOG_INFO("CONNECT OK......... %d\n",tUnit->fd);
#endif
					tmpEvt.events=EPOLLIN;
					tmpEvt.data.ptr=tUnit;
					epollrt=epoll_ctl(epollfd,EPOLL_CTL_MOD,tUnit->fd,&tmpEvt);
					setBlock(tUnit->fd);
					tUnit->ffd=getFakeSocketB(tUnit->fd_type,tUnit->fd,0);
					if(!tUnit->ffd){
						close(tUnit->fd);
						goto doCleanMass;
					}
					SET_PROXYUNIT_SFD(tUnit,tUnit->ffd->sockfd);
					SET_PROXYUNIT_BUDDY_CONNECT_OK(tUnit);

					PROXYUNIT_PROCESS_DATA(tUnit->buddy);
					if(tUnit->buddy->flags&FLAG_FIRST_FRAM_OK);
						sendProxyData(tUnit->buddy);
					continue;
				}
////////////////////////////////////////CCCCCCCCCCCCCCCCCCCCCC/////////////////////


///////////////////////////////////////BBBBBBBBBBBBBBBBBBBBBBB/////////////////////


				if(tUnit->flags&FLAG_BUDDY_CONEC_OK && 
				   !(tUnit->first != NULL && !memcmp(tUnit->first,"GET /",5) && memcmp(tUnit->first+tUnit->firstLen-4,"\r\n\r\n",5))){
#ifdef SSL_TEST_F
						//printf("WILL PROCESS DATA.........\n");
#endif
					PROXYUNIT_PROCESS_DATA(tUnit);
					if(tUnit->flags&FLAG_FIRST_FRAM_OK);
					sendProxyData(tUnit);
				}
				continue;
			}
			doCleanMass:
				//EPOLL_ERR_SHOW(internalErrno);
				{
					tUnit2=tUnit->buddy;
					tUnit->buddy=NULL;
					if(tUnit2){
						tUnit2->buddy=NULL;
						tUnit2->flags|=FLAG_CT_FREE;
					}
					if(tUnit->flags&FLAG_ENQUE_OK){
#ifdef SSL_TEST_F
						printf("BEFORE DEL EPOLL FD\n");
#endif
						int edl=epoll_ctl(epollfd,EPOLL_CTL_DEL,tUnit->fd,NULL);
						if(edl<0) LOG_ERROR("clean mass : del errno:%d\n",errno);
#ifdef SSL_TEST_F
						printf("AFTER DEL EPOLL FD\n");
#endif
					}	
					if(tUnit->flags&FLAG_CONEC_OK){
#ifdef SSL_TEST_F
						LOG_INFO("EPOLL CLOSE SOCK FD %d\n",tUnit->fd);
#endif
						closeFakeSocket(tUnit->ffd);
						//printf(".................FREE BEFOR :%d\n",tUnit->fd);
						tUnit->ffd=NULL;
					}
					freeProxyUnit(tUnit);
					//freeProxyUnit2(tUnit);
					tUnit=0;
				}	
#ifdef SSL_TEST_F
						printf("EPOLL CLEAN OK.........\n");
#endif		
		}	
	}		
}



static int setNONblock(int fd){
	int flag=fcntl(fd,F_GETFL);
	if(flag<0){
		LOG_ERROR("GET FD FLAGS FAIL\n");
		return 0;
	}
	flag|=O_NONBLOCK;
	if(fcntl(fd,F_SETFL,flag)<0){
		LOG_ERROR("SET FD FLAGS FAIL\n");
		return 0;
	}
//	printf("NONBLOCK ....\n");
	return 1;
}

static int setBlock(int fd){
	int flag=fcntl(fd,F_GETFL);
	if(flag<0){
		LOG_ERROR("N GET FD FLAGS FAIL\n");
		return 0;
	}
	flag&=~O_NONBLOCK;
	if(fcntl(fd,F_SETFL,flag)<0){
		LOG_ERROR("N SET FD FLAGS FAIL\n");
		return 0;
	}
//	printf("BLOCK ....\n");
	return 1;
}
