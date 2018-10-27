
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>

#include "dataProcessor.h"
#include "processorChain.h"
#include "serverInfo.h"
#include "fakeServer.h"
#include "fakeSocket.h"
#include "processorDataStr.h"
#include "maskFlags.h"
#include "Analyzer_log.h"

#define HOTMAIL "64.4.20.174"

#define SELECT_TIME_OUT 20
#define CBUF_SIZE 1024*1024*2
#define RBUF_SIZE 1024*20
#define BUF_SIZE 10240
#define RUN_LIMIT 2
//ProcessorChain* chainR;
//ProcessorChain* chainC;
//char Cbuf[CBUF_SIZE];
//char Rbuf[RBUF_SIZE];




	pthread_spinlock_t lock;
	int thread=0;

//Function Name: startServer
//Description: begin listen on port 80
//Parameter: port : listen port (80)
//				 max:  connection limit
int startServer(int port,int max){

	pthread_spin_init(&lock,PTHREAD_PROCESS_SHARED);
	signal(SIGPIPE,SIG_IGN);
	struct sockaddr_in sa;
	struct sockaddr_in ca;
	int addrlen=sizeof(ca);
	int sfd=socket(AF_INET,SOCK_STREAM,0);
	if(sfd<0){
		LOG_FATAL("make socket fail: system will exit\n");
		exit(1);
	}
	int reuse=1;
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
	sa.sin_family=AF_INET;
	sa.sin_port=htons(port);
	sa.sin_addr.s_addr=htonl(INADDR_ANY);
	
	int bid=bind(sfd,(struct sockaddr*)&sa,sizeof(sa));
	if(bid<0){
		LOG_FATAL("bind fail: system will exit\n");
		exit(1);
	}	
	
	int lis=listen(sfd,max);
	if(lis<0){
		LOG_FATAL("listen fail: system will exit\n");
		exit(1);
	}
	LOG_INFO("sfd=%d bid=%d lis=%d\n",sfd,bid,lis);	
	LOG_INFO("server begin listening on port:%d .....\n",port);
	
	while(1){
//		printf("server waiting for connect\n");
		int rfd;
		pthread_t tid;
	   rfd=accept(sfd,(struct sockaddr*)&ca,&addrlen);
	   LOG_INFO("server receive connection: %s  port %u\n",inet_ntoa(ca.sin_addr),ca.sin_port);
		void* (*func)(void*)=processRequest;
		RPP* para=(RPP*)malloc(sizeof(RPP));
		if(!para){
			LOG_ERROR("malloc for RPP fail\n");
			close(rfd);
			continue;
		}
		para->fd=rfd;
		para->ip=ca.sin_addr.s_addr;
		para->port=ca.sin_port;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
		int i=pthread_create(&tid,&attr,func,para);
		LOG_INFO("create new thread is 0 : %d\n",i);
		if(i){
			LOG_ERROR("create thread fail thread total is: %d\n",thread);
			close(para->fd);
			free(para);
			continue;
		}
		else{
			pthread_spin_lock(&lock);
			thread++;
			pthread_spin_unlock(&lock);
		}
	}	
}


//Function Name: processRequest
//Description: process the request from client
//Parameter: para: is not useful now 

int processRequest(RPP* para){
	//RRP
	//printf("get into processRequest\n");	
	int cfd=0;
	int run=RUN_LIMIT;
	FakeSocket* rfs=NULL;
	FakeSocket* cfs=NULL;
	ProcessorChain* chainR=NULL;
	ProcessorChain* chainC=NULL;
	ProcessorPara* priPara=NULL;
	ConnectInfo* conInfo=NULL;
	char* Cbuf=NULL;
	char* Rbuf=NULL;
	ServerInfo sif;
	memset(&sif,0,sizeof(ServerInfo));	

	int sip=getServerInfo(para->fd,&sif);
	if(sip<0){
		LOG_ERROR("find ip fail:ERROR: %d\n",sip);
		close(para->fd);
		free(para);
		pthread_spin_lock(&lock);
		thread--;
		pthread_spin_unlock(&lock);
		return -1;
	}
	chainR=getProcessorChain(1,PARA_MOD_PUB,dataProcessFuncPubB);
	if(!chainR){
		LOG_ERROR(" get ProcessorChain fail \n");
		close(para->fd);
		pthread_spin_lock(&lock);
		thread--;
		pthread_spin_unlock(&lock);
		return -1;
	}
	chainR->sitMsk=sif.msk|SITE_DIRECTION_UP;
	switch(sif.msk&SITE_SERIAL_MSK){
		case SITE_SERIAL_WANGYI:{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
											 dataProcessFunc163E);
			if(!chainC){
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			break;
		}
		case SITE_SERIAL_HOTMIL:{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
											 dataProcessFuncMsnC);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncMsnD,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncMsnQ,NULL);
			if(!chainC){
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			break;
		}
		case SITE_SERIAL_GOOGLE:{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
											 dataProcessFuncGH);
			if(!chainC){
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGR,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGM,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGG,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGJ,NULL);
			addProcessor(chainR,PARA_MOD_PUB,dataProcessFuncGO,NULL);
			addProcessor(chainR,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGP,NULL);
			break;
		}
		case SITE_SERIAL_SOHU:
		{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
									 dataProcessFuncSOHU);
				
			
			if(!chainC)
			{
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			break;
		}
		case SITE_SERIAL_YAHOO:
		{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
									 dataProcessFuncYAHOO);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncYAHOO_B,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncYAHOO_C,NULL);
			if(!chainC)
			{
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			break;
		}
		case SITE_SERIAL_QQ:
		{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
									 dataProcessFuncQQ);
			
			if(!chainC)
			{
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			break;
		}
		
		default :{
			chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,
											 dataProcessFuncMsnD);
			if(!chainC){
				LOG_ERROR(" get ProcessorChain fail \n");
				close(para->fd);
				releaseProcessorList(chainR);
				pthread_spin_lock(&lock);
				thread--;
				pthread_spin_unlock(&lock);
				return -1;
			}
			chainC->sitMsk=sif.msk|SITE_DIRECTION_DOWN;
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGR,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncMsnC,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFunc163E,NULL);
			addProcessor(chainR,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncPubA,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGH,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGG,NULL);
			addProcessor(chainR,PARA_MOD_PUB,dataProcessFuncGO,NULL);
			addProcessor(chainR,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGP,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGJ,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncGM,NULL);
			addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncMsnQ,NULL);
			break;
		}
	}	

/*
	chainC=getProcessorChain(1,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncD);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncR,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncC,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncE,NULL);
	addProcessor(chainR,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncA,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncH,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncG,NULL);
	//addProcessor(chainR,PARA_MOD_PUB,dataProcessFuncN,NULL);
	addProcessor(chainR,PARA_MOD_PUB,dataProcessFuncO,NULL);
	addProcessor(chainR,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncP,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncJ,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncM,NULL);
	addProcessor(chainC,PARA_MOD_PUB|PRO_MOD_AP_SET,dataProcessFuncQ,NULL);
*/
/*
		conInfo=(ConnectInfo*)malloc(sizeof(ConnectInfo));
		conInfo->ipCli=para->ip;
		conInfo->portCli=para->port;
		conInfo->ipSer=sif.ip;
		conInfo->portSer=sif.port;
		priPara=(ProcessorPara*)malloc(sizeof(ProcessorPara));
		priPara->pub=NULL;
		priPara->pri=conInfo;
*/
	//addProcessor(chainR,PARA_MOD_PRI|PRO_MOD_AP_SET,dataProcessFuncF,priPara);

	Cbuf=(char*)malloc(CBUF_SIZE);
	Rbuf=(char*)malloc(RBUF_SIZE);
	rfs=getFakeSocket(FAKE_SOCK_SET,para->fd,0);
	cfs=getFakeSocket(sif.type,sif.ip,sif.port);

	if(!chainR||!chainC||!Cbuf||!Rbuf||!rfs||!cfs){
		LOG_ERROR("*** something is wrong ***\n");
		run=0;
	}
	if(chainR&&chainC&&Rbuf&&Cbuf){
		resetChainHead(chainR,Rbuf,0);
		resetChainHead(chainC,Cbuf,0);
		chainR->buddy=chainC;
	}
	struct timeval tv;
	tv.tv_sec=SELECT_TIME_OUT;
	tv.tv_usec=0;
	fd_set fdRead;
	int maxfd=para->fd;
	if(rfs&&cfs){
		maxfd=rfs->sockfd > cfs->sockfd ? rfs->sockfd+1 : cfs->sockfd+1;
	}
	int selectVal=0;
 	char buf[BUF_SIZE+1];
	buf[BUF_SIZE]=0;
	
	while(run){
//printf("get into while \n");
		memset(buf,0,BUF_SIZE);
		FD_ZERO(&fdRead);
		FD_SET(rfs->sockfd,&fdRead);
		FD_SET(cfs->sockfd,&fdRead);
		selectVal=select(maxfd,&fdRead,NULL,NULL,&tv);
//		printf("select return %d\n",selectVal);
		if(selectVal<0){
			LOG_ERROR("something wrong in select\n");
			run=0;
		}
		else if(selectVal==0){			
			// send data in urgent mode
			//printf("time out in select\n");
			if(chainR->len>0){
				process(chainR,MODE_RCV|MODE_URGENT,buf,0);
				int slen=sendData(cfs,chainR->data,chainR->len,0);
				LOG_INFO("send: %d to server in urgent mode \n",slen);
				//printf("%s\n",chainR->data);
				memset(Rbuf,0,RBUF_SIZE);
				resetChainHead(chainR,Rbuf,0);
				run=RUN_LIMIT;
				continue;
			}
			if(chainC->len>0){
				process(chainC,MODE_CON|MODE_URGENT,buf,0);
				int slen=sendData(rfs,chainC->data,chainC->len,0);
				LOG_INFO("send: %d to client in urgent mode\n",slen);
				//printf("%s\n",chainC->data);
				memset(Cbuf,0,CBUF_SIZE);
				resetChainHead(chainC,Cbuf,0);
				run=RUN_LIMIT;
				continue;
			}
			run--;
		}
		else{
			if(FD_ISSET(rfs->sockfd,&fdRead)){
				int len=recvData(rfs,buf,BUF_SIZE,0);
				LOG_INFO("receive %d bytes from client\n",len);
				if(len>0){
					process(chainR,MODE_RCV,buf,len);
					if(chainR->tmode&CHAIN_MOD_SND){
						int slen=sendData(cfs,chainR->data,chainR->len,0);
						LOG_INFO("send %d bytes to server \n",slen);
						memset(Rbuf,0,RBUF_SIZE);
						resetChainHead(chainR,Rbuf,0);
					}
				}
				else if(len==0){
	//				printf("recv close signal from client\n");
					run=0;
				}
				else{
					LOG_ERROR("recv error signal from client\n" );
					run= 0;
				}
			}

			if(FD_ISSET(cfs->sockfd,&fdRead)){
				int len=recvData(cfs,buf,BUF_SIZE,0);
				LOG_INFO("receive %d bytes from server\n",len);
				if(len>0){
					process(chainC,MODE_CON,buf,len);
					if(chainC->tmode&CHAIN_MOD_SND){
						int slen=sendData(rfs,chainC->data,chainC->len,0);
						LOG_INFO("send %d bytes to client\n",slen);
						memset(Cbuf,0,CBUF_SIZE);
						resetChainHead(chainC,Cbuf,0);
					}
				}
				else if(len==0){
	//				printf("recv close signal from server\n");
					run=0;
				}
				else{
					LOG_ERROR("recv error signal from server\n");
					run=0;
				}
			}
		}
		
	}
//	if(conInfo)
//		free(conInfo);
	if(priPara)
		free(priPara);
	if(Rbuf)
		free(Rbuf);
	if(Cbuf)
		free(Cbuf);
	if(rfs)
	closeFakeSocket(rfs);
	else
	close(para->fd);
	if(cfs)
	closeFakeSocket(cfs);
	releaseProcessorList(chainR);
	releaseProcessorList(chainC);
	free(para);
	pthread_spin_lock(&lock);
	thread--;
	pthread_spin_unlock(&lock);
	
	return 1;
}

