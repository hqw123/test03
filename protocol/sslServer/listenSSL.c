
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "listenSSL.h"
#include "dnsServer.h"
#include "Analyzer_log.h"

#define SSL_MAX_CONN 500
#define BUFF_SIZE 4096

char buff[BUFF_SIZE];


struct SockPair{
	int fd;
	struct SockPair* buddy;
};

int getConnection(){
	struct sockaddr_in addr;
	addr.sin_family=AF_INET;
	addr.sin_port=0xBB01;
	addr.sin_addr.s_addr=ip[0];
	int sfd=socket(AF_INET,SOCK_STREAM,0);
	if(sfd==-1)
		return 0;
	return sfd;
}







int getsslServerSocket(int port,int max);
int runssl(int sfd);

int startsslServer(unsigned short port,int max){
	if(signal(SIGPIPE,SIG_IGN)==SIG_ERR){
		LOG_ERROR("set sig fail...\n");
		exit(-1);
	}
	int sfd=getsslServerSocket(port,max);
	runssl(sfd);
}
	
int getsslServerSocket(int port,int max){
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
		LOG_ERROR("MSN BIND FAIL ERRNO:%d\n",errno);
		close(sfd);
		return -1;
	}
	int lis=listen(sfd,max);
	if(lis<0){
		LOG_ERROR("MSN LISTEN FAIL ERRNO:%d\n",errno);
		close(sfd);
		return -1;
	}
//	printf("MSN LISTEN ON PORT %d\n",port);
	return sfd;
}	

int runssl(int sfd){
	 
	struct sockaddr_in ca; 
	int addrlen=sizeof(ca);
	int epollfd=epoll_create(SSL_MAX_CONN);
	if(epollfd==-1){
		LOG_ERROR("MSN EPOLL CREATE FAIL: ERRNO %d\n",errno);
		exit(1);
	}
	
	int evtlen=sizeof(struct epoll_event)*SSL_MAX_CONN;
	struct epoll_event* loopevent=(struct epoll_event*)malloc(evtlen);
	if(!loopevent){
		LOG_ERROR("MALLOC LOOP EVENT FAIL :ERRNO %d\n",errno);
		exit(1);
	}
	
	struct epoll_event tmpEvt;
	struct epoll_event tmpEvt2;
	tmpEvt.events=EPOLLIN;
	tmpEvt.data.fd=sfd;
	struct SockPair* pair=0;
	struct SockPair* pair2=0;
	int epollctl,epollctl2;
	int looprt=0;
	int epollrt=epoll_ctl(epollfd,EPOLL_CTL_ADD,sfd,&tmpEvt);
	while(1){
		//	printf("WAITING ......\n");
		looprt=epoll_wait(epollfd,loopevent,SSL_MAX_CONN,-1);
		int i=0;
		if(looprt==-1){
			LOG_ERROR("EPOLLWAIT RETURN -1 ERRNO %d\n",errno);
			continue;
		}
 
		while(i<looprt){
			pair=pair2=0;
			if(loopevent[i].data.fd==sfd){
				i++;
				int nsf=accept(sfd,(struct sockaddr*)&ca,&addrlen);
				if(nsf==-1){LOG_ERROR("accept fail:num %d\n",errno);continue;}
				int firstchar=ca.sin_addr.s_addr&0xff;
				if(firstchar==127){
					close(nsf);
					continue;
				}
				pair=malloc(sizeof(struct SockPair));
				pair2=malloc(sizeof(struct SockPair));
				int conn=getConnection();
				if(!pair || !pair2 || ! conn){
					if(conn)
						close(conn);
					if(pair)
						free(pair);
					if(pair2)
						free(pair2);
					continue;	
				}
				pair->fd=nsf;
				pair->buddy=pair2;
				pair2->fd=conn;
				pair2->buddy=pair;
				tmpEvt.events=EPOLLIN;
				tmpEvt.data.ptr=pair;
				tmpEvt2.events=EPOLLIN;
				tmpEvt2.data.ptr=pair2;
				epollctl=epoll_ctl(epollfd,EPOLL_CTL_ADD,pair->fd,&tmpEvt);
				if(epollctl){
					close(pair->fd);
					close(pair2->fd);
					free(pair);
					free(pair2);
					continue;
				}
				epollctl2=epoll_ctl(epollfd,EPOLL_CTL_ADD,pair2->fd,&tmpEvt2);
				if(epollctl2){
					epoll_ctl(epollfd,EPOLL_CTL_DEL,pair->fd,0);
					close(pair->fd);
					close(pair2->fd);
					free(pair);
					free(pair2);
					continue;
				}

			}
			else{	
				pair=loopevent[i].data.ptr;
				i++;
				int snd=0;
				int len=recv(pair->fd,buff,BUFF_SIZE,0);
				if(len>0){	
					pair2=pair->buddy;
					while(snd<len){
						int sd=send(pair2->fd,buff+snd,snd,0);
						if(sd<0)
							break;
						snd+=sd;
					}
				}
				if(len<=0||snd<0){
					epoll_ctl(epollfd,EPOLL_CTL_DEL,pair->fd,0);
					close(pair->fd);
					free(pair);
				}
			}
		}	
	}		
}




 



