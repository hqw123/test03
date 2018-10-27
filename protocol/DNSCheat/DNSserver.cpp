
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "DNSserver.h"
#include "DNSutil.h"
#include "Analyzer_log.h"

extern struct ServerIP serverIP;
extern struct DnsPkt   dnsPkt;

DNSserver::DNSserver(){
	type=0;
	sip=&serverIP;
	pkt=&dnsPkt;
	memset(sip,0,sizeof(struct ServerIP));
	memset(pkt,0,sizeof(struct DnsPkt));
	sip->dnsIP=0x08080808;
}

int DNSserver::setDomain(const char* domain,int type){
	if(strlen(domain)>200){
		LOG_ERROR("ERROR: DOMAIN NAME IS TOO  LONG :%s\n",domain);
		return -1;
	}
	this->type=type;
	memcpy(sip->domain,domain,strlen(domain));
	return 0;	
}

int DNSserver::setDnsIP(unsigned int ip){
	sip->dnsIP=ip;
	return 0;
}

int DNSserver::setDev(const char* dev,int type){
	if(strlen(dev)>63){
		LOG_ERROR("FUCK. THE DEV NAME IS MUCH TOO LONG:  ^!^\n");
		return -1;
	}
	memcpy(sip->devOUT,dev,strlen(dev));
	return 0;
}

int DNSserver::run(int slepsec){
	pthread_t tid;
	int rt=pthread_create(&tid,0,runA,NULL);
	if(rt){
		LOG_ERROR("OH,BAD NEWS:SOMETHING WRONG HAPPENDED WHEN CREATE NEW THREAD !!!\n");
		return -1;
	}
/*
	pthread_t tid2;
	int rt2=pthread_create(&tid2,0,runB,NULL);
	if(rt2){
		printf("OH,NO GOOD NEWS: SOMETHING WRONG HAPPENDED WHEN CREATE NEW THREAD !!!\n");
		return -2;
	}
*/
	return 0;
}


