#include "dnsServer.h"
#include <netdb.h>
#include <stdio.h>

//Function name: getIpbyName
//
//Description: get the ip of domain
//Parameter: domain:the domain 
unsigned int getIpbyName(char* domain){
	if(!domain)
		return 0;
	struct hostent *myhost;
	char ** pp;
	myhost= gethostbyname(domain);
	if(!myhost)
		return 0;
	pp=myhost->h_addr_list;
	if(*pp!=NULL){
		unsigned int ip=(unsigned int)(*(unsigned int*)*pp);
//		printf("%s:%d.%d.%d.%d\n",domain,ip>>24&0xff,ip>>16&0xff,ip>>8&0xff,ip&0xff);
		return ip;
	}
	//printf("can not find %s\n",domain);
	return 0;
}
								
							
