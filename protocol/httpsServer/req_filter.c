#include "req_filter.h"
#include "proxyUnit.h"
#include "serverInfo.h"
#include "siteTab.h"

#define QQ_RELOCATION_ID 
extern unsigned int serverMask[SERVER_INFO_SIZE];

char* relocation_qq="HTTP/1.1 302 Moved Temporarily\r\n"
						  "Location: http://w.mail.qq.com/cgi-bin/loginpage?f=xhtml\r\n" 
						  "Content-Length: 0\r\n\r\n";
char* req_qq="GET / ";
char* req_qq2="GET /cgi-bin/loginpage ";
int do_filter(struct ProxyUnit* pu,int sid){
	if(pu && sid==serverMask[QQ_B]){
		if(memcmp(pu->first,req_qq,strlen(req_qq))==0 ||
			memcmp(pu->first,req_qq2,strlen(req_qq2))==0){
			sendData(pu->ffd,relocation_qq,strlen(relocation_qq),0);
			return 1;
		}
	}
	return 0;
}
 
