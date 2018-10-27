
#include <libxml/parser.h>
#include <string.h>
#include <unistd.h>

#include "siteSwitch.h"
#include "Analyzer_log.h"

extern const char* SSL_RUN;
struct SSLswitch sslswitch;
static const char* nextSection(const char* v);
static void initSiteSwitch(struct SSLswitch* ssl,const char* val);
static int initSSLstatus(struct SSLswitch* ssl);

void* checkSwitch(void* path){
	int run=1;
	while(run){
		initSSLstatus(&sslswitch);	
		if(sslswitch.sslOn)
			SSL_RUN="1";
		else
			SSL_RUN="0";
		//printf("THE DNS STATUS IN THREAD RUNB: %s\n",SSL_RUN);
		sleep(60);
	}
	return 0;
}

int isSwitchOn(int flag){
	int f=flag>>16&0xffff;
	if(f<SWITCH_MAX)
		return sslswitch.siteSwitch[f];
	return 0;
}


static int initSSLstatus(struct SSLswitch* ssl){
	int rt=0;
	const char* configfile = "/spy/config/sslConfig.xml";
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	char* SSL_RUN="0";
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if(!doc){
		LOG_ERROR("READ CONFIGURE FILE FAIL\n");
		return rt;
	}
	curNode = xmlDocGetRootElement(doc);
	if(!curNode){
		LOG_ERROR("EMPTY CONFIGURE FILE\n");
		xmlFreeDoc(doc);
		return rt;
	}
	if(xmlStrcmp(curNode->name, BAD_CAST "config")){
		LOG_ERROR("BAD ROOT ELEMENT\n");
		xmlFreeDoc(doc);
		return rt;
	}
	xmlChar* xsslRun=NULL;
	xmlChar* xSwitch=NULL;
	itemNode = curNode->xmlChildrenNode;
	while(itemNode){
		if(itemNode->type != XML_ELEMENT_NODE){
			itemNode = itemNode->next;
			continue;
		}
		if(!xmlStrcmp (itemNode->name, BAD_CAST "sslSwitch")){
			xsslRun = xmlNodeGetContent(itemNode);
			SSL_RUN=(char *)xsslRun;
			ssl->sslOn=0;
			if(!strcmp(SSL_RUN,"1"))
				ssl->sslOn=1;
			xmlFree(xsslRun);
		}
		if(!xmlStrcmp(itemNode->name, BAD_CAST "emailSwitch")){
			xSwitch=xmlNodeGetContent(itemNode);
			initSiteSwitch(ssl,(const char*)xSwitch);
			xmlFree(xSwitch);
		}
		 
		itemNode = itemNode->next;
	}
		rt=1;
	xmlFreeDoc(doc);
//#define LZ_CHEAT_TEST
#ifdef LZ_CHEAT_TEST
int j=0;
for(;j<6;j++)
	LOG_INFO(".........%d %d\n",j,ssl->siteSwitch[j]);
#endif

	return rt;
}



static void initSiteSwitch(struct SSLswitch* ssl,const char* val){
	memset(ssl->siteSwitch,0,sizeof(ssl->siteSwitch));
	int t=0;
	const char* v=val;
	while(*v && (*v<'0' || *v>'9'))
		v++;
	
	while(*v){
		t=atoi(v);
		ssl->siteSwitch[t]=1;
		v=nextSection(v);
	}

}

static const char* nextSection(const char* v){
	const char* t=v;
	int i=0;
	while(*t && *t>='0' && *t<='9')
		t++;
	while(*t && (*t<'0' || *t>'9'))
		t++;	
	return t;	
}



