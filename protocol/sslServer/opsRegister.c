
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "opsRegister.h"
#include "dataProcessorB.h"
#include "Analyzer_log.h"

/* global variable*/
int pubHeadOpsNum;
headFunc* pubHeadOps;
struct DataOperation* dataOperations[MAX_DATA_OPERATIONS];
struct DataOperation* pubOps;
/*****/

#define SIT_SERIAL_TO_OPS_INDEX(x)	(x>>16&0x3FFF)

int initPublicHeadOps(){
	pubHeadOpsNum=4;
	pubHeadOps=(headFunc*)malloc(sizeof(headFunc)*pubHeadOpsNum);
	pubHeadOps[0]=getDataType;
	pubHeadOps[1]=isHeadComplete;
	pubHeadOps[2]=getContentType;
	pubHeadOps[3]=getTransferencode;
	
	return 1;
}

int initPublicOps(){
	pubOps=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(!pubOps){
		LOG_ERROR("INIT PUBOPS FAIL\n");
		exit(1);
	}
	memset(pubOps,0,sizeof(*pubOps));
	pubOps->hnum=pubHeadOpsNum;
	pubOps->hOps=pubHeadOps;
	return 1;
}

int registerOps(int index,struct DataOperation* dopt){
	if(!dopt || index>=MAX_DATA_OPERATIONS)
		return 0;
	if(index<0)
		return 0;
	dataOperations[index]=dopt;
	return 1;
}

struct DataOperation* getRequestOps(int simsk){
	struct DataOperation* tmp=0;
	int index=SIT_SERIAL_TO_OPS_INDEX(simsk);
	//printf("getRequestOps DATA OPERATION INDEX: %d\n",index);
	if(index<0 || index>=MAX_DATA_OPERATIONS)
		return NULL;
	tmp=dataOperations[index];
	if(tmp==0)
		LOG_WARN("DATA OPERATION IS NULL\n");
	return tmp;
}

struct DataOperation* getResponseOps(int simsk){
	struct DataOperation* tmp=0;
	int index=SIT_SERIAL_TO_OPS_INDEX(simsk);
	//printf("getResponseOps DATA OPERATION INDEX: %d\n",index);
	if(index<0 || index>=MAX_DATA_OPERATIONS)
		return NULL;
	tmp=dataOperations[index];
	if(tmp==0)
		LOG_WARN("DATA OPERATION IS NULL\n");
	return tmp;
}

int initOps(){
	initPublicHeadOps();
	initPublicOps();
	struct DataOperation* tmp=NULL;
	tmp=getWangyiOps();
	if(tmp){
		registerOps(OPS_INDEX_WANGYI,tmp);
		//printf("REGISTER WANGYI OK %d\n",OPS_INDEX_WANGYI);
	}
	tmp=getMsnOps();
	if(tmp)
		registerOps(OPS_INDEX_MSN,tmp);
	tmp=getGugoOps();
	if(tmp)
		registerOps(OPS_INDEX_GUGO,tmp);
	tmp=getQqOps();
	if(tmp)
		registerOps(OPS_INDEX_QQ,tmp);
	tmp=getSohuOps();
	if(tmp)
		registerOps(OPS_INDEX_SOHU,tmp);
	tmp=getYahooOps();
	if(tmp)
		registerOps(OPS_INDEX_YAHOO,tmp);
	tmp=getHanmailOps();
	if(tmp)
		registerOps(OPS_INDEX_HANMAIL,tmp);
	tmp=getSinaOps();
	if(tmp)
		registerOps(OPS_INDEX_SINA,tmp);
	return 1;
}

struct DataOperation* getPublicHeadOps(int flag){
	return pubOps;
}

 
