#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>

#include "dnsServer.h"
#include "serverInfo.h"
#include "siteTab.h"
#include "maskFlags.h"
#include "../Analyzer_log.h"

#define GIP_BUF_SIZE 2048+1024

#define GET_GM_A "GET /mail/ "
#define GET_GM_B "GET / "
#define GET_GW_A "GET /accounts/"
#define POST_GW_A "POST "

#define GET_WANGYI "GET / "

//Function name: getSIp
//deprecated
//Description get the ip by sock
unsigned int getSIp(int sock){
	return 0;
}


//int* serverInfo=NULL;
unsigned int serverInfo[SERVER_INFO_SIZE];
unsigned int serverMask[SERVER_INFO_SIZE];

//Function name: initServerInfo
//Description: get the ip address for some domains
//Parameter: array: int array to store IPs of domains
int initServerInfo(int* array){

	memset(serverInfo,0,sizeof(serverInfo));
	memset(serverMask,0,sizeof(serverMask));
	unsigned int ip=0;
	ip=getIpbyName(HOTMAIL_DOMN_A);
	serverInfo[HOTMAIL_A]=ip;
	serverMask[HOTMAIL_A]=SITE_SERIAL_HOTMIL|HOTMAIL_A;
	ip=getIpbyName(HOTMAIL_DOMN_B);
	serverInfo[HOTMAIL_B]=ip;
	serverMask[HOTMAIL_B]=SITE_SERIAL_HOTMIL|HOTMAIL_B;
	ip=getIpbyName(HOTMAIL_DOMN_C);
	serverInfo[HOTMAIL_C]=ip;
	serverMask[HOTMAIL_C]=SITE_SERIAL_HOTMIL|HOTMAIL_C;
	ip=getIpbyName(HOTMAIL_DOMN_D);
	serverInfo[HOTMAIL_D]=ip;
	serverMask[HOTMAIL_D]=SITE_SERIAL_HOTMIL|HOTMAIL_D;
	ip=getIpbyName(HOTMAIL_DOMN_E);
	serverInfo[HOTMAIL_E]=ip;
	serverMask[HOTMAIL_E]=SITE_SERIAL_HOTMIL|HOTMAIL_E;
	ip=getIpbyName(HOTMAIL_DOMN_F);
	serverInfo[HOTMAIL_F]=ip;
	serverMask[HOTMAIL_F]=SITE_SERIAL_HOTMIL|HOTMAIL_F;

	ip=getIpbyName(WANGYI_DOMN_A);
	serverInfo[WANGYI_A]=ip;
	serverMask[WANGYI_A]=SITE_SERIAL_WANGYI|WANGYI_A;
	ip=getIpbyName(WANGYI_DOMN_B);
	serverInfo[WANGYI_B]=ip;
	serverMask[WANGYI_B]=SITE_SERIAL_WANGYI|WANGYI_B;
	ip=getIpbyName(WANGYI_DOMN_C);
	serverInfo[WANGYI_C]=ip;
	serverMask[WANGYI_C]=SITE_SERIAL_WANGYI|WANGYI_C;
	ip=getIpbyName(WANGYI_DOMN_D);
	serverInfo[WANGYI_D]=ip;
	serverMask[WANGYI_D]=SITE_SERIAL_WANGYI|WANGYI_D;
	ip=getIpbyName(WANGYI_DOMN_E);
	serverInfo[WANGYI_E]=ip;
	serverMask[WANGYI_E]=SITE_SERIAL_WANGYI|WANGYI_E;
	ip=getIpbyName(WANGYI_DOMN_F);
	serverInfo[WANGYI_F]=ip;
	serverMask[WANGYI_F]=SITE_SERIAL_WANGYI|WANGYI_F;
	ip=getIpbyName(WANGYI_DOMN_G);
	serverInfo[WANGYI_G]=ip;
	serverMask[WANGYI_G]=SITE_SERIAL_WANGYI|WANGYI_G;
	ip=getIpbyName(WANGYI_DOMN_H);
	serverInfo[WANGYI_H]=ip;
	serverMask[WANGYI_H]=SITE_SERIAL_WANGYI|WANGYI_H;
	ip=getIpbyName(WANGYI_DOMN_I);
	serverInfo[WANGYI_I]=ip;
	serverMask[WANGYI_I]=SITE_SERIAL_WANGYI|WANGYI_I;
	ip=getIpbyName(WANGYI_DOMN_J);
	serverInfo[WANGYI_J]=ip;
	serverMask[WANGYI_J]=SITE_SERIAL_WANGYI|WANGYI_J;
	ip=getIpbyName(WANGYI_DOMN_K);
	serverInfo[WANGYI_K]=ip;
	serverMask[WANGYI_K]=SITE_SERIAL_WANGYI|WANGYI_K;
	ip=getIpbyName(WANGYI_DOMN_L);
	serverInfo[WANGYI_L]=ip;
	serverMask[WANGYI_L]=SITE_SERIAL_WANGYI|WANGYI_L;
	ip=getIpbyName(WANGYI_DOMN_M);
	serverInfo[WANGYI_M]=ip;
	serverMask[WANGYI_M]=SITE_SERIAL_WANGYI|WANGYI_M;
	ip=getIpbyName(WANGYI_DOMN_N);
	serverInfo[WANGYI_N]=ip;
	serverMask[WANGYI_N]=SITE_SERIAL_WANGYI|WANGYI_N;
	ip=getIpbyName(WANGYI_DOMN_O);
	serverInfo[WANGYI_O]=ip;
	serverMask[WANGYI_O]=SITE_SERIAL_WANGYI|WANGYI_O;


	ip=getIpbyName(GOOGLE_DOMN_A);
	serverInfo[GOOGLE_A]=ip;
	serverMask[GOOGLE_A]=SITE_SERIAL_GOOGLE|GOOGLE_A;
	ip=getIpbyName(GOOGLE_DOMN_B);
	serverInfo[GOOGLE_B]=ip;
	serverMask[GOOGLE_B]=SITE_SERIAL_GOOGLE|GOOGLE_B;
	ip=getIpbyName(GOOGLE_DOMN_C);
	serverInfo[GOOGLE_C]=ip;
	serverMask[GOOGLE_C]=SITE_SERIAL_GOOGLE|GOOGLE_C;
	ip=getIpbyName(GOOGLE_DOMN_D);
	serverInfo[GOOGLE_D]=ip;
	serverMask[GOOGLE_D]=SITE_SERIAL_GOOGLE|GOOGLE_D;
	ip=getIpbyName(GOOGLE_DOMN_E);
	serverInfo[GOOGLE_E]=ip;
	serverMask[GOOGLE_E]=SITE_SERIAL_GOOGLE|GOOGLE_E;
	ip=getIpbyName(GOOGLE_DOMN_F);
	serverInfo[GOOGLE_F]=ip;
	serverMask[GOOGLE_F]=SITE_SERIAL_GOOGLE|GOOGLE_F;	


	ip=getIpbyName(YAHOO_DOMN_A);
	serverInfo[YAHOO_A]=ip;
	serverMask[YAHOO_A]=SITE_SERIAL_YAHOO|YAHOO_A;
	ip=getIpbyName(YAHOO_DOMN_B);
	serverInfo[YAHOO_B]=ip;
	serverMask[YAHOO_B]=SITE_SERIAL_YAHOO|YAHOO_B;
	ip=getIpbyName(YAHOO_DOMN_C);
	serverInfo[YAHOO_C]=ip;
	serverMask[YAHOO_C]=SITE_SERIAL_YAHOO|YAHOO_C;
	ip=getIpbyName(YAHOO_DOMN_D);
	serverInfo[YAHOO_D]=ip;
	serverMask[YAHOO_D]=SITE_SERIAL_YAHOO|YAHOO_D;
	ip=getIpbyName(YAHOO_DOMN_E);
	serverInfo[YAHOO_E]=ip;
	serverMask[YAHOO_E]=SITE_SERIAL_YAHOO|YAHOO_E;
	ip=getIpbyName(YAHOO_DOMN_F);
	serverInfo[YAHOO_F]=ip;
	serverMask[YAHOO_F]=SITE_SERIAL_YAHOO|YAHOO_F;
	
	ip=getIpbyName(SOHU_DOMN_A);
	serverInfo[SOHU_A]=ip;
	serverMask[SOHU_A]=SITE_SERIAL_SOHU|SOHU_A;
	ip=getIpbyName(SOHU_DOMN_B);
	serverInfo[SOHU_B]=ip;
	serverMask[SOHU_B]=SITE_SERIAL_SOHU|SOHU_B;
	
	ip=getIpbyName(QQ_DOMN_A);
	serverInfo[QQ_A]=ip;
	serverMask[QQ_A]=SITE_SERIAL_QQ|QQ_A;
	ip=getIpbyName(QQ_DOMN_B);
	serverInfo[QQ_B]=ip;
	serverMask[QQ_B]=SITE_SERIAL_QQ|QQ_B;
	ip=getIpbyName(QQ_DOMN_C);
	serverInfo[QQ_C]=ip;
	serverMask[QQ_C]=SITE_SERIAL_QQ|QQ_C;

	ip=getIpbyName(HANMAIL_DOMN_A);
	serverInfo[HANMAIL_A]=ip;
	serverMask[HANMAIL_A]=SITE_SERIAL_HANMAIL|HANMAIL_A;
	ip=getIpbyName(HANMAIL_DOMN_B);
	serverInfo[HANMAIL_B]=ip;
	serverMask[HANMAIL_B]=SITE_SERIAL_HANMAIL|HANMAIL_B;
	ip=getIpbyName(HANMAIL_DOMN_C);
	serverInfo[HANMAIL_C]=ip;
	serverMask[HANMAIL_C]=SITE_SERIAL_HANMAIL|HANMAIL_C;
	ip=getIpbyName(HANMAIL_DOMN_D);
	serverInfo[HANMAIL_D]=ip;
	serverMask[HANMAIL_D]=SITE_SERIAL_HANMAIL|HANMAIL_D;
	ip=getIpbyName(HANMAIL_DOMN_E);
	serverInfo[HANMAIL_E]=ip;
	serverMask[HANMAIL_E]=SITE_SERIAL_HANMAIL|HANMAIL_E;
	
	ip=getIpbyName(SINA_DOMN_A);
	serverInfo[SINA_A]=ip;
	serverMask[SINA_A]=SITE_SERIAL_SINA|SINA_A;
	ip=getIpbyName(SINA_DOMN_B);
	serverInfo[SINA_B]=ip;
	serverMask[SINA_B]=SITE_SERIAL_SINA|SINA_B;
	ip=getIpbyName(SINA_DOMN_C);
	serverInfo[SINA_C]=ip;
	serverMask[SINA_C]=SITE_SERIAL_SINA|SINA_C;
	ip=getIpbyName(SINA_DOMN_D);
	serverInfo[SINA_D]=ip;
	serverMask[SINA_D]=SITE_SERIAL_SINA|SINA_D;
	
printf("init sslServer over\n");
return 1;
}


//Function Name: getServerInfo
//Description: get ip and port of the real-server for the client
//Parameter: sock: socket-id received from client
//				sif : a pointer to ServerInfo to store the ip and port 
//						of real-server
int getServerInfo(int sock,ServerInfo* sif){
	return 0;
}


int getServerInfoB(char* data,int len,ServerInfo* sif){//if(strstr(data,"GET /")){printf("\n%s\n",data);}
	if(!data || len<10 || !sif)
		return 0;
	char* host=strstr(data,"Host:");
	char tbuf[32];
	memset(tbuf,0,32);
	if(!host)
		return 0;
	char* max=data+len;
	int i=0;
	host+=5;
	while(host<max && *host==0x20)
		host++;
	while(host<max && i<32){
		if(*host==0x20 ||*host=='\r' ||*host=='\n')
			break;
		tbuf[i]=*host;
		i++;
		host++;
	}
	if(host==max || i==32)
		return 0;
	int dflag=0xf0000000;
	sif->type=FAKE_SOCK_COM;
	sif->port=0x5000;
	sif->ip=0;
	
	if(!strcmp(tbuf,HOTMAIL_DOMN_A)){
		sif->ip=serverInfo[HOTMAIL_A];
		sif->msk=serverMask[HOTMAIL_A];
		dflag=HOTMAIL_A;
	}
	else if(!strcmp(tbuf,HOTMAIL_DOMN_B)){
		sif->ip=serverInfo[HOTMAIL_B];
		sif->msk=serverMask[HOTMAIL_B];
		dflag=HOTMAIL_B;
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;
	}
	else if(!strcmp(tbuf,HOTMAIL_DOMN_C)){
		sif->ip=serverInfo[HOTMAIL_C];
		sif->msk=serverMask[HOTMAIL_C];
		dflag=HOTMAIL_C;
	}
	else if(!strcmp(tbuf,HOTMAIL_DOMN_D)){
		sif->ip=serverInfo[HOTMAIL_D];
		sif->msk=serverMask[HOTMAIL_D];
		dflag=HOTMAIL_D;/*
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;*/
	}
	else if(!strcmp(tbuf,HOTMAIL_DOMN_E)){
		sif->ip=serverInfo[HOTMAIL_E];
		sif->msk=serverMask[HOTMAIL_E];
		dflag=HOTMAIL_E;
	}
	else if(!strcmp(tbuf,HOTMAIL_DOMN_F)){
		sif->ip=serverInfo[HOTMAIL_F];
		sif->msk=serverMask[HOTMAIL_F];
		dflag=HOTMAIL_F;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_A)){
		sif->ip=serverInfo[WANGYI_A];
		sif->msk=serverMask[WANGYI_A];
		dflag=WANGYI_A;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_B)){
		sif->ip=serverInfo[WANGYI_B];
		sif->msk=serverMask[WANGYI_B];
		dflag=WANGYI_B;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_C)){
		sif->ip=serverInfo[WANGYI_C];
		sif->msk=serverMask[WANGYI_C];
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_D)){
		sif->ip=serverInfo[WANGYI_D]; 
		sif->msk=serverMask[WANGYI_D];
		dflag=WANGYI_D;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_E)){
		sif->ip=serverInfo[WANGYI_E];
		sif->msk=serverMask[WANGYI_E];
		dflag=WANGYI_E;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_F)){
		sif->ip=serverInfo[WANGYI_F];
		sif->msk=serverMask[WANGYI_F];
		dflag=WANGYI_E;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_G)){
		sif->ip=serverInfo[WANGYI_G];
		sif->msk=serverMask[WANGYI_G];
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_H)){
		sif->ip=serverInfo[WANGYI_H];
		sif->msk=serverMask[WANGYI_H];
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_I)){
		sif->ip=serverInfo[WANGYI_I];
		sif->msk=serverMask[WANGYI_I];
		dflag=WANGYI_E;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_J)){
		sif->ip=serverInfo[WANGYI_J];
		sif->msk=serverMask[WANGYI_J];
		dflag=WANGYI_E;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_K)){
		sif->ip=serverInfo[WANGYI_K];
		sif->msk=serverMask[WANGYI_K];
		dflag=WANGYI_K;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_L)){
		sif->ip=serverInfo[WANGYI_L];
		sif->msk=serverMask[WANGYI_L];
		dflag=WANGYI_L;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_M)){
		sif->ip=serverInfo[WANGYI_M];
		sif->msk=serverMask[WANGYI_M];
		dflag=WANGYI_M;
	}
	else if(!strcmp(tbuf,WANGYI_DOMN_N)){
		sif->ip=serverInfo[WANGYI_N];
		sif->msk=serverMask[WANGYI_N];
		dflag=WANGYI_N;
	}



	else if(!strcmp(tbuf,GOOGLE_DOMN_A)){
		sif->ip=serverInfo[GOOGLE_A];
		sif->msk=serverMask[GOOGLE_A];
		dflag=GOOGLE_A;
	}
	else if(!strcmp(tbuf,GOOGLE_DOMN_B)){
		sif->ip=serverInfo[GOOGLE_B];
		sif->msk=serverMask[GOOGLE_B];
		dflag=GOOGLE_B;
	}
	else if(!strcmp(tbuf,GOOGLE_DOMN_C)){
		sif->ip=serverInfo[GOOGLE_C];
		sif->msk=serverMask[GOOGLE_C];
		dflag=GOOGLE_C;
	}
	else if(!strcmp(tbuf,GOOGLE_DOMN_D)){
		sif->ip=serverInfo[GOOGLE_D];
		sif->msk=serverMask[GOOGLE_D];
		dflag=GOOGLE_D;
	}
	else if(!strcmp(tbuf,GOOGLE_DOMN_E)){
		sif->ip=serverInfo[GOOGLE_E];
		sif->msk=serverMask[GOOGLE_E];
		dflag=GOOGLE_E;
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;
	}
	else if(!strcmp(tbuf,GOOGLE_DOMN_F)){
		sif->ip=serverInfo[GOOGLE_F];
		sif->msk=serverMask[GOOGLE_F];
		dflag=GOOGLE_F;
	}

	else if(!strcmp(tbuf,YAHOO_DOMN_A))
	{
		sif->ip=serverInfo[YAHOO_A];
		sif->msk=serverMask[YAHOO_A];
		dflag=YAHOO_A;
	}
	else if(!strcmp(tbuf,YAHOO_DOMN_B))
	{
		sif->ip=serverInfo[YAHOO_B];
		sif->msk=serverMask[YAHOO_B];
		dflag=YAHOO_B;
	}
	else if(!strcmp(tbuf,YAHOO_DOMN_C))
	{
		sif->ip=serverInfo[YAHOO_C];
		sif->msk=serverMask[YAHOO_C];
		dflag=YAHOO_C;
	}
	else if(!strcmp(tbuf,YAHOO_DOMN_D))
	{
		sif->ip=serverInfo[YAHOO_D];
		sif->msk=serverMask[YAHOO_D];
		dflag=YAHOO_D;
	}
	else if(!strcmp(tbuf,YAHOO_DOMN_E))
	{
		sif->ip=serverInfo[YAHOO_E];
		sif->msk=serverMask[YAHOO_E];
		dflag=YAHOO_E;
	}
	else if(!strcmp(tbuf,YAHOO_DOMN_F))
	{
		sif->ip=serverInfo[YAHOO_F];
		sif->msk=serverMask[YAHOO_F];
		dflag=YAHOO_F;
	}
	else if(!strcmp(tbuf,SOHU_DOMN_A))
	{
		sif->ip=serverInfo[SOHU_A];
		sif->msk=serverMask[SOHU_A];
		dflag=SOHU_A;
	}
	else if(!strcmp(tbuf,SOHU_DOMN_B))
	{
		sif->ip=serverInfo[SOHU_B];
		sif->msk=serverMask[SOHU_B];
		dflag=SOHU_B;
	}
	else if(!strcmp(tbuf,QQ_DOMN_A))
	{
		sif->ip=serverInfo[QQ_A];
		sif->msk=serverMask[QQ_A];
		dflag=QQ_A;
	}
	else if(!strcmp(tbuf,QQ_DOMN_B))
	{
		sif->ip=serverInfo[QQ_B];
		sif->msk=serverMask[QQ_B];
		dflag=QQ_B;
	}
	else if(!strcmp(tbuf,QQ_DOMN_C))
	{
		sif->ip=serverInfo[QQ_C];
		sif->msk=serverMask[QQ_C];
		dflag=QQ_C;
	}
	else if(!strcmp(tbuf,HANMAIL_DOMN_A))
	{
		sif->ip=serverInfo[HANMAIL_A];
		sif->msk=serverMask[HANMAIL_A];
		dflag=HANMAIL_A;
	}
	else if(!strcmp(tbuf,HANMAIL_DOMN_B))
	{
		sif->ip=serverInfo[HANMAIL_B];
		sif->msk=serverMask[HANMAIL_B];
		dflag=HANMAIL_B;
	}
	else if(!strcmp(tbuf,HANMAIL_DOMN_C))
	{
		sif->ip=serverInfo[HANMAIL_C];
		sif->msk=serverMask[HANMAIL_C];
		dflag=HANMAIL_C;
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;
	}
	else if(!strcmp(tbuf,HANMAIL_DOMN_D))
	{
		sif->ip=serverInfo[HANMAIL_D];
		sif->msk=serverMask[HANMAIL_D];
		dflag=HANMAIL_D;
	}
	else if(!strcmp(tbuf,HANMAIL_DOMN_E))
	{
		sif->ip=serverInfo[HANMAIL_E];
		sif->msk=serverMask[HANMAIL_E];
		dflag=HANMAIL_E;
	}
	else if(!strcmp(tbuf,SINA_DOMN_A))
	{
		sif->ip=serverInfo[SINA_A];
		sif->msk=serverMask[SINA_A];
		dflag=SINA_A;
	}
	else if(!strcmp(tbuf,SINA_DOMN_B))
	{
		sif->ip=serverInfo[SINA_B];
		sif->msk=serverMask[SINA_B];
		dflag=SINA_B;
	}
	else if(!strcmp(tbuf,SINA_DOMN_C))
	{
		sif->ip=serverInfo[SINA_C];
		sif->msk=serverMask[SINA_C];
		dflag=SINA_C;
	}
	else if(!strcmp(tbuf,SINA_DOMN_D))
	{
		sif->ip=serverInfo[SINA_D];
		sif->msk=serverMask[SINA_D];
		dflag=SINA_D;
	}
//printf("IN SERVER INFO ....................5\n");
	else
		return 0;
	//
	if(dflag==WANGYI_K||dflag==WANGYI_L||dflag==WANGYI_M){
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;
	}
	
	if(dflag==GOOGLE_A) {
		//sif->port=0xBB01;
		//sif->type=FAKE_SOCK_SSL;
		sif->port=0x5000;
		sif->type=FAKE_SOCK_COM;
#define GGA "GET /mail/ "
#define GGA_B "GET / "
		if(!memcmp(data,GGA,strlen(GGA)) || !memcmp(data,GGA_B,strlen(GGA_B))){
			sif->port=0x5000;
			sif->type=FAKE_SOCK_COM;
		}	
	}
	if(dflag==GOOGLE_B){
		sif->port=0xBB01;
		sif->type=FAKE_SOCK_SSL;
#define GGB "GET /acco"
#define GGB_B "POST"
	}
	if(dflag==HOTMAIL_B){
#define MSN_P "POST /ppsecure/post.srf"
		if(!memcmp(data,MSN_P,strlen(MSN_P))){
			sif->port=0xBB01;
			sif->type=FAKE_SOCK_SSL;
		}
	}
	if(dflag==QQ_B) 
	{
		sif->type=FAKE_SOCK_SSL;
		sif->port=0xBB01;
	}
	if(dflag==SOHU_A) {
#define SOHU_GET "GET /?schemeforce=1"
		if(!memcmp(SOHU_GET,data,strlen(SOHU_GET))){
			sif->type=FAKE_SOCK_SSL;
			sif->port=0xBB01;
		}
#define SOHU_GET2 "GET /?schemeforce=0"
		else if(!memcmp(SOHU_GET2,data,strlen(SOHU_GET2))){
			sif->type=FAKE_SOCK_COM;
			sif->port=0x5000;
		}
#define SOHU_OPTION "SOHU_LOGIN_OPTION=1"
		else if(strstr(data,SOHU_OPTION)){
			sif->type=FAKE_SOCK_SSL;
			sif->port=0xBB01;
		}
	}
	if(dflag==SOHU_B) {
		sif->type=FAKE_SOCK_SSL;
		sif->port=0xBB01;
	}

	if(dflag==YAHOO_C || dflag==YAHOO_B) {
		sif->type=FAKE_SOCK_SSL;
		sif->port=0xBB01;
	}

	if(dflag==SINA_A) {
#define SINA_GET "POST /sso/login.php?"
// 		if(!memcmp(SINA_GET,data,strlen(SINA_GET))){
			sif->type=FAKE_SOCK_SSL;
			sif->port=0xBB01;
// 		}
	}
//#define TEST_SERVERINFO
#ifdef TEST_SERVERINFO
	if(sif->type==FAKE_SOCK_SSL)
		LOG_INFO("TYPE: SSL\n");
	if(sif->type==FAKE_SOCK_COM)
		LOG_INFO("TYPE: COM\n");
#endif
	return 1;			
}


