
#include <string.h>
#include <stdio.h>

#include "storeEngineL.h"
#include "accountL.h"
#include "db_data.h"
//#include "Analyzer_log.h"

#define NTOH(p) (p<<8&0xff00)|(p>>8&0xff)

static int ipntoc(int ip,int net,char *buf);
static int portstoc(short port,int net,char *buf);

/*********************************************************************************************************
Function name: storeAccount
Description: store the account information into database
Parameter: 	account_ a pointer to struct Account that stores the informaation of account
**********************************************************************************************************/
int storeAccount(Account* account_)
{
	char* mail = account_->mail;
	int len = strlen(mail);
	int i = 0;
	int ii = 0;
	char email[len+1];
	memset(email, 0, len+1);
	while(i < len)
	{
		if((mail[i] == '%')&&(i+2 < len))
		{
			char tmp=' ';
			if (mail[i+1]>='0'&&mail[i+1]<='9')
				tmp=(mail[i+1]-'0')<<4;
			else if (mail[i+1]>='A'&&mail[i+1]<='F')
				tmp=(mail[i+1]-55)<<4;
			if (mail[i+2]>='0'&&mail[i+2]<='9')
				tmp|=mail[i+2]-'0';
			else if (mail[i+2]>='A'&&mail[i+2]<='F')
				tmp|=mail[i+2]-55;
			email[ii]=tmp;
			ii++;
			i+=3;	
		}
		else
		{
			email[ii]=mail[i];
			ii++;
			i++;
			
		}
	}
	char* tpass = account_->pass;
	len = strlen(tpass);
	char epass[len+1];
	memset(epass, 0, len+1);
	i = 0;
	ii = 0;
	while(i < len)
	{
		if((tpass[i] == '%')&&(i+2 < len))
		{
			char tmp=' ';
			if(tpass[i+1]>='0'&&tpass[i+1]<='9')
				tmp=(tpass[i+1]-'0')<<4;
			else if(tpass[i+1]>='A'&&tpass[i+1]<='F')
				tmp=(tpass[i+1]-55)<<4;
			if(tpass[i+2]>='0'&&tpass[i+2]<='9')
				tmp|=tpass[i+2]-'0';
			else if(tpass[i+2]>='A'&&tpass[i+2]<='F')
				tmp|=tpass[i+2]-55;
			epass[ii]=tmp;
			ii++;
			i+=3;	
		}
		else
		{
			epass[ii] = tpass[i];
			ii++;
			i++;
		}
	}

	/*write webaccount data to shared memory, by zhangzm*/
	WEBACCOUNT_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));

	tmp_data.p_data.clueid = (unsigned int)account_->objectId;
	tmp_data.p_data.readed = 0;
	ipntoc(account_->ipSrc, 1, tmp_data.p_data.clientIp);
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x",
			account_->macSrc[0]&0xff,account_->macSrc[1]&0xff,account_->macSrc[2]&0xff,
			account_->macSrc[3]&0xff,account_->macSrc[4]&0xff,account_->macSrc[5]&0xff);
	portstoc(account_->portSrc, 0, tmp_data.p_data.clientPort);

	ipntoc(account_->ipDst, 1, tmp_data.p_data.serverIp);
	portstoc(account_->portDst, 0, tmp_data.p_data.serverPort);
	tmp_data.p_data.captureTime = (int)account_->cap_time;
	strncpy(tmp_data.url, account_->url, LZ_URL_LEN);

	if (strlen(email) > 64)
		strcpy(tmp_data.username, "");
	else
		strncpy(tmp_data.username, email, 64);

	if(strlen(epass) > 64)
		strcpy(tmp_data.password, "");
	else
		strncpy(tmp_data.password, epass, 64);

	tmp_data.p_data.proType = account_->type;
	tmp_data.p_data.deleted = 0;

	msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));

#if 0
	memcpy(db_data+2, (void *)&tmp_data, sizeof(tmp_data));

	if (sem_post(g_prsem) < 0)
	{
		printf("Fail to sem_post prsem.\n");
		return -1;
	}
#endif

	return 1;
}

/*********************************************************************************************************
Function name: ipntoc
Description: translate the ip from int to characters
Parameter: ip : value that needs being translated
		   net: if the ip is network order
		   buf: to store the translated value
**********************************************************************************************************/
static int ipntoc(int ip,int net,char *buf)
{
	memset(buf,0,16);
	int tmp=ip;
	if(net==1){
	
    	tmp=0;
	tmp=(ip<<24)&0xff000000;
	tmp|=(ip<<8)&0x00FF0000;
	tmp|=(ip>>8)&0x0000FF00;
	tmp|=(ip>>24)&0x000000FF;
	
	}
	int i=0;
	int j=0;
	int m=0;
	int val=0;
	int valB=0;
	int flag=0;
	while(i<4){
		flag=0;
		val=(tmp>>((3-i)*8))&0x000000FF;
		valB=val/100;
		if(valB>0){
			flag=1;
			buf[j]=(char)(valB+0x30);
			j++;
		}
		valB=(val%100)/10;
		if(flag==0){
			if(valB>0){
			buf[j]=(char)(valB+0x30);
			j++;
			}
		}else{
			buf[j]=(char)(valB+0x30);
			j++;
		}
		valB=(val%10);
		buf[j]=(char)(valB+0x30);
		j++;
		buf[j]='.';
		j++;
		i++;		
	}
	buf[j-1]=0;
	return 1;
}


/*********************************************************************************************************
Function name: portstoc
Describe: convert the short-value of port to string
Parameter: port
		   net: if is the network order
		   buf: stored the converted string
**********************************************************************************************************/
static int portstoc(short port, int net, char *buf)
{
	memset(buf,0,6);
	unsigned short tmp = port;
	if(net == 1)
	{	
		tmp = 0;
		tmp |= (port>>8)&0x00FF;
		tmp |= (port<<8)&0xFF00;
	}
	
	sprintf(buf,"%d",tmp);
	return 1;
}


