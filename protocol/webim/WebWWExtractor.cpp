
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iconv.h>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>

#include "WebWWExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define PORT_BITS 16

//#define RECVPOST_RULE "^GET\\s/get.do\\?callback=TDog.DataManager.Message.saveGetData&nkh=(.+)&appId=(.+)"
//#define SEND_RULE "^GET\\s/send.do\\?callback=TDog.WebServer.handleSendResult&userId=cntaobao(.+)&content=(.+)&nkh=(.+)&appId=(.+)"
#define SEND_RULE "^GET\\s/send.do\\?.+?&callback=TDog.WebServer.handleSendResult&userId=cntaobao(.+)&content=(.+)&nkh=(.+)&appId=(.+).*"
//#define RECVMSG_RULE "^HTTP/1.1\\s200(.+)TDog.DataManager.Message.saveGetData(.+)\"cntaobao(.+)\",\"messages\":(.+)\"content\":\"(.+)\",\"head\":(.+)"
//#define LOGIN_RULE "^GET\\s/1.gif\\?acookie_load_id=(.+)&pre=&category=&(.+)Referer:\\shttp://www.taobao.com/(.+)tracknick=(.+);\\sssllogin=(.+)&cookie(.+)"
#define LOGIN_RULE "GET\\s/login.do\\?.+?&callback=TDog.WebServer.prepareLogin&nickName=(.+)&autoLogin=(.+)&loginTag=(.+)&nkh=(.+)&appId=(.+).*"
#define LOGIN_RULE2 "^GET\\s/my_taobao.htm\\?nekot=(.+)Host:\\si.taobao.com(.+)Cookie:(.+)tracknick=(.+);\\sssllogin=(.+)"
//#define LOGOUT_RULE "^GET\\s/user/logout.htm\\sHTTP/\\s1.1(.+)"
#define LOGOUT_RULE "^GET\\s/member/logout.jhtml.*"
#define RECV_RULE "HTTP/1.1\\s200(.+)TDog.DataManager.(handleReceiveMessage|saveStartChatData)(.+)\\{\"userId\":\"cntaobao(.+)\",\"fromId\":\"cntaobao(.+)\",\"sendTime\":\"(.+)\",\"content\":\"(.+)\",\"type\":\\d,\"subType\":201\\}\\]\\}\\}.;$"

static int FLAG = 0;
static int LEN = 0;
static char flaglogin[15] = {0};
static char flagsend[15] = {0};
static char flaglogout[15] = {0};
static char DataStr[2500] = {0};
using namespace std;

WebWWExtractor::WebWWExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBIM/WebWW");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_WEBPAGECHAT;
    // Create a directory to store the webqq message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	
	loginRule_ = new boost::regex(LOGIN_RULE);
	loginRule2_ = new boost::regex(LOGIN_RULE2);
	//recvMsgRule_ = new boost::regex(RECVMSG_RULE);
	sendRule_ = new boost::regex(SEND_RULE);
	logoutRule_ = new boost::regex(LOGOUT_RULE);
	//recvPostRule_ = new boost::regex(RECVPOST_RULE);
	recvRule_ = new boost::regex(RECV_RULE);
	memcpy(tableName_, "WEBIM", 6);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

WebWWExtractor::~WebWWExtractor()
{
	delete loginRule_;
	delete recvMsgRule_;
	delete sendRule_;
	delete logoutRule_;
	delete recvPostRule_;
	delete recvRule_;

}

bool WebWWExtractor::IsWebIMText(PacketInfo* pktInfo)
{
	bool iswebwwText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	const char *pstart = NULL;
	const char *pend = NULL;
	int len;
	//webww login
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;

	if (boost::regex_search(first, last, matchedStr, *logoutRule_))
	{
		FLAG = 1;
	}
	if(FLAG)
	{
		if (!strncmp(first,flaglogout, 10))
		{
			return false;
		}
		else if (strstr(first, "_nk_=") != NULL)
		{
			strncpy(DataStr+LEN, first, pktInfo_->bodyLen);
			first = DataStr;
			last = DataStr + strlen(DataStr);
			//cout<<"DataStr: "<<DataStr<<endl;
			FLAG = 0;
			LEN = 0; 
		}
		else 
		{
			strncpy(DataStr+LEN, first, pktInfo_->bodyLen);
			strncpy(flaglogout, first, 15);
			LEN += pktInfo_->bodyLen;
			return false;
		}
	}

	if(boost::regex_search(first, last, matchedStr, *loginRule_)
	   || boost::regex_search(first, last, matchedStr, *loginRule2_)){
		//cout<<"...........webwwlogin..........."<<endl;
		pstart = strstr(first+100, "&t=");
		if (pstart == NULL)
			return -1;
		pstart += 3;
		if (!strncmp(pstart, flaglogin, 15))
			return 0;
		memcpy(flaglogin, pstart, 15);
		//cout<<"flaglogin: "<<flaglogin<<endl;
		int len = matchedStr[4].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[4].first, len);
		char* from_=str;
		char *from = new char [50];
		memset(from , 0 , 50);
		htmldecode_full(from_ , from);
		delete[] from_;
		clear_tag(from);
		//cout<<"from: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 603;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 0;
		StoreMsg2DB(node);

		pktInfo_ = NULL;
		iswebwwText = true;
	} else if(boost::regex_match(first, last, matchedStr, *sendRule_)){
		//cout<<".......begin_sendRule........."<<endl;
		pstart = strstr(first+100, "&t=");
		if (pstart == NULL)
			return -1;
		pstart += 5;
		if (!strncmp(pstart, flagsend, 15))
			return 0;
		memcpy(flagsend, pstart, 15);
		//cout<<"flagsend: "<<flagsend<<endl;
		int len = matchedStr[1].length();
		char *str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *to_ = str;

		char *to = new char [50];
		memset(to , 0 ,50);
		htmldecode_full(to_ , to);
		delete[] to_;
		//cout<<"to: "<<to<<endl;
		
		len=matchedStr[2].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char* text=str;

		len = matchedStr[3].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[3].first, len);
		char *from_=str;

		char *from = new char [50];
		memset(from , 0 ,50);
		htmldecode_full(from_ , from);
		delete[] from_;
		//cout<<"from: "<<from<<endl;

		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		memcpy(node, pktInfo_, COPY_BYTES);

		node->from = from;
		node->to = to;
		node->text = new char [1500];
		memset(node->text , 0 , 1500);
		htmldecode_full(text, node->text);
		delete[] text;
		//cout<<"text: "<<node->text<<endl;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 603;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 0;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
		iswebwwText = true;
		
	} else if((boost::regex_match(first, last, matchedStr, *logoutRule_)) && strstr(first, "_nk_=")){
		//cout<<"..........begain_logout.........."<<endl;
		pstart = strstr(first, "time=");
		if (pstart == NULL)
			return -1;
		pstart += 5;
		if (!strncmp(pstart, flagsend, 15))
			return 0;
		memcpy(flagsend, pstart, 15);
		//cout<<"flagsend: "<<flagsend<<endl;

		pstart = strstr(pstart, "_nk_=");
		if (pstart == NULL)	
			return -1;
		pstart += 5;
		pend = strstr(pstart, ";");
		len = pend - pstart;
		char *str = new char [len +1];
		memset(str, 0, len+1);
		memcpy(str, pstart, len);
		//cout<<"STR: "<<str<<endl;
		char *from_ = str;
		
		char *from = new char [50];
		memset(from , 0 ,50);
		htmldecode_full(from_ , from);
		delete[] from_;
		//cout<<"from: "<<from<<endl;	

		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		memcpy(node, pktInfo_, COPY_BYTES);

		// Copy basic data to message node
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Logout;
		//cout<<"node->msgType: "<<node->msgType<<endl;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;

		node->protocolType = 603;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));

		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 0;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
		keyMap.clear();
		memset(DataStr, 0, 2500);
		iswebwwText = true;
	} else if(boost::regex_match(first, last, matchedStr, *recvRule_)){
		//cout<<"...........Program excution begin_recvRule.........."<<endl;
		int len = matchedStr[4].length();
		char *str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[4].first, len);
		char *to_ = str;	

		char *to = new char [50];
		memset(to , 0 ,50);
		code_convert( "gb2312","UTF-8",to_,0,to,0);
		delete[] to_;
		
		len = matchedStr[7].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[7].first, len);
		char* text=str;

		len = matchedStr[5].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[5].first, len);
		char *from_=str;

		char *from = new char [50];
		memset(from , 0 ,50);
		code_convert( "gb2312","UTF-8",from_,0,from,0);
		delete[] from_;

		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		memcpy(node, pktInfo_, COPY_BYTES);

		node->srcIpv4=pktInfo_->destIpv4;
		node->srcPort=pktInfo_->destPort;
		node->destIpv4=pktInfo_->srcIpv4;
		node->destPort=pktInfo_->srcPort;

		node->from = from;
		node->to = to;
		node->text = new char [1500];
		memset(node->text , 0 , 1500);
		//htmldecode_full(text , node->text);
		code_convert( "gb2312","UTF-8",text,0,node->text,0);
		delete[] text;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		//cout<<"node->from: "<<node->from<<endl;
		//cout<<"node->to: "<<node->to<<endl;
		//cout<<"node->text: "<<node->text<<endl;
		
		node->protocolType = 603;
		char strmac[20] = {0};
#ifdef VPDNLZ
		ParseMac(pktInfo_->srcMac,strmac);
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		ParseMac(pktInfo_->destMac, strmac);
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
#ifdef VPDNLZ
		node->affixFlag = 0;
#else
		node->affixFlag = 9000;
#endif
		StoreMsg2DB(node);
		pktInfo_ = NULL;
		iswebwwText = true;
	}

	return iswebwwText;
}		


int WebWWExtractor::htmldecode_full(char *src, char *dest)
{
	int strlength=strlen(src);
	if(strlength<3)
	{
		strcpy(dest,src);
		return 0;
	}
	int i=0;
	int flag=0;
	int j=0;
	char tmp1=0;
	char tmp2=0;
	char tmpA=0;
	char tmpB=0;
	char A,B;

	for(i=0; i<strlength; i++)
	{
		if(src[i] =='%')
		{
			flag = 1;
			continue;
		}
		switch(flag)
		{
			case 0:
			{	
				
				dest[j]=src[i];
				if(dest[j] == '+') dest[j] = ' ';
				j++;
				break;
			}
			case 1:
				flag = 2;
				if(i < (strlength-12) &&src[i]=='0'   &&src[i+1]=='D'  && src[i+2]=='%' 
				   && src[i+3]=='0'   &&src[i+4]=='A' )
				{
					dest[j]=10;
					i=i+4;
					flag=0;
					j++;
					break;
				}
		
				if(i < (strlength-10) &&src[i]=='5' &&src[i+1]=='C' && src[i+2]=='%' && 
					src[i+3]=='5' &&src[i+4]=='C'  )
				{
					dest[j]='\\';
					i=i+4;
					flag=0;
					j++;
					break;
				}
				tmpA = src[i];
				
				break;
			case 2:
				tmpB = src[i];
				tmp1 = toupper(tmpA);
				tmp2 = toupper(tmpB);
				if(((tmp1 >= 48&&tmp1 <= 57) || (tmp1 >= 65&&tmp1 <= 90)) && (
								 (tmp2 >= 48&&tmp2 <= 57) || (tmp2 >= 65 && tmp2 <= 90)))
				{
					if(tmp1 >= 48&&tmp1 <= 57) A = tmp1 - 48;
					else A = 10 + tmp1 - 65;
					if(tmp2 >= 48 && tmp2 <= 57) B = tmp2 - 48;
					else B = 10 + tmp2 - 65;
					dest[j] = A * 16 + B;
					
				}
				else
				{
					dest[j] = '%';
					dest[j+1] = tmp1;
					dest[j+2] = tmp2;
					j += 2;
				}
				flag = 0;
				j++;
				break;
			default:
				break;
		}
	}
	dest[j] = 0;
}

int WebWWExtractor::char_to_int(char x)
{
	if(x>='0'&&x<='9')
		x=x-'0';
	else if(x>='a' && x<='f'){
		x-='a';
		x+=10;
	}else if(x>='A' && x<='F'){
		x-='A';
		x+=10;
	}

	return x;
}

int WebWWExtractor::str_to_int(char str[4])
{
   int sum=0;
   int i;
   for(i=0;i<4; i++)
   sum=sum*16+char_to_int(str[i]);
   return sum;
    
}

int  WebWWExtractor::clear_tag(char *str)
{
	char *head=NULL,*end=NULL;
	char A,B,C,D;
	char x,y,z;
	char u1=0x0e;
	char u2=0x80;
	char tem[4];
	int value;
	if(str==NULL) return 0;
	head=str;
	end=head;
	while(*head!='\0'){
		if(*head=='\\'&&*(head+1)=='\\'&&*(head+2)=='u')
		{
			*(end++)='\\';
			*(end++)='u';
			head+=3;
		}	
		if(*head=='\\'&&*(head+1)=='u'){
		         memcpy(tem,head+2,4);
		         value=str_to_int(tem);
		         if(value<0x0800)
		         {
		           A=((value>>6) & 0x1f) | 0xc0;
		           B=((value>>0) & 0x3f) | 0x80;
		           *(end++)=A;
		           *(end++)=B;
		         }
		         else
		         {
			A=char_to_int(*(head+2));
			B=char_to_int(*(head+3));
			C=char_to_int(*(head+4));
			D=char_to_int(*(head+5));
			x=(u1<<4)|A;
			y=u2 | (B<<2) |(C>>2);
			z=u2 | ((C&0x03)<<4) |D;
			*(end++)=x;
			*(end++)=y;
			*(end++)=z;
			}
			head+=6;
			continue;
		}else{
			if(end<head) *end=*head;
			end++;
			head++;
		}
	}
	*end='\0';

}

int WebWWExtractor::transferMean(char *str)
{
	char *head=NULL,*end=NULL;
	if(str==NULL) return 0;
	head=str;
	end=head;
	int flag = 0;
	while(*head!='\0'){
		 if(flag == 2){
			if(*head=='\\'){ 
				*(end++)='\\';
				head+=2;	
				flag=2;
			}
			else {
				*(end++)=*head;
				head+=1;	
				flag=0;
			}
		}		
		else if(flag == 1){
			if(*head=='0'){
				 *(end++)=0;
				head+=1;
				flag = 0;
			}	
			else if(*head=='a'){
				 *(end++)=7;
				head+=1;
				flag = 0;
			}		
			else if( *head=='b'){
				 *(end++)=8;
				head+=1;
				flag = 0;
			}	
			else if( *head=='t'){
				 *(end++)=9;
				head+=1;
				flag = 0;
			}	
			else if(*head=='n'){
				 *(end++)=10;
				head+=1;
				flag = 0;
			}	
			else if(*head=='v'){
				 *(end++)=11;
				head+=1;
				flag = 0;
			}	
			else if(*head=='f'){
				 *(end++)=12;
				head+=1;
				flag = 0;
			}	
			else if(*head=='r'){
				 *(end++)=13;
				head+=1;
				flag = 0;
			}	
			else if(*head=='e'){
				 *(end++)=27;
				head+=1;
				flag = 0;
			}			
			else if(*head=='\\')
			{
				*(end++)='\\';
				head+=1;
				flag = 2;
			}
			else if(end<head) {
				*end=*head;
				flag=0;
			}
		}
		else {
			if(*head== '\\')
			{
				flag=1;
				head+=1;
			}
			else {
				*(end++)=*head;
				head+=1;
				flag=0;
			}
		}
	}
	*end='\0';
	
}

int WebWWExtractor:: code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen , char *outbuf, size_t outlen)
{
   iconv_t cd;
   if ((cd  = iconv_open(to_charset, from_charset)) < 0) {
        cout << "Get iconv handle failed!" << endl;
        return -1;
    }
   char **pin=&inbuf;
   char **pout=&outbuf;

    size_t gbkInLen;
    if (inlen == 0) {
        gbkInLen = strlen(inbuf);
    } else {
        gbkInLen = inlen;
    }

     size_t utf8Len;
     if(outlen == 0){
     	 utf8Len = gbkInLen * 2;
     } else {
	utf8Len = outlen;
     }

   if (iconv(cd, pin, &gbkInLen, pout, &utf8Len) == -1) {
	   iconv_close(cd);
	   fprintf(stderr, "src: %s\ndest: %s\n", inbuf, outbuf);
	   return 0;
   }
   iconv_close(cd);
//  ucnv_convert("utf-8", "gb18030", outbuf, outlen, inbuf, inlen, NULL);
   return 0;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebWWExtractor::StoreMsg2DB(Node* msgNode)
{
	/*write iminfo data to shared memory, by zhangzm*/
	struct in_addr addr;
	IMINFO_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	addr.s_addr = msgNode->srcIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	if(msgNode->affixFlag == 9000)
	{
		ParseMac(msgNode->destMac, tmp_data.p_data.clientMac);
	}
	else
	{
		ParseMac(msgNode->srcMac, tmp_data.p_data.clientMac);
	}
	
	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
	addr.s_addr = pktInfo_->destIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;

	tmp_data.optype = msgNode->msgType;
	if (msgNode->text != NULL)
	{
		strncpy(tmp_data.content, msgNode->text, 499);
	}
	else
	{
		strcpy(tmp_data.content, "");
	}

	if (msgNode->from != NULL)
	{
		strncpy(tmp_data.sendNum, msgNode->from, 199);
	}
	else 
	{
		strcpy(tmp_data.sendNum, "");
	}
	
	if (msgNode->to != NULL)
	{
		strncpy(tmp_data.recvNum, msgNode->to, 199);
	}
	else
	{
		strcpy(tmp_data.recvNum, "");
	}	

	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(IMINFO, (void *)&tmp_data, sizeof(tmp_data));

	xmlStore_.ClearNode(msgNode);
}
// End of file

