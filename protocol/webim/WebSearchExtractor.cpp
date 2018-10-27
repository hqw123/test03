
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "WebSearchExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define BAIDU_RULE "^GET\\s(/s\\?.*?&wd|/baidu\\?word|/baidu\\?wd)=(.+?)&.*?Host:\\swww.baidu.com\r\n"
#define BING_RULE "^GET\\s/search\\?q=(.+?)&.*?Host:\\scn.bing.com\r\n"
#define SOSO_RULE "^GET\\s/web\\?query=(.+?)&.*?Host:\\swww.sogou.com\r\n"

WebSearchExtractor::WebSearchExtractor()
{   
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBIM/WebSearch");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_WEBPAGECHAT;
    // Create a directory to store the webim message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	baiduRule_ = new boost::regex(BAIDU_RULE);
	bingRule_ = new boost::regex(BING_RULE);
	sosoRule_ = new boost::regex(SOSO_RULE);

	memcpy(tableName_, "WEBSEARCH", 9);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

WebSearchExtractor::~WebSearchExtractor()
{
	delete baiduRule_;
	delete bingRule_;
	delete sosoRule_;
}

bool WebSearchExtractor::IsWebIMText(PacketInfo* pktInfo)
{
	bool iswebSearchText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
  	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
// 	cout<<"search.........."<<endl;

	if(boost::regex_search(first, last, matchedStr, *baiduRule_))
	{
	
		int len = matchedStr[2].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		
		//cout<<"Login ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text = new char [1500];
		memset(node->text,0,1500);
		char* text = str;
		htmldecode_full(text, node->text);
		delete[] text;
		node->from=NULL;
		node->to=NULL;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 1101;
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
		iswebSearchText = true;
	}
	else if(boost::regex_search(first, last, matchedStr, *bingRule_))
	{
// 		cout<<"bing search..."<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		
		//cout<<"Logout ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);

		node->text = new char [1500];
		memset(node->text,0,1500);
		char* text = str;
		htmldecode_full(text,node->text);
		delete[] text;
		node->from=NULL;
		node->to=NULL;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 1102;
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
		iswebSearchText = true;
	}
	else if(boost::regex_search(first, last, matchedStr, *sosoRule_))
	{
// 		cout<<"sogou search..."<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text = new char [1500];
		memset(node->text,0,1500);
		char* text = str;
		htmldecode_full(text,node->text);
		delete[] text;
		node->from=NULL;
		node->to=NULL;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId = 0;
		
		node->protocolType = 1103;
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
		iswebSearchText = true;
	}
	
	return iswebSearchText;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebSearchExtractor::StoreMsg2DB(Node* msgNode)
{
	/*write iminfo data to shared memory, by zhangzm*/
	struct in_addr addr;
	SEARCH_ENGINE_T tmp_data;
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

	if (msgNode->text != NULL)
	{
		strncpy(tmp_data.content, msgNode->text, 1023);
	}
	else
	{
		return;
	}

	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(SEARCH_ENGINE, (void *)&tmp_data, sizeof(tmp_data));

	xmlStore_.ClearNode(msgNode);
}

int WebSearchExtractor::htmldecode_full(char *src, char *dest)
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
				if(i < (strlength-12) &&src[i]=='5'   &&src[i+1]=='C'  && src[i+2]=='%' 
				   && src[i+3]=='5'   &&src[i+4]=='C' && src[i+5]=='r' &&src[i+6]=='%'
				   && src[i+7]=='5'   &&src[i+8]=='C' && src[i+9]=='%' && src[i+10]=='5'
				   && src[i+11]=='C'  && src[i+12]=='n' )
				{
					dest[j]=10;
					i=i+12;
					flag=0;
					j++;
					break;
				}
				if(i < (strlength-20)  && src[i]=='5'    && src[i+1]=='C'  && src[i+2]=='%' 
				     && src[i+3]=='2'  && src[i+4]=='2'  && src[i+5]=='%'  && src[i+6]=='2'
				     && src[i+7]=='C'  && src[i+8]=='%'  && src[i+9]=='5'  && src[i+10]=='C' 
				     && src[i+11]=='%' && src[i+12]=='2' && src[i+13]=='2' && src[i+14]=='%' 
				     && src[i+15]=='5' && src[i+16]=='C' && src[i+17]=='%' && src[i+18]=='5'
				     && src[i+19]=='C' && src[i+20]=='n')
				{
					dest[j]=10;
					i=i+20;
					flag=0;
					j++;
					break;
				}
				if(i < (strlength-10) &&src[i]=='5' &&src[i+1]=='C' && src[i+2]=='%' && 
					src[i+3]=='5' &&src[i+4]=='C'  &&src[i+5]=='%'
				   && src[i+6]=='5' &&src[i+7]=='C' && src[i+8]=='%' && 
					src[i+9]=='5' && src[i+10]=='C' )
				{
					dest[j]='\\';
					i=i+10;
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


// End of file
