
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>

#include "WebTwitterExtractor.h"
#include "Public.h"
#include "clue_c.h"

#define SEND_STATUSES_RULE "POST\\s/1/statuses/update.json\\sHTTP/1(.+)"
#define SENDD_STATUSES_RULE "POST\\s/1/statuses/update.json(.+?);\\stwid=u%3D(\\d+?)%7C(.+?)include_entities=true&status=(.+?)&post_authenticity_token(.+)"
#define SEND_STATUSES_2_RULE "POST\\s/1/statuses/update_with_media.json\\sHTTP/1(.+)"
#define SENDD_STATUSES_2_RULE "POST\\s/1/statuses/update_with_media.json(.+?);\\stwid=u%3D(\\d+?)%7C(.+?)status=(.+?)&media_data(.+)"
#define SEND_RULE "POST\\s/1/direct_messages/new.json\\sHTTP/1(.+)"
#define SENDD_RULE "POST\\s/1/direct_messages/new.json(.+?);\\stwid=u%3D(\\d+?)%7C(.+?)user=(.+?)&text=(.+?)&post_authenticity_token(.+)"
//#define SEND_NEWS_RULE "POST\\s/ajax/messaging/async.php.__a=1\\sHTTP/1(.+)"
//#define SENDD_NEWS_1_RULE "POST\\s/ajax/messaging/async.php(.+?);\\sc_user=(\\d+?);(.+?)&body=(.+?)&action=send&recipients\\[0\\]=(\\d+?)&force_sms=(true|false)(.*)&post_form_id=(.+?)&fb_dtsg(.+)"
//#define SENDD_NEWS_2_RULE "POST\\s/ajax/messaging/async.php(.+?);\\sc_user=(\\d+?);(.+?)&recipients\\[0\\]=(\\d+?)&body=(.+?)&action=send&force_sms=(true|false)&send_on_enter=false(.*)&post_form_id=(.+?)&fb_dtsg(.+)"
//#define UPLOAD_RULE "POST\\s/ajax/messaging/upload.php\\sHTTP/1(.+)"
//#define UPLOADD_RULE "Content-Disposition:\\sform-data;\\sname=\"uploadbutton\"\r\n\r\n"
//#define REPLY_STATUS_RULE "POST\\s/ajax/ufi/modify.php.__a=1\\sHTTP/1(.+)"
//#define REPLYY_STATUS_RULE "POST\\s/ajax/ufi/modify.php(.+?);\\sc_user=(\\d+?);(.+?)%22target_profile_id%22%3A%22(\\d+?)%22(.+?)&add_comment_text=(.+?)&(.+)"
//#define RECV_STATUS_RULE "\"from_uid\":(\\d+?),\"context_id\":(.+?),\"owner\":\"(\\d+?)\",\"text\":\"(.+?)\",\"object_id\":(.+)"
//#define RECV_RULE "for\\s\\(;;\\);\\{\"t\":\"msg\"(.+?)\"ms\":\\[\\{\"msg\":\\{\"text\":\"(.+?)\",\"time\":(.+?)\\},\"from\":(.+?),\"to\":\"(.+?)\",\"from_name\":(.+?)\"from_gender\":1,\"fl\":1,\"to_name\":(.+?)\"type\":\"msg\"\\}\\]\\}"

using namespace std;


WebTwitterExtractor::WebTwitterExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBSNS/Twitter");
	isRunning_ = true;
	isDeepParsing_ = false;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	
	sendRule_ = new boost::regex(SEND_RULE);
	senddRule_ = new boost::regex(SENDD_RULE);
	sendStatusesRule_ = new boost::regex(SEND_STATUSES_RULE);
	senddStatusesRule_ = new boost::regex(SENDD_STATUSES_RULE);
	sendStatuses2Rule_ = new boost::regex(SEND_STATUSES_2_RULE);
	senddStatuses2Rule_ = new boost::regex(SENDD_STATUSES_2_RULE);
	memcpy(tableName_, "WEBSNS", 7);
	
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}


WebTwitterExtractor::~WebTwitterExtractor()
{
	delete sendRule_;
	delete senddRule_;
	delete sendStatusesRule_;
	delete senddStatusesRule_;
	delete sendStatuses2Rule_;
	delete senddStatuses2Rule_;
}

bool WebTwitterExtractor::IsWebSNSText(PacketInfo* pktInfo)
{
	bool iswebFBText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;

	if(boost::regex_match(first, last, matchedStr, *sendRule_)){
//cout<<"/////////////////////sendRule_!!!"<<endl;
		LOG_INFO("/////////////////////sendRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *sendStatusesRule_)){
//cout<<"/////////////////////////sendStatusRule_!!!"<<endl;
		LOG_INFO("/////////////////////////sendStatusRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *sendStatuses2Rule_)){
//cout<<"/////////////////////////sendStatusRule_!!!"<<endl;
		LOG_INFO("/////////////////////////sendStatusRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(ntohl(pktInfo_->tcp->seq) == sendSeq_){
//cout<<"/////////////////////sendSeq_!!!"<<endl;
	LOG_INFO("/////////////////////sendSeq_!!!\n");
//cout<<"sendBodyLen_ = "<<sendBodyLen_<<"pktInfo_->bodyLen = "<<pktInfo_->bodyLen<<endl;
		LOG_INFO("sendBodyLen_ = %d pktInfo_->bodyLen = %d\n",sendBodyLen_,pktInfo_->bodyLen);
		sendBodyLen_ = sendBodyLen_ + pktInfo_->bodyLen;cout<<"sendBodyLen_ = "<<sendBodyLen_<<endl;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = (char *)realloc(sendBody_, sendBodyLen_ + 1);
		strncat(sendBody_, str, pktInfo_->bodyLen);

		const char* firstt = sendBody_;
		const char* lastt = sendBody_ + sendBodyLen_;
		if(boost::regex_search(firstt, lastt, matchedStr, *senddRule_)){
//cout<<"/////////////////////senddRule_!!!"<<endl;
			LOG_INFO("/////////////////////senddRule_!!!\n");
			int len = matchedStr[4].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* to=str;
	
			len = matchedStr[2].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[5].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[5].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);

			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);           // cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                         //cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->to=to;                                 //cout<<"toId = "<<node->toId<<endl;
			LOG_INFO("toId = %s\n",node->toId);
			node->from=NULL;
			node->toId=NULL;
			node->msgType=Text;
			node->contentType=Msg;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_match(firstt, lastt, matchedStr, *senddStatusesRule_)){
//cout<<"/////////////////////////senddStatusesRule_!!!"<<endl;
			LOG_INFO("/////////////////////////senddStatusesRule_!!!\n");
			int len = matchedStr[2].length();
			char *str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[4].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);    // cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                 // cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=NULL;
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=Status;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));

			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_match(firstt, lastt, matchedStr, *senddStatuses2Rule_)){
//cout<<"/////////////////////////senddStatuses2Rule_!!!"<<endl;
			LOG_INFO("/////////////////////////senddStatuses2Rule_!!!\n");
			int len = matchedStr[2].length();
			char *str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[4].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);     //cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=NULL;
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=Status;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));

			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}
		iswebFBText = true;
		pktInfo_ = NULL;
	}
	return iswebFBText;
}


int WebTwitterExtractor::htmldecode_full(char *src, char *dest)
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


//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebTwitterExtractor::StoreMsg2DB(Node* msgNode)
{
	struct in_addr addr;
	char tmp[256];	
	char srcMac[20];


#if 0  //zhangzm webtwitter	
	string sql = "insert into websns(objectid,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,sendname,sendid,replyname,replyid,content,type,attchmentname,datafile)";
	sql+=" values(";
	sprintf(tmp, "%lu", msgNode->clueId);
	sql.append(tmp);
	sql+=",\'";
	addr.s_addr = msgNode->srcIpv4;
	sql+=inet_ntoa(addr);	//CLIENTIP
	sql+="\',\'";

	if(msgNode->affixFlag==9000){
		ParseMac(msgNode->destMac, srcMac);
	}
	else{
		ParseMac(msgNode->srcMac, srcMac);
	}
	sql+=srcMac;	//CLIENTMAC
	sql+="\',";
	sprintf(tmp, "%d", msgNode->srcPort);
	sql+=tmp; 		//CLIENTPORT
	sql+=",\'";
	addr.s_addr = msgNode->destIpv4;
	sql+=inet_ntoa(addr);	//serverip
	sql+="\',";
	sprintf(tmp, "%d",  msgNode->destPort);
	sql+=tmp;		//SERVERPORT
	sql+=",";
	sql+="now()";		//capturetime record currenttime
	sql+=",";
	switch (msgNode->msgType) {
		case Login:
			sprintf(tmp, "%d", 1);
			sql.append(tmp); 
			sql+=",";
			break;
		case Logout:
			sprintf(tmp, "%d", 2);
			sql.append(tmp); 
			sql+=",";
			break;
		case Text:
		case Qun:
		case Dis:
			sprintf(tmp, "%d", 3);
			sql.append(tmp); 
			sql+=",";
			break;
	}
	if (msgNode->text != NULL)
	{
		sql+="\'";
		sql+=msgNode->text; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	if (msgNode->from != NULL)
	{
		sql+="\'";
		sql+= msgNode->from; 	
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->fromId != NULL)
	{
		sql+="\'";
		sql+= msgNode->fromId; 	
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->to != NULL)
	{
		sql+="\'";
		sql+= msgNode->to; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	if (msgNode->toId != NULL)
	{
		sql+="\'";
		sql+= msgNode->toId; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	switch (msgNode->contentType) {
		case Rests:
			sprintf(tmp, "%d", 0);
			sql.append(tmp);
			sql+=",";
			break;
		case Msg:
			sprintf(tmp, "%d", 1);
			sql.append(tmp); 
			sql+=",";
			break;
		case News:
			sprintf(tmp, "%d", 2);
			sql.append(tmp); 
			sql+=",";
			break;
		case Status:
			sprintf(tmp, "%d", 3);
			sql.append(tmp); 
			sql+=",";
			break;
	}
	sprintf(tmp, "%lu", msgNode->protocolType);//TYPE
	sql+=tmp;
	sql+=",";
	if (msgNode->attchmentname != NULL)
	{
		sql+="\'";
		sql+= msgNode->attchmentname;
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->attchmentpath != NULL)
	{
		sql+="\'";
		sql+= msgNode->attchmentpath;
		sql+="\'";
	}
	else 
	{
		sql+="\' \'";
	}
	sql+=")";
	//cout<<"SQL : "<<sql<<endl;
	sqlConn_->Insert(&sql);

//	AddObjectId (msgNode->clueId,srcMac);

// #ifndef VPDNLZ
// 	AddObjectId (msgNode->clueId,srcMac);
// 
// #endif
#endif

	xmlStore_.ClearNode(msgNode);
	LOG_INFO("[WEBFACEBOOK] Data insert into DB!\n");
	//cout<<"[WEBFACEBOOK] Data insert into DB!"<<endl;	
}

// End of file

