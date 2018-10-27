
#include <map>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>

#include "WebQQExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define PORT_BITS 16

#define SENDPOST_RULE "^POST\\s/channel/send_(.+)pt2gguin=o0?(\\d+?);(.+)"
//2.0"^POST\\s/channel/send_(.+)uin=o0([0-9]{5,})(.+)"
//uin=o0([0-9]\\{5,\\})(.+)"
#define SENDDQUNMSG_RULE "r=%7B%22group_uin%22%3A([0-9]*)%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)"
#define SENDQUNMSG_RULE ".*r=%7B%22group_uin%22%3A([0-9]*)%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)(%5C%5Cn%5C|%5C)%22%2C%5B%5C%22font(.+)"
//2.0"^r=%7B%22group_uin%22%3A([0-9]*)%2C%22content%22%3A%22%5B%5C%22(.+)%5C%22%2C%5B%5C%22font(.+)"
//"(\\d+);\\w+;\\w+;\\w+;(.\\d+;\\w+;\\w+;\\w+;)?(\\w+);(\\d+);([^;]+?);(.+;)?"
#define SENDD_RULE "r=%7B%22to%22%3A([0-9]*)%2C%22face%22%3A([0-9]*)%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)"
// #define SEND_RULE ".*r=%7B%22to%22%3A([0-9]*)%2C%22face%22%3A([0-9]*)%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)(%5C%5Cn%5C|%5C)%22%2C%5B%5C%22font(.+)"
#define SEND_RULE ".*r=%7B%22to%22%3A([0-9]*)%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)(%5C%5Cn%5C|%5C)%22%2C%5B%5C%22font(.+)"
//2.0"^r=%7B%22to%22%3A([0-9]*)%2C%22face%22%3A([0-9]*)%2C%22content%22%3A%22%5B%5C%22(.+)%5C%22%2C%5B%5C%22font(.+)"
//"(\\d+);(\\d+);(\\d+);(\\w+);(\\d+);(\\w+);(\\d+);(.*?);(.+;)?"
#define SENDDDIS_RULE "r=%7B%22did%22%3A%22([0-9]*)%22%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)"
#define SENDDIS_RULE "r=%7B%22did%22%3A%22([0-9]*)%22%2C%22content%22%3A%22(%5B|%5B%5B)%5C%22(.+?)(%5C%5Cn%5C|%5C)%22%2C%5B%5C%22font(.+)"
//{"poll_type":"message","value":{"msg_id":17274,"from_uin":189094021,"to_uin":1194436381,"msg_id2":603862,"msg_type":9,"reply_ip":2887223633,"time":1305768210,"content":[["font",{"size":9,"color":"6a6a6a","style":[0,0,0],"name":"\u5B8B\u4F53"}],"123"],"raw_content":"123"}}
#define RECVMSG_RULE "\\{\"poll_type\":\"message\",\"value\":\\{(.+?)\"to_uin\":(\\d+?),(.+?)\"name\"(.+?)\\}\\],(\"?)(.+)(\"|\\])\\]\\}\\}"
//"\\{\"poll_type\":\"message\",\"value\":\\{(.+?)\"to_uin\":(\\d+?),(.+?)\"name\"(.+?)\\}\\],(\"?)(.+?)(\"|\\])\\],\"raw_content\":\"(.+?)\"\\}\\}"
//2.0"^HTTP/1.1\\s200\\sOK\r\nServer:\\semwebqq(.+)\\{\"retcode\":0,\"result\":\\[\\{\"poll_type\":\"message\",(.+)\"to_uin\":([0-9]*)(.+)\"name\"(.+)\"\\}\\],\"(.+)\"\\],\"raw_content\":\"(.+)\"\\}\\}\\]\\}(.+)"
//"^HTTP/1.1\\s200\\sOK\r\nContent-Type:\\stext/html;\\scharset=utf-8\r\nCache-Control:\\sprivate\r\nServer:\\sTENCENT_HTTP_Server\r\nContent-Length:\\s(\\d+)\r\n\r\n(\\d+);(\\w+);(\\w+);(\\d+);(\\w+);(\\w+);(\\w+);([^;]+?);(\\w+[\u4e00-\u9fa5]*?;)?\\d+;\\d+;$"
//recive qq qun msg
#define RECVQUNMSG_RULE "\\{\"poll_type\":\"group_message\",\"value\":\\{(.+?)\"to_uin\":(\\d+?),(.+?)\"info_seq\":(\\d+?),(.+?)\\}\\],(\"?)(.+?)(\"|\\])\\]\\}\\}"
//2.0"^HTTP/1.1\\s200\\sOK\r\nServer:\\semwebqq(.+)\\{\"retcode\":0,\"result\":\\[\\{\"poll_type\":\"group_message\",(.+)\"to_uin\":([0-9]*),(.+)\"info_seq\":([0-9]*),(.+)\"\\}\\],\"(.+)\"\\]\\}\\}\\]\\}(.+)"
//"^HTTP/1.1\\s200\\sOK\r\nContent-Type:\\stext/html;\\scharset=utf-8\r\nCache-Control:\\sprivate\r\nServer:\\sTENCENT_HTTP_Server\r\nContent-Length:\\s\\d+\r\n\r\n(\\d+);\\w+;\\w+;\\w+;\\w+;\\w+;\\w+;([^;]+?);(\\w+[\u4e00-\u9fa5]*?;)?\\d+;(\\d+);(\\d+);\\d+;\\d+;\\d+;\\d+;$"
#define RECVDISMSG_RULE "\\{\"poll_type\":\"discu_message\",\"value\":\\{(.+?)\"to_uin\":(\\d+?),(.+?)\"info_seq\":(\\d+?),(.+?)\\}\\],(\"?)(.+?)(\"|\\])\\]\\}\\}"

#define RECV_RULE "^HTTP/1.1\\s200\\sOK\r\n(.*?)\\{\"retcode\":0,\"result\":\\[(.+)\\]\\}\r\n"
#define LOGIN_RULE "^HTTP/1.1\\s200\\sOK\r\n(.+)Server:\\sTencent\\sLogin\\sServer/2.0.0\r\nSet-Cookie:\\spt2gguin=o0?(\\d+?);(.+)"
//2.0"^GET\\s/login.+?u=(\\w+?)&p=(.+)"
// #define ONLINE_RULE "GET\\s/channel/get_online_buddies2.clientid=(\\d+?)&psessionid=(.+?)&t=(\\d+?)\\sHTTP/1.1\r\n(.+);\\spt2gguin=o0?(\\d+?);(.+)"
#define ONLINE_RULE "^GET\\s/check_sig\\?pttype=1&uin=(\\d+)&.+"
//#define LOGOUT_RULE "^GET\\s/check.+?uin=(\\w+?)&appid=(.+)"
#define MINILOGOUT_RULE "^GET\\s/channel/logout2\?.+\\suin=o0?(\\d+?);(.+)"
//2.0"^GET\\s/channel/logout2\?(.+)\\spt2gguin=o0([0-9]*);(.+)"
//"(\\d+);\\w+;\\w+;\\w+;(.\\d+;\\w+;\\w+;\\w+;)?(\\d);"
// #define OFFLINE_RULE "GET\\s/channel/change_status2.newstatus=offline&clientid=(.+?);\\spt2gguin=o0?(\\d+?);(.+)"
#define OFFLINE_RULE "^GET\\s/collect.*?subject=&nrnd=(\\d+)&rnd"

using namespace std;
set<string> chatset;

WebQQExtractor::WebQQExtractor()
{ 
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBIM/WebQQ");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_WEBPAGECHAT;
    // Create a directory to store the webqq message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	
	loginRule_ = new boost::regex(LOGIN_RULE);
	onlineRule_ = new boost::regex(ONLINE_RULE);
	//logoutRule_ = new boost::regex(LOGOUT_RULE);
	recvMsgRule_ = new boost::regex(RECVMSG_RULE);
	sendPostRule_ = new boost::regex(SENDPOST_RULE);
	sendRule_ = new boost::regex(SEND_RULE);
	sendQunRule_ = new boost::regex(SENDQUNMSG_RULE);
	sendDisRule_ = new boost::regex(SENDDIS_RULE);
	senddRule_ = new boost::regex(SENDD_RULE);
	senddQunRule_ = new boost::regex(SENDDQUNMSG_RULE);
	senddDisRule_ = new boost::regex(SENDDDIS_RULE);
	recvQunMsgRule_ = new boost::regex(RECVQUNMSG_RULE);
	recvDisMsgRule_ = new boost::regex(RECVDISMSG_RULE);
	recvRule_ = new boost::regex(RECV_RULE);
	minilogoutRule_ = new boost::regex(MINILOGOUT_RULE);
	offlineRule_ = new boost::regex(OFFLINE_RULE);

	sendSrcIpv4_ = 0;
	sendSeq_ = -1;
	sendBody_ = NULL;
	sendBodyLen_ = 0;
	isWebqq_ = 0;

	memcpy(tableName_, "WEBIM", 6);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}


WebQQExtractor::~WebQQExtractor()
{
	delete loginRule_;
	delete onlineRule_;
	//delete logoutRule_;
	delete recvMsgRule_;
	delete sendRule_;
	delete sendQunRule_;
	delete sendDisRule_;
	delete senddRule_;
	delete senddQunRule_;
	delete senddDisRule_;
	delete recvQunMsgRule_;
	delete recvDisMsgRule_;
	delete recvRule_;
	delete minilogoutRule_;
	delete offlineRule_;

}

bool WebQQExtractor::IsWebIMText(PacketInfo* pktInfo)
{
	bool iswebqqText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	//webqq login
	if(strstr(pktInfo_->body, "web.qq.com") || strstr(pktInfo_->body, "web2.qq.com"))
	{
		isWebqq_ = 1;
	}
	if(strstr(pktInfo_->body, "Content-Encoding: gzip\r\n") && isWebqq_ == 1)
	{
		int length = 0;
		char *p = strstr(pktInfo_->body, "\r\nContent-Length:");
		if (p == NULL)
			return 0;
		p += 17;
		while( *p != '\r') {
			if(*p != ' ')
				length = length * 10 + (*p - '0');
			p++;
		}
		if (length > 0)
		{
			p=strstr(pktInfo_->body,"\r\n\r\n");
			if(p==NULL)
				return -1;
			p+=4;
			char *data;
			data=(char *)malloc(500000);
			memset(data,0,500000);
			memcpy(data,p,length);
			char *dest = NULL;
			int result = decomp_gzip(data, length - 2, &dest);
			if (result == -1) 
			{
				//fprintf(stderr, "webmail:analyse_gmail_recive: decomp_zip return error!\n");
				return -1;
			}
			free(data);
			data = dest;       //cout<<"data = \n"<<data<<endl;
			dest = NULL;
			dest = strdup("HTTP/1.1 200 OK\r\n");
			dest = (char *)realloc(dest,strlen(dest)+strlen(data)+1);
			strcat(dest,data);
			
			pktInfo_->bodyLen = strlen(data)+17;//cout<<"strlen(data) = "<<strlen(data)<<endl;
			pktInfo_->body = NULL;
			pktInfo_->body = dest;//cout<<"pktInfo_->body = \n"<<pktInfo_->body<<endl;
		}
		isWebqq_ = 0;
	}
	else if(!strncmp(pktInfo_->body, "HTTP/1.1 200 OK\r\n",17) && isWebqq_ == 1)
		isWebqq_ = 0;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;

	if(boost::regex_search(first, last, matchedStr, *onlineRule_))
	{
		//cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!webqqonline!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
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
		
		node->protocolType = 601;
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
		iswebqqText = true;
		
		
	}
	else if(boost::regex_match(first, last, matchedStr, *recvRule_))
	{
//cout<<"recvRule_////////////"<<endl;
		int len = matchedStr[2].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);//cout<<"str = \n"<<str<<endl;

		boost::cmatch matchedStrr;
		if(boost::regex_search(str, matchedStrr, *recvMsgRule_) || boost::regex_search(str, matchedStrr, *recvQunMsgRule_) || boost::regex_search(str, matchedStrr, *recvDisMsgRule_)){
			for(;strlen(str)>225;)
			{
				if(boost::regex_search(str, matchedStrr, *recvMsgRule_)){
//cout<<"recvMsgRule_////////////"<<endl;
					if(matchedStrr[2].length()<5){
						iswebqqText = false;
					}else{
						int lenn = matchedStrr[2].length();
						char* strr = new char[lenn + 1];
						strr[lenn] = 0;
						memcpy(strr, matchedStrr[2].first, lenn);
						char* to=strr;
						Node* node = new Node;
						memset(node, 0, sizeof(Node));
							// Copy basic data to message node
						memcpy(node, pktInfo_, COPY_BYTES);
						node->to=to;
				
						node->srcIpv4=pktInfo_->destIpv4;
						node->srcPort=pktInfo_->destPort;
						node->destIpv4=pktInfo_->srcIpv4;
						node->destPort=pktInfo_->srcPort;
							
						lenn=matchedStrr[6].length();
						strr = new char[lenn + 1];
						strr[lenn] = 0;
						memcpy(strr, matchedStrr[6].first, lenn);
						char* text=strr;
						clear_tag(text);
						transferMean(text);
						node->text=text;
				
						node->from=NULL;
						node->msgType=Text;
						node->time = NULL;
						//time(&node->timeVal);
						node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
						u_int clueId=0;
						
						node->protocolType = 601;
						char strmac[20] = {0};
						ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
						clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
						//clueId = GetObjectId(strmac);
						struct in_addr addr;
						addr.s_addr = pktInfo_->destIpv4;
						clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
						node->clueId = clueId;
						node->fileName = NULL;
						node->affixFlag = 9000;
						StoreMsg2DB(node);
						iswebqqText = true;
						str = str + matchedStrr[0].length();
					}
				}
				else if(boost::regex_search(str, matchedStrr, *recvQunMsgRule_))
				{
//cout<<"recvQunMsgRule_////////////"<<endl;
					int lenn = matchedStrr[2].length();
					char* strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[2].first, lenn);
					char* to=strr;
					Node* node = new Node;
					memset(node, 0, sizeof(Node));
					// Copy basic data to message node
					memcpy(node, pktInfo_, COPY_BYTES);
					node->to=to;
			
					node->srcIpv4=pktInfo_->destIpv4;
					node->srcPort=pktInfo_->destPort;
					node->destIpv4=pktInfo_->srcIpv4;
					node->destPort=pktInfo_->srcPort;
			
					lenn=matchedStrr[4].length();
					strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[4].first, lenn);
					char* qunNum=strr;
			
					char* send=new char[matchedStrr[4].length()+7];
					sprintf(send,"group-%s\0",qunNum);
					
					node->from=send;
	
					lenn=matchedStrr[7].length();
					strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[7].first, lenn);
					char* text=strr;
					clear_tag(text);
					transferMean(text);
					node->text=text;
				
					node->msgType=Qun;
					node->time = NULL;
					//time(&node->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId=0;
			
					node->protocolType = 601;
					char strmac[20] = {0};
					ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
					clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					node->clueId = clueId;
					node->fileName = NULL;
					node->affixFlag = 9000;
					StoreMsg2DB(node);
					iswebqqText = true;
					str = str + matchedStrr[0].length();
				}
				else if(boost::regex_search(str, matchedStrr, *recvDisMsgRule_))
				{
//cout<<"recvDisMsgRule_////////////"<<endl;
					int lenn = matchedStrr[2].length();
					char* strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[2].first, lenn);
					char* to=strr;
					Node* node = new Node;
					memset(node, 0, sizeof(Node));
					// Copy basic data to message node
					memcpy(node, pktInfo_, COPY_BYTES);
					node->to=to;
			
					node->srcIpv4=pktInfo_->destIpv4;
					node->srcPort=pktInfo_->destPort;
					node->destIpv4=pktInfo_->srcIpv4;
					node->destPort=pktInfo_->srcPort;
			
					lenn=matchedStrr[4].length();
					strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[4].first, lenn);
					char* disNum=strr;
			
					char* send=new char[matchedStrr[4].length()+7];
					sprintf(send,"discu-%s\0",disNum);
					
					node->from=send;
					lenn=matchedStrr[7].length();
					strr = new char[lenn + 1];
					strr[lenn] = 0;
					memcpy(strr, matchedStrr[7].first, lenn);
					char* text=strr;
					clear_tag(text);
					transferMean(text);
					node->text=text;
				
					node->msgType=Dis;
					node->time = NULL;
					//time(&node->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId=0;
			
					node->protocolType = 601;
					char strmac[20] = {0};
					ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
					clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					node->clueId = clueId;
					node->fileName = NULL;
					node->affixFlag = 9000;
					StoreMsg2DB(node);
					iswebqqText = true;
					str = str + matchedStrr[0].length();
				}
			}
		}
		pktInfo_ = NULL;
	}
	else if(boost::regex_match(first, last, matchedStr, *minilogoutRule_) || boost::regex_match(first, last, matchedStr, *offlineRule_))
	{
//cout<<"begin_minilogoutRule:///////"<<endl;

		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Logout;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;

		node->protocolType = 601;
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
		keyMap.clear();
		iswebqqText = true;

	}
	else
	{
		uint64_t key = pktInfo_->srcIpv4;
			 key = key << PORT_BITS;
			 key += pktInfo_->srcPort;
		map<uint64_t,char*>::iterator it;
		it = keyMap.find(key);
		int t=0;
		if(boost::regex_match(first,last, matchedStr, *sendPostRule_))
		{
//cout<< "begin_sendPostRule:///////////////" << endl;
			int len = matchedStr[2].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first,len);
			char *from = str;
			keyMap.insert(pair<uint64_t ,char*>(key,from));
	
//cout<< "end_sendPostRule://////////////" <<endl;		
			iswebqqText = true;
		}
		it = keyMap.find(key);
		if(it !=keyMap.end() )
		{
			char *from=it->second;
			if(boost::regex_match(first,last, matchedStr, *sendRule_))
			{
//cout<<"begin_senRule_://////////"<<endl;
				
				Node *node=new Node;
				memset(node, 0, sizeof(Node));
				memcpy(node,pktInfo_, COPY_BYTES);

				node->from=from;
				node->to=NULL;
				node->msgType = Text;
				node->time = NULL;
				//time(&node ->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;
				node->protocolType = 601;
				node->fileName = NULL;
	
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
					
				int len = matchedStr[3].length();
				char *str = new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[3].first, len);
				node->text = new char [1500];
				memset(node->text,0,1500);
				char* text = str;
				htmldecode_full(text,node->text);
				delete[] text;
				node->affixFlag = 0;
				StoreMsg2DB(node);
				pktInfo_ = NULL;
				iswebqqText = true;
			}
			else if(boost::regex_match(first,last, matchedStr, *sendQunRule_))
			{
//cout<< "begin_sendQunRule://///////////" <<endl;

				Node *node=new Node;
				memset(node, 0, sizeof(Node));
				memcpy(node,pktInfo_, COPY_BYTES);
		
				node->from=from;
				node->to=NULL;
				node->msgType = Qun;
				node->time = NULL;
				//time(&node ->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;
				node->protocolType = 601;
				node->fileName = NULL;
	
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

				int len = matchedStr[3].length();
				char *str = new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[3].first, len);
				node->text = new char [1500];
				memset(node->text,0,1500);
				char* text = str;
				htmldecode_full(text,node->text);
				delete[] text;
				node->affixFlag = 0;
				StoreMsg2DB(node);
				pktInfo_ = NULL;
				iswebqqText = true;
			}
			else if(boost::regex_match(first,last, matchedStr, *sendDisRule_))
			{
//cout<< "begin_sendDisRule://///////////" <<endl;

				Node *node=new Node;
				memset(node, 0, sizeof(Node));
				memcpy(node,pktInfo_, COPY_BYTES);
		
				node->from=from;
				node->to=NULL;
				node->msgType = Dis;
				node->time = NULL;
			//	time(&node ->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;
				node->protocolType = 601;
				node->fileName = NULL;
	
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
					
				int len = matchedStr[3].length();
				char *str = new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[3].first, len);
				node->text = new char [1500];
				memset(node->text,0,1500);
				char* text = str;
				htmldecode_full(text,node->text);
				delete[] text;
				node->affixFlag = 0;
				StoreMsg2DB(node);
				pktInfo_ = NULL;
				iswebqqText = true;
			}
			else if((boost::regex_match(first,last, matchedStr, *senddRule_) && strstr(matchedStr[4].first, "%5C%22%2C%5B%5C%22font") == NULL) ||
				(boost::regex_match(first,last, matchedStr, *senddQunRule_) && strstr(matchedStr[3].first, "%5C%22%2C%5B%5C%22font") == NULL) ||
				(boost::regex_match(first,last, matchedStr, *senddDisRule_) && strstr(matchedStr[3].first, "%5C%22%2C%5B%5C%22font") == NULL))
			{//cout<<"begin_senddDisRule://///////////" <<endl;
				sendSrcIpv4_ = pktInfo_->srcIpv4;
				sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
				sendBodyLen_ = pktInfo_->bodyLen;
				char* str = new char[pktInfo_->bodyLen + 1];
				str[pktInfo_->bodyLen] = 0;
				memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
				sendBody_ = str;
	
				pktInfo_ = NULL;
				iswebqqText = true;
			}
			else if(ntohl(pktInfo_->tcp->seq) == sendSeq_ && pktInfo_->srcIpv4 == sendSrcIpv4_)
			{//cout<<"begin_sendddddddddddddDisRule://///////////" <<endl;
				sendBodyLen_ = sendBodyLen_ + pktInfo_->bodyLen;
				sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
				char* st = new char[pktInfo_->bodyLen + 1];
				st[pktInfo_->bodyLen] = 0;
				memcpy(st, pktInfo_->body, pktInfo_->bodyLen);
				sendBody_ = (char *)realloc(sendBody_, strlen(sendBody_) + pktInfo_->bodyLen + 1);
				strncat(sendBody_, st, pktInfo_->bodyLen);
				boost::cmatch matchedStrr;
				const char* firstt = sendBody_;
				const char* lastt = sendBody_ + sendBodyLen_;
				if(boost::regex_search(firstt, lastt, matchedStrr, *sendRule_))
				{//cout<<"begin_send://///////////" <<endl;
					Node *node=new Node;
					memset(node, 0, sizeof(Node));
					memcpy(node,pktInfo_, COPY_BYTES);
			
					node->from=from;//cout<<"node->from = "<<node->from<<endl;
					node->to=NULL;
					node->msgType = Text;
					node->time = NULL;
					//time(&node ->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId = 0;
					node->protocolType = 601;
					node->fileName = NULL;
			
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
						
					int len = matchedStrr[4].length();
					char *str = new char[len + 1];
					str[len] = 0;
					memcpy(str, matchedStrr[4].first, len);
					node->text = new char [150000];
					memset(node->text,0,150000);
					char* text = str;
					htmldecode_full(text,node->text);//cout<<"node->text = "<<node->text<<endl;
					delete[] text;
					node->affixFlag = 0;
					StoreMsg2DB(node);
					pktInfo_ = NULL;
					iswebqqText = true;
					sendSrcIpv4_ = 0;
					sendSeq_ = -1;
					sendBody_ = NULL;
					sendBodyLen_ = 0;
				}
				else if(boost::regex_match(firstt,lastt, matchedStrr, *sendQunRule_))
				{//cout<< "begin_sendQunRule_://///////////" <<endl;
					Node *node=new Node;
					memset(node, 0, sizeof(Node));
					memcpy(node,pktInfo_, COPY_BYTES);
			
					node->from=from;
					node->to=NULL;
					node->msgType = Qun;
					node->time = NULL;
					//time(&node ->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId = 0;
					node->protocolType = 601;
					node->fileName = NULL;
		
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
					
					int len = matchedStrr[3].length();
					char *str = new char[len + 1];
					str[len] = 0;
					memcpy(str, matchedStrr[3].first, len);
					node->text = new char [150000];
					memset(node->text,0,150000);
					char* text = str;
					htmldecode_full(text,node->text);
					delete[] text;
					node->affixFlag = 0;
					StoreMsg2DB(node);
					pktInfo_ = NULL;
					iswebqqText = true;
					sendSrcIpv4_ = 0;
					sendSeq_ = -1;
					sendBody_ = NULL;
					sendBodyLen_ = 0;
				}
				else if(boost::regex_match(firstt,lastt, matchedStrr, *sendDisRule_))
				{//cout<< "begin_sendDisRule_://///////////" <<endl;
					Node *node=new Node;
					memset(node, 0, sizeof(Node));
					memcpy(node,pktInfo_, COPY_BYTES);
			
					node->from=from;
					node->to=NULL;
					node->msgType = Dis;
					node->time = NULL;
					//time(&node ->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId = 0;
					node->protocolType = 601;
					node->fileName = NULL;
		
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
						
					int len = matchedStrr[3].length();
					char *str = new char[len + 1];
					str[len] = 0;
					memcpy(str, matchedStrr[3].first, len);
					node->text = new char [150000];
					memset(node->text,0,150000);
					char* text = str;
					htmldecode_full(text,node->text);
					delete[] text;
					node->affixFlag = 0;
					StoreMsg2DB(node);
					pktInfo_ = NULL;
					iswebqqText = true;
					sendSrcIpv4_ = 0;
					sendSeq_ = -1;
					sendBody_ = NULL;
					sendBodyLen_ = 0;
				}
			}
		}
	}
	return iswebqqText;
}		


int WebQQExtractor::htmldecode_full(char *src, char *dest)
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

int WebQQExtractor::char_to_int(char x)
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

int WebQQExtractor::str_to_int(char str[4])
{
   int sum=0;
   int i;
   for(i=0;i<4; i++)
   sum=sum*16+char_to_int(str[i]);
   return sum;
    
}

int  WebQQExtractor::clear_tag(char *str)
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

int WebQQExtractor::transferMean(char *str)
{
	char *head=NULL,*end=NULL;
	if(str==NULL) return 0;
	head=str;
	end=head;
	while(*head!='\0'){
		if((*head=='\\') && *(head+1)=='0') *(end++)=0,head+=2;
		if((*head=='\\') && *(head+1)=='a') *(end++)=7,head+=2;
		if((*head=='\\') && *(head+1)=='b') *(end++)=8,head+=2;
		if((*head=='\\') && *(head+1)=='t') *(end++)=9,head+=2;
		if((*head=='\\') && *(head+1)=='n') *(end++)=10,head+=2;
		if((*head=='\\') && *(head+1)=='v') *(end++)=11,head+=2;
		if((*head=='\\') && *(head+1)=='f') *(end++)=12,head+=2;
		if((*head=='\\') && *(head+1)=='r') *(end++)=13,head+=2;
		if((*head=='\\') && *(head+1)=='e') *(end++)=27,head+=2;
		if((*head=='\\') && *(head+1)=='\\')
		{ 
			*(end++)='\\';
			head+=2;
		}
		if(end<head) *end=*head;
				end++;
				head++;
	}
	*end='\0';
}

int WebQQExtractor::decomp_gzip(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip ...\n");
	int res;
	char tmp[201];
	int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Bytef*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Bytef*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK) {
			//fprintf(stderr, "webmail:decomp_gzip(): decompressing gzip error\n");
			has_error = 1;
			break;
		} else {
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) {
				*dest = (char*)malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} else {
				*dest = (char*)realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
				strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error) {
		if (!is_first)
			free(*dest);
		*dest = NULL;
		//printf("decomp_gzip complete Error ...\n");
		return -1;
	} else {
		//printf("decomp_gzip complete Ok ...\n");
		return 0;
	}
}
//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebQQExtractor::StoreMsg2DB(Node* msgNode)
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

