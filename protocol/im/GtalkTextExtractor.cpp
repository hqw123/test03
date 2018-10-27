
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>

#include "GtalkTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define SET_RULE   "<iq\\stype=.set.\\sid=.0.><bind\\sxmlns=.+?><resource>Talk.v\\w+?</resource></bind></iq>"
#define LOGIN_RULE "<iq\\sid=.0.\\stype=.result.><bind\\sxmlns=.+?><jid>(.+?)@gmail.com.+?</jid></bind></iq>"
#define SEND_RULE  "^<message\\sto=.(.+?)@gmail.com.+?\\stype=.chat.\\sid=.\\w+?.><body>(.+?)<"
#define SENDD_RULE "^<message\\sto=.+?@gmail.com.+?\\stype=.chat.\\sid=.\\w+?.><body>(.+?)"
#define RECV_RULE  "<message\\sto=.(.+?)@gmail.com.+?\\sfrom=.(.+?)@gmail.com.+?><body>(.+?)<"
#define RECVV_RULE "<message\\sto=.+?@gmail.com.+?\\sfrom=.+?@gmail.com.+?><body>(.+?)"
#define ITEM_RULE  "<iq\\sto=.+?\\sfrom=.+?\\sid=.+?\\stype=.+?><nos:query\\sxmlns:nos=.+?>(.+?)</nos:query></iq>"
#define ITEMM_RULE "<nos:item\\sjid=.(.+?@.+?.com).\\svalue=.disabled./>"
#define ID16_RULE  "<iq\\sto=.+?\\sid=.16.\\stype=.result.><query.+?/query></iq>"
/*<iq */
#define LOGIN_TAG   0x2071693c
/*<mes*/
#define SEND_RECV_TAG   0x73656d3c
/*sage*/
#define SEND_RECV_TAG2  0x65676173
/*to="*/
#define SEND_RECV_TAG3  0x223d6f74

#define RECV_LEN 120

//-----------------------------------------------------------------------
// Func Name   : GtalkTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
GtalkTextExtractor::GtalkTextExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/GTALK");

	// Create a directory to store the Fetion message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	setRule_ = new boost::regex(SET_RULE);
	loginRule_ = new boost::regex(LOGIN_RULE);
	sendRule_ = new boost::regex(SEND_RULE);
	recvRule_ = new boost::regex(RECV_RULE);
	senddRule_ = new boost::regex(SENDD_RULE);
	recvvRule_ = new boost::regex(RECVV_RULE);
	id16Rule_ = new boost::regex(ID16_RULE);
	itemRule_ = new boost::regex(ITEM_RULE);
	itemmRule_ = new boost::regex(ITEMM_RULE);

	sendSrcIpv4_ = 0;
	sendSeq_ = -1;
	sendBody_ = NULL;
	sendBodyLen_ = 0;
	recvSrcIpv4_ = 0;
	recvSeq_ = -1;
	recvBody_ = NULL;
	recvBodyLen_ = 0;
	message_int = 0;

	off_line_ = 0;
	len_ = 0;
	f_mes_ = 0;

	memcpy(tableName_, "GTALK", 6);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

//-----------------------------------------------------------------------
// Func Name   : ~GtalkTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
GtalkTextExtractor::~GtalkTextExtractor()
{
	delete setRule_;
	delete loginRule_;
	delete sendRule_;
	delete recvRule_;
	delete senddRule_;
	delete recvvRule_;
	delete id16Rule_;
	delete itemRule_;
	delete itemmRule_;
}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool GtalkTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isGtalkText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;

	if(ntohl(pktInfo_->tcp->seq) == message_recv.next_seq && pktInfo_->srcIpv4 == message_recv.srcIpv4)
	{
		message_recv.seq = ntohl(pktInfo_->tcp->seq);
		message_recv.next_seq = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
	}
	else if(ntohl(pktInfo_->tcp->seq) != message_recv.next_seq && pktInfo_->srcIpv4 == message_recv.srcIpv4)
	{
		int i = 0;
		for(; i<MESSAGE_LEN && message[i] != NULL; i++)
		{
			if(ntohl(message[i]->tcp->seq) == message_recv.next_seq && message[i]->srcIpv4 == message_recv.srcIpv4)
			{
				message_recv.seq = ntohl(message[i]->tcp->seq);
				message_recv.next_seq = ntohl(message[i]->tcp->seq) + message[i]->bodyLen;
			}
		}
		if(message_int < MESSAGE_LEN && message_int == i)
		{
			message[message_int++] = pktInfo_;
		}
	}
	else if(ntohl(pktInfo_->tcp->seq) != message_send.next_seq && pktInfo_->srcIpv4 == message_send.srcIpv4)
	{
		message_send.seq = ntohl(pktInfo_->tcp->seq);
		message_send.next_seq = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
	}
	else if(ntohl(pktInfo_->tcp->seq) != message_send.next_seq && pktInfo_->srcIpv4 == message_send.srcIpv4)
	{
		int i = 0;
		for(; i<MESSAGE_LEN && message[i] != NULL; i++)
		{
			if(ntohl(message[i]->tcp->seq) == message_send.next_seq && message[i]->srcIpv4 == message_send.srcIpv4)
			{
				message_send.seq = ntohl(message[i]->tcp->seq);
				message_send.next_seq = ntohl(message[i]->tcp->seq) + message[i]->bodyLen;
			}
		}
		if(message_int < MESSAGE_LEN && message_int == i)
		{
			message[message_int++] = pktInfo_;
		}
	}

	if(*reinterpret_cast<const u_int*>(pktInfo->body) == LOGIN_TAG) 
	{
		isGtalkText = MatchGtalk();
	}
	else if(*reinterpret_cast<const u_int*>(pktInfo->body) == SEND_RECV_TAG &&
		 *reinterpret_cast<const u_int*>(pktInfo->body + 4) == SEND_RECV_TAG2 &&
		 *reinterpret_cast<const u_int*>(pktInfo->body + 9) == SEND_RECV_TAG3 && off_line_ == 0)
	{
		isGtalkText = MatchGtalk();
	}
	else if(ntohl(pktInfo_->tcp->seq) == sendSeq_ && pktInfo_->srcIpv4 == sendSrcIpv4_)
	{
		if(strstr(pktInfo_->body, "<") != NULL)
		{
			sendBodyLen_ = sendBodyLen_ + pktInfo_->bodyLen;
			sendBody_ = (char *)realloc(sendBody_, strlen(sendBody_) + pktInfo_->bodyLen + 1);
			strncat(sendBody_, pktInfo_->body, pktInfo_->bodyLen);

			boost::cmatch matchedStr;
			const char* first = sendBody_;
			const char* last = sendBody_ + sendBodyLen_;
			if(boost::regex_search(first, last, matchedStr, *sendRule_))
			{
				uint64_t key = pktInfo->srcIpv4 + pktInfo->srcPort + pktInfo->destIpv4 + pktInfo->destPort;
				map<uint64_t,Log>::iterator it;
				it = keyMap.find(key);

				MsgNode* node = new MsgNode;
				memset(node, 0, sizeof(MsgNode));
				// Copy basic data to message node
	
				memcpy(node, pktInfo_, COPY_BYTES);

				int len = matchedStr[2].length();
				char* str = new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[2].first, len);
				char* text = str;
				//cout<<"TEXT:"<<text<<endl;
				LOG_INFO("TEXT:%s\n",text);
				node->text=text;

				string f = it->second.from;
				char* from = new char[f.size()+1];
				from[f.size()] = 0;
				memcpy(from, &f[0], f.size());

				node->from = from;

				len = matchedStr[1].length();
				char* strr = new char[len + 1];
				strr[len] = 0;
				memcpy(strr, matchedStr[1].first, len);
				char* to = strr;
				//cout<<"TO:"<<to<<endl;
				LOG_INFO("TO:%s\n",to);
				node->to = to;
				node->msgType = Text;
				node->time = NULL;
				//time(&node->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;

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
				node->protocolType = 506;
				node->user=NULL;
				node->pass=NULL;
				node->subject=NULL;
				node->affixFlag=0;
				node->cc=NULL;
				node->path=NULL;
				StoreMsg2DB(node);
				pktInfo_ = NULL;
				sendSrcIpv4_ = 0;
				sendSeq_ = -1;
				sendBody_ = NULL;
				sendBodyLen_ = 0;
				//isGtalkText = true;
			}
		}
		else
		{
			sendBodyLen_ = sendBodyLen_ + pktInfo_->bodyLen;
			sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			sendBody_ = (char *)realloc(sendBody_, strlen(sendBody_) + pktInfo_->bodyLen + 1);
			strncat(sendBody_, pktInfo_->body, pktInfo_->bodyLen);
			pktInfo_ = NULL;
			//isGtalkText = true;
		}
		isGtalkText = true;
	}
	else if(ntohl(pktInfo_->tcp->seq) == recvSeq_ && pktInfo_->srcIpv4 == recvSrcIpv4_)
	{
		boost::cmatch matchedStrr;
		const char* firstt = pktInfo_->body;
		const char* lastt = pktInfo_->body + pktInfo_->bodyLen;
		if(strstr(pktInfo_->body, "<") != NULL && off_line_ == 0){
			recvBodyLen_ = recvBodyLen_ + pktInfo_->bodyLen;
			recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + pktInfo_->bodyLen + 1);
			strncat(recvBody_, pktInfo_->body, pktInfo_->bodyLen);

			boost::cmatch matchedStr;
			const char* first = recvBody_;
			const char* last = recvBody_ + recvBodyLen_;
			if(boost::regex_search(first, last, matchedStr, *recvRule_)){
				MsgNode* node = new MsgNode;
				memset(node, 0, sizeof(MsgNode));
				// Copy basic data to message node
	
				memcpy(node, pktInfo_, COPY_BYTES);
				node->srcPort = pktInfo_->destPort;
				node->destPort = pktInfo_->srcPort;
				node->srcIpv4 = pktInfo_->destIpv4;
				node->destIpv4 = pktInfo_->srcIpv4;

				int len = matchedStr[3].length();
				char* str = new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[3].first, len);
				char* text = str;//cout<<"TEXT:"<<text<<endl;
				LOG_INFO("text:%s\n",str);
				node->text=text;

				len = matchedStr[2].length();
				char* strr = new char[len + 1];
				strr[len] = 0;
				memcpy(strr, matchedStr[2].first, len);
				char* from = strr;//cout<<"FROM:"<<from<<endl;
				LOG_INFO("from:%s\n",strr);
				node->from = from;

				len = matchedStr[1].length();
				char* strrr = new char[len + 1];
				strrr[len] = 0;
				memcpy(strrr, matchedStr[1].first, len);
				char* to = strrr;//cout<<"TO:"<<to<<endl;
				LOG_INFO("TO:%s\n",to);
				node->to = to;
				node->msgType = Text;
				node->time = NULL;
				//time(&node->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;

				char strmac[20];
				memset(strmac,0,20);
				ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
				clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				node->clueId = clueId;
				node->fileName = NULL;
				node->protocolType = 506;
				node->user=NULL;
				node->pass=NULL;
				node->subject=NULL;
				node->affixFlag=9000;
				node->cc=NULL;
				node->path=NULL;
				StoreMsg2DB(node);
				pktInfo_ = NULL;
				recvSrcIpv4_ = 0;
				recvSeq_ = -1;
				recvBody_ = NULL;
				recvBodyLen_ = 0;
				isGtalkText = true;
			}
		}else if(strstr(pktInfo_->body, "<") == NULL && off_line_ ==0){
			recvBodyLen_ = recvBodyLen_ + pktInfo_->bodyLen;
			recvSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + pktInfo_->bodyLen + 1);
			strncat(recvBody_, pktInfo_->body, pktInfo_->bodyLen);
			pktInfo_ = NULL;
			isGtalkText = true;
		}else if(off_line_ == 1 && !boost::regex_search(firstt, lastt, matchedStrr, *itemRule_)){
			recvBodyLen_ = recvBodyLen_ + pktInfo_->bodyLen;
			recvSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + pktInfo_->bodyLen + 1);
			strncat(recvBody_, pktInfo_->body, pktInfo_->bodyLen);
			if(strstr(pktInfo_->body, "message") == NULL){
				f_mes_ = 0;
			}
			if(f_mes_ == 1){
				len_ = len_ + pktInfo_->bodyLen;
			}
			pktInfo_ = NULL;
			isGtalkText = true;
		}
	}else if(pktInfo_->tcp->fin == 1){
		uint64_t key = pktInfo->srcIpv4 + pktInfo->srcPort + pktInfo->destIpv4 + pktInfo->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);
		
		if(it !=keyMap.end())
		{
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node

			memcpy(node, pktInfo_, COPY_BYTES);

			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());

			node->from = from;
			node->to=NULL;
			node->msgType=Logout;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

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
			node->protocolType = 506;
			node->user=NULL;
			node->pass=NULL;
			node->subject=NULL;
			node->affixFlag=0;
			node->cc=NULL;
			node->path=NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			keyMap.erase(key);

			message_send.srcIpv4 = 0;
			message_send.seq = -1;
			message_send.next_seq = -1;
			message_recv.srcIpv4 = 0;
			message_recv.seq = -1;
			message_recv.next_seq = -1;
			message_int = 0;
			for(int i=0; i<MESSAGE_LEN; i++){message[i] = NULL;}
			isGtalkText = true;
		}
	}
	for(int i=0; i<MESSAGE_LEN && message[i] != NULL; i++){
		if(ntohl(message[i]->tcp->seq) == sendSeq_ && message[i]->srcIpv4 == sendSrcIpv4_){
			if(strstr(message[i]->body, "<") != NULL){
				sendBodyLen_ = sendBodyLen_ + message[i]->bodyLen;
				sendBody_ = (char *)realloc(sendBody_, strlen(sendBody_) + message[i]->bodyLen + 1);
				strncat(sendBody_, message[i]->body, message[i]->bodyLen);

				boost::cmatch matchedStr;
				const char* first = sendBody_;
				const char* last = sendBody_ + sendBodyLen_;
				if(boost::regex_search(first, last, matchedStr, *sendRule_)){
					uint64_t key = message[i]->srcIpv4 + message[i]->srcPort + message[i]->destIpv4 + message[i]->destPort;
					map<uint64_t,Log>::iterator it;
					it = keyMap.find(key);

					MsgNode* node = new MsgNode;
					memset(node, 0, sizeof(MsgNode));
					// Copy basic data to message node
	
					memcpy(node, message[i], COPY_BYTES);

					int len = matchedStr[2].length();
					char* str = new char[len + 1];
					str[len] = 0;
					memcpy(str, matchedStr[2].first, len);
					char* text = str;//cout<<"TEXT:"<<text<<endl;
					LOG_INFO("TEXT:%s\n",text);
					node->text=text;

					string f = it->second.from;
					char* from = new char[f.size()+1];
					from[f.size()] = 0;
					memcpy(from, &f[0], f.size());

					node->from = from;

					len = matchedStr[1].length();
					char* strr = new char[len + 1];
					strr[len] = 0;
					memcpy(strr, matchedStr[1].first, len);
					char* to = strr;//cout<<"TO:"<<to<<endl;
					LOG_INFO("TO:%s\n",to);
					node->to = to;
					node->msgType = Text;
					node->time = NULL;
					//time(&node->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId = 0;

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
					node->protocolType = 506;
					node->user=NULL;
					node->pass=NULL;
					node->subject=NULL;
					node->affixFlag=0;
					node->cc=NULL;
					node->path=NULL;
					StoreMsg2DB(node);
					sendSrcIpv4_ = 0;
					sendSeq_ = -1;
					sendBody_ = NULL;
					sendBodyLen_ = 0;
					isGtalkText = true;
				}
			}else if(strstr(message[i]->body, "<") == NULL && message[i]->body != NULL){
				sendBodyLen_ = sendBodyLen_ + message[i]->bodyLen;
				sendSeq_ = ntohl(message[i]->tcp->seq) + message[i]->bodyLen;
				sendBody_ = (char *)realloc(sendBody_, strlen(sendBody_) + message[i]->bodyLen + 1);
				strncat(sendBody_, message[i]->body, message[i]->bodyLen);
				isGtalkText = true;
			}
		}else if(ntohl(message[i]->tcp->seq) == recvSeq_ && message[i]->srcIpv4 == recvSrcIpv4_){
			boost::cmatch matchedStrr;
			const char* firstt = message[i]->body;
			const char* lastt = message[i]->body + message[i]->bodyLen;
			if(strstr(message[i]->body, "<") != NULL && off_line_ == 0){
				recvBodyLen_ = recvBodyLen_ + message[i]->bodyLen;
				char* st = new char[message[i]->bodyLen + 1];
				st[message[i]->bodyLen] = 0;
				memcpy(st, message[i]->body, message[i]->bodyLen);
				recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + message[i]->bodyLen + 1);
				strncat(recvBody_, st, message[i]->bodyLen);

				boost::cmatch matchedStr;
				const char* first = recvBody_;
				const char* last = recvBody_ + recvBodyLen_;
				if(boost::regex_search(first, last, matchedStr, *recvRule_)){
					MsgNode* node = new MsgNode;
					memset(node, 0, sizeof(MsgNode));
					// Copy basic data to message node
	
					memcpy(node, pktInfo_, COPY_BYTES);
					node->srcPort = message[i]->destPort;
					node->destPort = message[i]->srcPort;
					node->srcIpv4 = message[i]->destIpv4;
					node->destIpv4 = message[i]->srcIpv4;

					int len = matchedStr[3].length();
					char* str = new char[len + 1];
					str[len] = 0;
					memcpy(str, matchedStr[3].first, len);
					char* text = str;//cout<<"TEXT:"<<text<<endl;
					LOG_INFO("TEXT:%s\n",text);
					node->text=text;

					len = matchedStr[2].length();
					char* strr = new char[len + 1];
					strr[len] = 0;
					memcpy(strr, matchedStr[2].first, len);
					char* from = strr;//cout<<"FROM:"<<from<<endl;
					LOG_INFO("FROM:%s\n",from);
					node->from = from;

					len = matchedStr[1].length();
					char* strrr = new char[len + 1];
					strrr[len] = 0;
					memcpy(strrr, matchedStr[1].first, len);
					char* to = strrr;//cout<<"TO:"<<to<<endl;
					LOG_INFO("TO:%s\n",to);
					node->to = to;
					node->msgType = Text;
					node->time = NULL;
					//time(&node->timeVal);
					node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					u_int clueId=0;

					char strmac[20] = {0};
					ParseMac(pktInfo_->destMac,strmac);
#ifdef VPDNLZ
					clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					node->clueId = clueId;
					node->fileName = NULL;
					node->protocolType = 506;
					node->user=NULL;
					node->pass=NULL;
					node->subject=NULL;
					node->affixFlag=9000;
					node->cc=NULL;
					node->path=NULL;
					StoreMsg2DB(node);
					recvSrcIpv4_ = 0;
					recvSeq_ = -1;
					recvBody_ = NULL;
					recvBodyLen_ = 0;
					isGtalkText = true;
				}
			}else if(strstr(message[i]->body, "<") == NULL && off_line_ == 0){
				recvBodyLen_ = recvBodyLen_ + message[i]->bodyLen;
				recvSeq_ = ntohl(message[i]->tcp->seq) + message[i]->bodyLen;
				recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + message[i]->bodyLen + 1);
				strncat(recvBody_, message[i]->body, message[i]->bodyLen);
				isGtalkText = true;
			}else if(off_line_ == 1 && !boost::regex_search(firstt, lastt, matchedStrr, *itemRule_)){
				recvBodyLen_ = recvBodyLen_ + message[i]->bodyLen;
				recvSeq_ = ntohl(message[i]->tcp->seq) + message[i]->bodyLen;
				recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + message[i]->bodyLen + 1);
				strncat(recvBody_, message[i]->body, message[i]->bodyLen);
				if(strstr(message[i]->body, "message") == NULL){
					f_mes_ = 0;
				}
				if(f_mes_ == 1){
					len_ = len_ + message[i]->bodyLen;
				}
				isGtalkText = true;
			}
		}
	}

	return isGtalkText;
}

//-----------------------------------------------------------------------
// Func Name   : MatchGtalk
// Description : The function matches the packet if is belong to Gtalk.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool GtalkTextExtractor::MatchGtalk()
{
	bool matched = false;	

	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;

	if (boost::regex_search(first, last, matchedStr, *setRule_)) {
		message_send.srcIpv4 = pktInfo_->srcIpv4;
		message_send.seq = ntohl(pktInfo_->tcp->seq);
		message_send.next_seq = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
	}
	if (boost::regex_search(first, last, matchedStr, *loginRule_)) {
		message_recv.srcIpv4 = pktInfo_->srcIpv4;
		message_recv.seq = ntohl(pktInfo_->tcp->seq);
		message_recv.next_seq = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;

		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from =str;

		Log log;
		log.from = from;
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		keyMap.insert(pair<uint64_t,Log>(key,log));

		MsgNode* node = new MsgNode;
		memset(node, 0, sizeof(MsgNode));
		// Copy basic data to message node
	
		memcpy(node, pktInfo_, COPY_BYTES);
		node->srcPort = pktInfo_->destPort;
		node->destPort = pktInfo_->srcPort;
		node->srcIpv4 = pktInfo_->destIpv4;
		node->destIpv4 = pktInfo_->srcIpv4;

		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId = 0;

		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac,strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->protocolType = 506;
		node->user=NULL;
		node->pass=NULL;
		node->subject=NULL;
		node->affixFlag=9000;
		node->cc=NULL;
		node->path=NULL;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
        matched = true;
	}
	else if (boost::regex_search(first, last, matchedStr, *id16Rule_))
	{
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);

		if(it !=keyMap.end())
		{
			recvSrcIpv4_ = pktInfo_->srcIpv4;
			recvSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			recvBodyLen_ = pktInfo_->bodyLen;
			char* str = new char[pktInfo_->bodyLen + 1];
			str[pktInfo_->bodyLen] = 0;
			memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
			recvBody_ = str;
			len_ = pktInfo_->bodyLen;
			pktInfo_ = NULL;
			off_line_ = 1;
			f_mes_ = 1;
			matched = true;
		}
	}
	else if (boost::regex_search(first, last, matchedStr, *itemRule_) && off_line_ == 1) 
	{
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);

		if(it !=keyMap.end())
		{
			int len = matchedStr[1].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);

			boost::cmatch matchedStrr;
			for(;boost::regex_search(str, matchedStrr, *itemmRule_);)
			{
				char strmac[20] = {0};
				ParseMac(pktInfo_->destMac, strmac);
				u_int clueId = 0;
#ifdef VPDNLZ
				char pppoe[60];
				clueId = GetObjectId2(pktInfo_->destIpv4, pppoe);
				if (clueId == 0)
					return false;
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				int lenn = matchedStrr[1].length();
				char* strr = new char[lenn+1];
				strr[lenn] = 0;
				memcpy(strr, matchedStrr[1].first, lenn);

				char* item = strr;

				string f = it->second.from;
				char* from = new char[f.size()+1];
				from[f.size()] = 0;
				memcpy(from, &f[0], f.size());
				char* user = from;

				char tmp[256];
				
#if 0  //zhangzm relation_list
				string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
				sql += " values(";
				sql += "\'";
				sql += user;
				sql += "\',";
				u_int type = 506;
				sprintf(tmp, "%lu", type);	//TYPE
				sql += tmp;
				sql += ",\'";
				sql += item;
				sql += "\',";
				sql += "now()";	//capturetime record currenttime
				sql += ",";
				u_int isgroup = 1;
				sprintf(tmp, "%lu", isgroup);
				sql.append(tmp);
				sql += ",";
				sprintf(tmp, "%lu", clueId);
				sql.append(tmp);
				sql += ")";
				sqlConn_->Insert(&sql);
#endif
			//	cout << "[GTALK GroupNum] Data insert into DB!" << endl;
				LOG_INFO("[GTALK GroupNum] Data insert into DB!\n");
				delete item;
				delete user;
			}
			delete str;
			recvBodyLen_ = pktInfo_->bodyLen;
			recvBody_ = (char *)realloc(recvBody_, strlen(recvBody_) + pktInfo_->bodyLen + 1);
			strncat(recvBody_, pktInfo_->body, pktInfo_->bodyLen);
			recvBody_ = recvBody_ + len_;

			boost::cmatch matchedSt;
			for(;boost::regex_search(recvBody_, matchedSt, *recvRule_);)
			{
				MsgNode* node = new MsgNode;
				memset(node, 0, sizeof(MsgNode));
				// Copy basic data to message node

				memcpy(node, pktInfo_, COPY_BYTES);
				node->srcPort = pktInfo_->destPort;
				node->destPort = pktInfo_->srcPort;
				node->srcIpv4 = pktInfo_->destIpv4;
				node->destIpv4 = pktInfo_->srcIpv4;

				int lenn = matchedSt[3].length();
				char* s = new char[lenn + 1];
				s[lenn] = 0;
				memcpy(s, matchedSt[3].first, lenn);
				char* text = s;//cout<<"TEXT:"<<text<<endl;
				LOG_INFO("TEXT:%s\n",text);
				node->text=text;
	
				lenn = matchedSt[2].length();
				char* strr = new char[lenn + 1];
				strr[lenn] = 0;
				memcpy(strr, matchedSt[2].first, lenn);
				char* from = strr;//cout<<"FROM:"<<from<<endl;
				LOG_INFO("FROM:%s\n",from);
				node->from = from;
	
				lenn = matchedSt[1].length();
				char* strrr = new char[lenn + 1];
				strrr[lenn] = 0;
				memcpy(strrr, matchedSt[1].first, lenn);
				char* to = strrr;//cout<<"TO:"<<to<<endl;
				LOG_INFO("TO:%s\n",to);
				node->to = to;
				node->msgType = Text;
				node->time = NULL;
				//time(&node->timeVal);
				node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				u_int clueId = 0;
	
				char strmac[20] = {0};
				ParseMac(pktInfo_->destMac,strmac);
#ifdef VPDNLZ
				clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				node->clueId = clueId;
				node->fileName = NULL;
				node->protocolType = 506;
				node->user=NULL;
				node->pass=NULL;
				node->subject=NULL;
				node->affixFlag=9000;
				node->cc=NULL;
				node->path=NULL;
				StoreMsg2DB(node);
				recvBody_ = recvBody_ + matchedSt[0].length() + RECV_LEN;
			}
			pktInfo_ = NULL;
			recvSrcIpv4_ = 0;
			recvSeq_ = -1;
			recvBody_ = NULL;
			recvBodyLen_ = 0;
			off_line_ = 0;
			matched = true;
		}
	}
	else if (boost::regex_search(first, last, matchedStr, *sendRule_)) 
	{
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);

		if(it !=keyMap.end())
		{
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
	
			memcpy(node, pktInfo_, COPY_BYTES);

			int len = matchedStr[2].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* text = str;//cout<<"TEXT:"<<text<<endl;
			LOG_INFO("TEXT:%s\n",text);
			node->text=text;

			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());

			node->from = from;

			len = matchedStr[1].length();
			char* strr = new char[len + 1];
			strr[len] = 0;
			memcpy(strr, matchedStr[1].first, len);
			char* to = strr;//cout<<"TO:"<<to<<endl;
			LOG_INFO("TO:%s\n",to);
			node->to = to;
			node->msgType = Text;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac,strmac);
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
			node->protocolType = 506;
			node->user=NULL;
			node->pass=NULL;
			node->subject=NULL;
			node->affixFlag=0;
			node->cc=NULL;
			node->path=NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
        	matched = true;
		}
	}else if (boost::regex_search(first, last, matchedStr, *recvRule_)) {

		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);
		if(it !=keyMap.end())
		{
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
	
			memcpy(node, pktInfo_, COPY_BYTES);
			node->srcPort = pktInfo_->destPort;
			node->destPort = pktInfo_->srcPort;
			node->srcIpv4 = pktInfo_->destIpv4;
			node->destIpv4 = pktInfo_->srcIpv4;

			int len = matchedStr[3].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[3].first, len);
			char* text = str;//cout<<"TEXT:"<<text<<endl;
			LOG_INFO("TEXT:%s\n",text);
			node->text=text;

			len = matchedStr[2].length();
			char* strr = new char[len + 1];
			strr[len] = 0;
			memcpy(strr, matchedStr[2].first, len);
			char* from = strr;//cout<<"FROM:"<<from<<endl;
			LOG_INFO("FROM:%s\n",from);
			node->from = from;

			len = matchedStr[1].length();
			char* strrr = new char[len + 1];
			strrr[len] = 0;
			memcpy(strrr, matchedStr[1].first, len);
			char* to = strrr;//cout<<"TO:"<<to<<endl;
			LOG_INFO("TO:%s\n",to);
			node->to = to;
			node->msgType = Text;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

			char strmac[20] = {0};
			ParseMac(pktInfo_->destMac,strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->destIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 506;
			node->user=NULL;
			node->pass=NULL;
			node->subject=NULL;
			node->affixFlag=9000;
			node->cc=NULL;
			node->path=NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
        	matched = true;
		}
	}else if (boost::regex_search(first, last, matchedStr, *senddRule_)&&
		  strstr(matchedStr[1].first, "<") == NULL) {
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);

		if(it !=keyMap.end())
		{
			sendSrcIpv4_ = pktInfo_->srcIpv4;
			sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			sendBodyLen_ = pktInfo_->bodyLen;
			char* str = new char[pktInfo_->bodyLen + 1];
			str[pktInfo_->bodyLen] = 0;
			memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
			sendBody_ = str;

			pktInfo_ = NULL;
			matched = true;
		}
	}else if (boost::regex_search(first, last, matchedStr, *recvvRule_) &&
		  strstr(matchedStr[1].first, "<") == NULL){
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Log>::iterator it;
		it = keyMap.find(key);

		if(it !=keyMap.end())
		{
			recvSrcIpv4_ = pktInfo_->srcIpv4;
			recvSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
			recvBodyLen_ = pktInfo_->bodyLen;
			char* str = new char[pktInfo_->bodyLen + 1];
			str[pktInfo_->bodyLen] = 0;
			memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
			recvBody_ = str;

			pktInfo_ = NULL;
			matched = true;
		}
	}
	return matched;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void GtalkTextExtractor::StoreMsg2DB(MsgNode* msgNode)
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

	xmlStorer_.ClearNode(msgNode);
}


// End of file
