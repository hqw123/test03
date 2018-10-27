
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidMiliaoTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "Analyzer_log.h"
#include "db_data.h"
#include "function_def.h"

// Regular expression rules.
#define LEN_TAG    30
//#define LOGIN_RULE "^<bind\\sid=.+?to=.xiaomi.com.+?from=.(.+?)@xiaomi.com.+?</bind>\r\n$"
#define LOGIN_RULE "^<bind\\sid=.+?to=.xiaomi.com.+?from=.(.+?)@xiaomi.com.+?</bind>$"

#define SEND_RULE "^<message\\schid=.+?type=.chat.\\sfrom=.(.+?)@xiaomi.com.+?to=.(.+?)@xiaomi.com.+?id=.\\d*."

//-----------------------------------------------------------------------
// Func Name   : MiliaoTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
AndroidMiliaoTextExtractor::AndroidMiliaoTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/Miliao");
    // Create a directory to store the Miliao message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	loginRule_ = new boost::regex(LOGIN_RULE);
    sendrule_ = new boost::regex(SEND_RULE);
    memcpy(tableName_, "MILIAO", 7);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

// Func Name   : ~AndroidMiliaoTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
AndroidMiliaoTextExtractor::~AndroidMiliaoTextExtractor()
{
	delete loginRule_;
}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool AndroidMiliaoTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isMiliaoText = false;
	//assert(pktInfo != NULL);
	if (!CheckPort(pktInfo->srcPort) && !CheckPort(pktInfo->destPort))
		return false;
    
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen > LEN_TAG)
	{
		isMiliaoText = MatchMiliao();
	}
#ifdef CONF_MILIAO_NEED_LOGOUT
	else if(pktInfo_->tcp->fin || pktInfo_->tcp->rst)
	{
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,Miliao_Login>::iterator it;
		it = keyMap.find(key);
		
		if(it != keyMap.end())
		{
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
	
			memcpy(node, pktInfo_, COPY_BYTES);
			if(pktInfo_->srcPort == 5222)
			{
				node->srcPort = pktInfo_->destPort;
				node->destPort = pktInfo_->srcPort;
				node->srcIpv4 = pktInfo_->destIpv4;
				node->destIpv4 = pktInfo_->srcIpv4;
			}
			node->text=NULL;

			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());

			node->from = from;
			node->to = NULL;
			node->msgType = Logout;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

			struct in_addr addr;
			char strmac[20] = {0};
			if(pktInfo_->srcPort == 5222)
			{
				ParseMac(pktInfo_->destMac,strmac);
				addr.s_addr = pktInfo_->destIpv4;
				node->affixFlag = 9000;
			}
			else
			{
				ParseMac(pktInfo_->srcMac,strmac);
				addr.s_addr = pktInfo_->srcIpv4;
				node->affixFlag = 0;
			}
			//clueId = GetObjectId(strmac);
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 508;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			//node->affixFlag=0;
			//if(pktInfo_->srcPort == 5222)
			//	node->affixFlag=9000;
			node->cc = NULL;
			node->path = NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			keyMap.erase(key);
			isMiliaoText = true;
		}
	}
#endif
	
    return isMiliaoText;
}

//-----------------------------------------------------------------------
// Func Name   : MatchMiliao
// Description : The function matches the packet if is belong to Miliao.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool AndroidMiliaoTextExtractor::MatchMiliao()
{
	bool matched = false;
	boost::cmatch matchedStr;
    const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	
	if (boost::regex_search(first, last, matchedStr, *loginRule_))
	{
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from = str;

#ifdef CONF_MILIAO_NEED_LOGOUT
		Miliao_Login log;
		log.from = from;
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		keyMap.insert(pair<uint64_t,Miliao_Login>(key,log));
#endif

		MsgNode* node = new MsgNode;
		memset(node, 0, sizeof(MsgNode));
		
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);

		node->text = NULL;
		node->from = from;
		node->to = NULL;
		node->msgType = Login;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		
		u_int clueId = 0;
		struct in_addr addr;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
		addr.s_addr = pktInfo_->srcIpv4;
		//clueId = GetObjectId(strmac);
		clueId = get_clue_id(strmac, inet_ntoa(addr));
		
		node->clueId = clueId;
		node->fileName = NULL;
		node->protocolType = 508;
		node->user = NULL;
		node->pass = NULL;
		node->subject = NULL;
		node->affixFlag = 0;
		node->cc = NULL;
		node->path = NULL;
		
		StoreMsg2DB(node);
		pktInfo_ = NULL;
        matched = true;
	}
    else if (boost::regex_search(first, last, matchedStr, *sendrule_))
    {
        int len1 = matchedStr[1].length();
		char* send = new char[len1 + 1];
		send[len1] = 0;
		memcpy(send, matchedStr[1].first, len1);
        
        int len2 = matchedStr[2].length();
		char* recv = new char[len2 + 1];
        recv[len2] = 0;
        memcpy(recv, matchedStr[2].first, len2);
       
		MsgNode* node = new MsgNode;
		memset(node, 0, sizeof(MsgNode));
		
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);

		node->text = NULL;
		node->from = send;
		node->to = recv;
		node->msgType = Text;
		node->time = NULL;
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		
		u_int clueId = 0;
		struct in_addr addr;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
		
		node->clueId = clueId;
		node->fileName = NULL;
		node->protocolType = 508;
		node->user = NULL;
		node->pass = NULL;
		node->subject = NULL;
		node->affixFlag = 0;
		node->cc = NULL;
		node->path = NULL;
		
		StoreMsg2DB(node);
		pktInfo_ = NULL;
        matched = true;
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
void AndroidMiliaoTextExtractor::StoreMsg2DB(MsgNode* msgNode)
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

bool AndroidMiliaoTextExtractor::CheckPort(u_short port)
{
	switch (port)
	{
		case 5222:
			return true;
	}
	return false;
}


// End of file
