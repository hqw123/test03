
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>

#include "WangwangTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define LOGIN_TAG   0x00000688
#define LOGIN_TAG2  0x0000
#define LOGIN_TAG3  0x0001
#define LOGIN_TAG4  0x00000100

#define LOGINN_TAG   0x00000688
#define LOGINN_TAG2  0x0001
#define LOGINN_TAG3  0x03000101

#define LEN_TAG     24
#define LOGOUT_TAG  0x00000688
#define LOGOUT_TAG2 0x89000001
#define LOGOUT_TAG3 0x00010000
#define LOGOUT_TAG4 0x00000700
//-----------------------------------------------------------------------
// Func Name   : WangwangTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
WangwangTextExtractor::WangwangTextExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/ALIIM");

	// Create a directory to store the Fetion message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	memcpy(tableName_, "ALIIM", 6);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

//-----------------------------------------------------------------------
// Func Name   : ~WangwangTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
WangwangTextExtractor::~WangwangTextExtractor()
{

}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool WangwangTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isWangwangText = false;
	//assert(pktInfo != NULL);

	if(pktInfo->bodyLen > 204 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body) == LOGIN_TAG &&
	   *reinterpret_cast<const u_short*>(pktInfo->body + 4) == LOGIN_TAG2 &&
	   *reinterpret_cast<const u_short*>(pktInfo->body + 16) == LOGIN_TAG3 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body + 190) == LOGIN_TAG4) 
	{
		int len = *reinterpret_cast<const int*>(pktInfo->body + 195)-1953391360-8;
		if (len <= 0 || len > pktInfo->bodyLen)
			return isWangwangText;
		
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, pktInfo->body + 190 + 6 + 8, len);
		LoginFrom login;
		login.from.assign(str);
		uint64_t key = pktInfo->srcIpv4 + pktInfo->srcPort + pktInfo->destIpv4 + pktInfo->destPort;
		keyMap.insert(pair<uint64_t,LoginFrom>(key,login));
		delete str;
		isWangwangText = true;
	}
	else if(pktInfo->bodyLen > 20 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body) == LOGINN_TAG &&
	   *reinterpret_cast<const u_short*>(pktInfo->body + 4) == LOGINN_TAG2 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body + 16) == LOGINN_TAG3) 
	{
		uint64_t key = pktInfo->srcIpv4 + pktInfo->srcPort + pktInfo->destIpv4 + pktInfo->destPort;
		map<uint64_t,LoginFrom>::iterator it;
		it = keyMap.find(key);
		
		if(it !=keyMap.end())
		{
			pktInfo_ = pktInfo;
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
	
			memcpy(node, pktInfo_, COPY_BYTES);
			node->srcPort = pktInfo_->destPort;
			node->destPort = pktInfo_->srcPort;
			node->srcIpv4 = pktInfo_->destIpv4;
			node->destIpv4 = pktInfo_->srcIpv4;
			node->text=NULL;

			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());

			node->from = from;
			node->to=NULL;
			node->msgType=Login;
			node->time = NULL;
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

			char strmac[20] = {0};
			ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->destIpv4,node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = node->destIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 505;
			node->user=NULL;
			node->pass=NULL;
			node->subject=NULL;
			node->affixFlag=9000;
			node->cc=NULL;
			node->path=NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			isWangwangText = true;
		}
	}
	else if(pktInfo->bodyLen == LEN_TAG &&
	   *reinterpret_cast<const u_int*>(pktInfo->body) == LOGOUT_TAG &&
	   *reinterpret_cast<const u_int*>(pktInfo->body + 4) == LOGOUT_TAG2 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body + 14) == LOGOUT_TAG3 &&
	   *reinterpret_cast<const u_int*>(pktInfo->body + 18) == LOGOUT_TAG4) 
	{
		uint64_t key = pktInfo->srcIpv4 + pktInfo->srcPort + pktInfo->destIpv4 + pktInfo->destPort;
		map<uint64_t,LoginFrom>::iterator it;
		it = keyMap.find(key);
		
		if(it !=keyMap.end())
		{
			pktInfo_ = pktInfo;
			MsgNode* node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
	
			memcpy(node, pktInfo_, COPY_BYTES);
			node->text=NULL;

			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());

			node->from=from;
			node->to=NULL;
			node->msgType = Logout;
			node->time = NULL;
			node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			u_int clueId = 0;

			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = node->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 505;
			node->user=NULL;
			node->pass=NULL;
			node->subject=NULL;
			node->affixFlag=0;
			node->cc=NULL;
			node->path=NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			keyMap.erase(key);
			isWangwangText = true;
		}
	}

	return isWangwangText;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WangwangTextExtractor::StoreMsg2DB(MsgNode* msgNode)
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
