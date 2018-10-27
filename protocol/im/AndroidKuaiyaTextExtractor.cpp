#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidKuaiyaTextExtractor.h"
#define KUAIYA_LOGIN  "PUT \\/dewmobile\\/kuaiya\\/users\\/(\\d*?) HTTP\\/1.1"

AndroidKuaiyaTextExtractor::AndroidKuaiyaTextExtractor()
{
	MLoginRule_ = new boost::regex(KUAIYA_LOGIN);
}

AndroidKuaiyaTextExtractor::~AndroidKuaiyaTextExtractor()
{
	delete MLoginRule_;
}

void AndroidKuaiyaTextExtractor::Push_Action_Message()
{
	Im_MsgNode *imNode = NULL;
	imNode = new Im_MsgNode;
	memset(imNode,0,sizeof(Im_MsgNode));
	ParseMac(pktInfo_->srcMac,imNode->cliMac);
	imNode->cliIpv4 = pktInfo_->srcIpv4;
	imNode->cliPort = pktInfo_->srcPort;
	imNode->msgType = Login;
	imNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	imNode->serIpv4 = pktInfo_->destIpv4;
	imNode->serPort = pktInfo_->destPort;
	imNode->type = 2008;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidKuaiyaTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidkuaiyaText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	
	boost::cmatch matchedStr;
	pktInfo_ = pktInfo;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidkuaiyaText = true;
	}

	return AndroidkuaiyaText;
}

