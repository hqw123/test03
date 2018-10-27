#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidViberTextExtractor.h"

#define  VIBER_LOGIN  "aloha.viber.com"

AndroidViberTextExtractor::AndroidViberTextExtractor()
{
	MLoginRule_ = new boost::regex(VIBER_LOGIN);
}

AndroidViberTextExtractor::~AndroidViberTextExtractor()
{
	delete MLoginRule_;
}

void AndroidViberTextExtractor:: Push_Action_Message()
{
	Im_MsgNode *imNode = NULL;
	imNode = new Im_MsgNode;
	memset(imNode,0,sizeof(Im_MsgNode));
	ParseMac(pktInfo_->srcMac,imNode->cliMac);
	imNode->cliIpv4 = pktInfo_->srcIpv4;
	imNode->cliPort = pktInfo_->srcPort;
	imNode->msgType = Logout;
	imNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	imNode->serIpv4 = pktInfo_->destIpv4;
	imNode->serPort = pktInfo_->destPort;
	imNode->type = 2020;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidViberTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidviberText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort== 53 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidviberText = true;
	}

	return AndroidviberText;
}

