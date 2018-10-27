#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidLineTextExtractor.h"
#define LINE_LOGIN "engine.mobileapptracking.com"
AndroidLineTextExtractor::AndroidLineTextExtractor()
{
	MLoginRule_ = new boost::regex(LINE_LOGIN);
}

AndroidLineTextExtractor::~AndroidLineTextExtractor()
{
	delete MLoginRule_;
}

void AndroidLineTextExtractor::Push_Action_Message()
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
	imNode->type = 2021;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidLineTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidlineText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	
	boost::cmatch matchedStr;
	pktInfo_ = pktInfo;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort == 443 && *(pktInfo_->body + 5) == 0x01 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidlineText = true;
	}

	return AndroidlineText;
}

