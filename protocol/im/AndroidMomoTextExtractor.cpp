#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidMomoTextExtractor.h"

#define MOMO_LOGIN  "live-api.immomo.com"
AndroidMomoTextExtractor::AndroidMomoTextExtractor()
{
	MLoginRule_ = new boost::regex(MOMO_LOGIN);
}

AndroidMomoTextExtractor::~AndroidMomoTextExtractor()
{
	delete MLoginRule_;
}

void AndroidMomoTextExtractor::Push_Action_Message()
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
	imNode->type = 2012;
	StoreImDb(imNode);
	delete[] imNode;
}
bool AndroidMomoTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidMOMOText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo->destPort == 53 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidMOMOText = true;
	}

	return AndroidMOMOText;
}