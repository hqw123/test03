#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidSkypeTextExtractor.h"

#define SKYPE_LOGIN  "api.cc.skype.com"

AndroidSkypeTextExtractor::AndroidSkypeTextExtractor()
{
	MLoginRule_ = new boost::regex(SKYPE_LOGIN);
}

AndroidSkypeTextExtractor::~AndroidSkypeTextExtractor()
{
	delete MLoginRule_;
}

void AndroidSkypeTextExtractor::Push_Action_Message()
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
	imNode->type = 2025;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidSkypeTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidskypeText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;	
	
	boost::cmatch matchedStr;
	if(pktInfo_->bodyLen == 0)
		return false;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort == 443 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidskypeText = true;
	}
	
	return AndroidskypeText;
}

