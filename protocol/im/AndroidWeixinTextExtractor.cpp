#include "AndroidWeixinTextExtractor.h"
#include "Public.h"
#include <iostream>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WEIXIN_LOGIN "mp.weixin.qq.com"

AndroidWeixinTextExtractor::AndroidWeixinTextExtractor()
{
	MLoginRule_ = new boost::regex(WEIXIN_LOGIN);
}

AndroidWeixinTextExtractor::~AndroidWeixinTextExtractor()
{
	delete MLoginRule_;
}

void AndroidWeixinTextExtractor::Push_Action_Message()
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
	imNode->type = 2002;
	StoreImDb(imNode);
	delete[] imNode;
}
bool AndroidWeixinTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidWeixinText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort == 53 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidWeixinText = true;
	}

	return AndroidWeixinText;
}

