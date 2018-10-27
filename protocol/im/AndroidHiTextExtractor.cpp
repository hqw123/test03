#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidHiTextExtractor.h"

AndroidHiTextExtractor::AndroidHiTextExtractor()
{

}

AndroidHiTextExtractor::~AndroidHiTextExtractor()
{

}

void AndroidHiTextExtractor::Push_Action_Message()
{
	Im_MsgNode *imNode = NULL;
	imNode = new Im_MsgNode;
	memset(imNode,0,sizeof(Im_MsgNode));
	ParseMac(pktInfo_->destMac,imNode->cliMac);
	imNode->cliIpv4 = pktInfo_->destIpv4;
	imNode->cliPort = pktInfo_->destPort;
	imNode->msgType = Login;
	imNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	imNode->serIpv4 = pktInfo_->srcIpv4;
	imNode->serPort = pktInfo_->srcPort;
	imNode->type = 2009;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidHiTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidhiText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(!strncmp(pktInfo_->body,"HTTP/1.1 200 OK",15) && strstr(pktInfo_->body,"\"method\":\"user_login\""))
	{
		Push_Action_Message();
		AndroidhiText = true;
	}
	return AndroidhiText;
}

