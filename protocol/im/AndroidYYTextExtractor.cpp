#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidYYTextExtractor.h"

AndroidYYTextExtractor::AndroidYYTextExtractor()
{

}

AndroidYYTextExtractor::~AndroidYYTextExtractor()
{

}

void AndroidYYTextExtractor::Push_Action_Message()
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
	imNode->type = 2007;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidYYTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidyyText = false;	
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(!strncmp(pktInfo_->body,"POST /report.do?act=webudbauthsdk HTTP/1.1",42) && strstr(pktInfo_->body,"Host: rpt.yy.com"))
	{
		Push_Action_Message();
		AndroidyyText = true;
	}
	
	return AndroidyyText;
}

