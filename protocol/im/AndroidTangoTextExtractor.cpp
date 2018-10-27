#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidTangoTextExtractor.h"

AndroidTangoTextExtractor::AndroidTangoTextExtractor()
{

}

AndroidTangoTextExtractor::~AndroidTangoTextExtractor()
{
	
}

void AndroidTangoTextExtractor:: Push_Action_Message()
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
	imNode->type = 2019;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidTangoTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidTangoText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(!strncmp(pktInfo_->body,"GET /potsitron/rest/v1/check_vip_status",39))
	{
		Push_Action_Message();
		AndroidTangoText = true;
	}
	return AndroidTangoText;
}



