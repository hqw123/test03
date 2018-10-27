#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidOovooTextExtractor.h"

AndroidOovooTextExtractor::AndroidOovooTextExtractor()
{

}

AndroidOovooTextExtractor::~AndroidOovooTextExtractor()
{
	
}

void AndroidOovooTextExtractor::Push_Action_Message()
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
	imNode->type = 2014;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidOovooTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidOOVOOText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(!strncmp(pktInfo_->body + 4,"id=\'bind_1\' type=\'result\'",25) && strstr(pktInfo_->body,"@im1.oovoo.com"))
	{
		Push_Action_Message();
		AndroidOOVOOText = true;
	}
	return AndroidOOVOOText;
}

