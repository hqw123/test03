#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidAireTalkTextExtractor.h"

AndroidAireTalkTextExtractor::AndroidAireTalkTextExtractor()
{

}

AndroidAireTalkTextExtractor::~AndroidAireTalkTextExtractor()
{

}

void  AndroidAireTalkTextExtractor::Push_Action_Message()
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
	imNode->type = 531;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidAireTalkTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidairetalkText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(!strncmp(pktInfo_->body,"POST /onair/getbuddylist_aire.php HTTP/1.1",42))
	{
		Push_Action_Message();
		AndroidairetalkText = true;
	}
	return AndroidairetalkText;
}

