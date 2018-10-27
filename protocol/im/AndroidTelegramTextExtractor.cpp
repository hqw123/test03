#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidTelegramTextExtractor.h"

#define TELEGRAM_LOGIN  "track.mediav.com"

AndroidTelegramTextExtractor::AndroidTelegramTextExtractor()
{

}

AndroidTelegramTextExtractor::~AndroidTelegramTextExtractor()
{
	
}

void AndroidTelegramTextExtractor::Push_Action_Message()
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
	imNode->type = 2006;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidTelegramTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidtelegramText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	struct  in_addr   dst_ip;
	dst_ip.s_addr = pktInfo_->destIpv4;
	if(!strcmp(inet_ntoa(dst_ip),"91.108.56.170") && pktInfo_->destPort == 443 && pktInfo_->tcp->fin)
	{
		Push_Action_Message();
		AndroidtelegramText = true;
	}
	
	return AndroidtelegramText;
}

