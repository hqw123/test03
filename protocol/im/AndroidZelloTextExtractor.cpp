#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidZelloTextExtractor.h"

#define ZELLO_LOGIN  "zello.com"

AndroidZelloTextExtractor::AndroidZelloTextExtractor()
{

}

AndroidZelloTextExtractor::~AndroidZelloTextExtractor()
{
	
}

void AndroidZelloTextExtractor::Push_Action_Message()
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
	imNode->type = 2022;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidZelloTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidzelloText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	struct  in_addr   dst_ip;
	dst_ip.s_addr = pktInfo_->destIpv4;
	if(!strcmp(inet_ntoa(dst_ip),"184.173.136.144") && pktInfo_->tcp->fin)
	{
		Push_Action_Message();
		AndroidzelloText = true;
	}
	return AndroidzelloText;
}

