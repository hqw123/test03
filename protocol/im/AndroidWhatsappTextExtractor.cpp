#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidWhatsappTextExtractor.h"
#define WHARSAPP_LOGIN  "e(\\d*?).whatsapp.net"

AndroidWhatsappTextExtractor::AndroidWhatsappTextExtractor()
{
	MLoginRule_ = new boost::regex(WHARSAPP_LOGIN);
}

AndroidWhatsappTextExtractor::~AndroidWhatsappTextExtractor()
{
	delete MLoginRule_;
}

void AndroidWhatsappTextExtractor::Push_Action_Message()
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
	imNode->type = 2004;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidWhatsappTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidwhatsappText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort== 53 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidwhatsappText = true;
	}

	return AndroidwhatsappText;
}

