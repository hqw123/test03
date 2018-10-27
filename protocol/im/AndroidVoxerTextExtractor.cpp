#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidVoxerTextExtractor.h"

#define VOXER_LOGIN "voxer.com"

AndroidVoxerTextExtractor::AndroidVoxerTextExtractor()
{
	MLoginRule_ = new boost::regex(VOXER_LOGIN);
}

AndroidVoxerTextExtractor::~AndroidVoxerTextExtractor()
{
	delete MLoginRule_;
}

void AndroidVoxerTextExtractor::Push_Action_Message()
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
	imNode->type = 2023;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidVoxerTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidvoxerText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;	
	
	boost::cmatch matchedStr;
	pktInfo_ = pktInfo;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->srcPort == 443 && *(pktInfo_->body + 5) == 0x02 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidvoxerText = true;
	}

	return AndroidvoxerText;
}


