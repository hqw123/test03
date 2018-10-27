#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidQQTextExtractor.h"

#define QQ_LOGIN   "Host: cdn.ark.qq.com"

AndroidQQTextExtractor::AndroidQQTextExtractor()
{
	MLoginRule_ = new boost::regex(QQ_LOGIN);
}

AndroidQQTextExtractor::~AndroidQQTextExtractor()
{
	delete MLoginRule_;
}

void AndroidQQTextExtractor::Push_Action_Message()
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
	imNode->type = 2001;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidQQTextExtractor::IsImText(PacketInfo* pktInfo)
{

	bool AndroidQQText = false;
	assert(pktInfo != NULL);
	
	boost::cmatch matchedStr;
	pktInfo_ = pktInfo;
    if(pktInfo_->bodyLen == 0)
        return false;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(!strncmp(pktInfo_->body,"GET /arkapp/app_config.json HTTP/1.",35) && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroidQQText = true;
	}

	return AndroidQQText;
}


