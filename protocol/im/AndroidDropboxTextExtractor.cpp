#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidDropboxTextExtractor.h"
#define DROPBOX_LOGIN  "api.dropbox.com"

AndroidDropboxTextExtractor::AndroidDropboxTextExtractor()
{
	MLoginRule_ = new boost::regex(DROPBOX_LOGIN);
}

AndroidDropboxTextExtractor::~AndroidDropboxTextExtractor()
{
	delete MLoginRule_;
}

void AndroidDropboxTextExtractor::Push_Action_Message()
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
	imNode->type = 2024;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidDropboxTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroiddropboxText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if(pktInfo_->bodyLen == 0)
		return false;

	boost::cmatch matchedStr;
	pktInfo_ = pktInfo;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->destPort == 443 && *(pktInfo_->body + 5) == 0x01 && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
		Push_Action_Message();
		AndroiddropboxText = true;
	}

	return AndroiddropboxText;
}
