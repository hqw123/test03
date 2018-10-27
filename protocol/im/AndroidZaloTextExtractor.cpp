#include <iostream>
#include "Public.h"
#include <boost/regex.hpp>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AndroidZaloTextExtractor.h"


AndroidZaloTextExtractor::AndroidZaloTextExtractor()
{
   
}

AndroidZaloTextExtractor::~AndroidZaloTextExtractor()
{

}

void AndroidZaloTextExtractor::Push_Action_Message()
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
	imNode->type = 2015;
	StoreImDb(imNode);
	delete[] imNode;
}

bool AndroidZaloTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidzaloText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
    boost::cmatch matchedStr;
	if(pktInfo_->bodyLen == 0)
		return false;

    const char* first = pktInfo_->body;	
    const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(!strncmp(pktInfo_->body,"GET /api/resource/getLink",25) && strstr(pktInfo_->body,"Host: res.conf.zaloapp.com"))
	{
		Push_Action_Message();
		AndroidzaloText = true;
	}
	return AndroidzaloText;
}

