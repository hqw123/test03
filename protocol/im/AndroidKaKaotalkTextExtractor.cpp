#include <iostream>
#include "Public.h"
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidKaKaotalkTextExtractor.h"
#define KAKAOTALK_LOGIN  "GET\\s/images/ac/app/(.*?)\\.png HTTP/1.1"

AndroidKaKaotalkTextExtractor::AndroidKaKaotalkTextExtractor()
{
	MLoginRule_ = new boost::regex(KAKAOTALK_LOGIN);
}

AndroidKaKaotalkTextExtractor::~AndroidKaKaotalkTextExtractor()
{
	delete MLoginRule_;
}

void AndroidKaKaotalkTextExtractor::Push_Action_Message()
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
		imNode->type = 2017;
		StoreImDb(imNode);
		delete[] imNode;
}

bool AndroidKaKaotalkTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool AndroidkakaotalkText = false;
    static int num = 0;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(pktInfo_->bodyLen == 0)
		return false;
	if(strstr(pktInfo_->body,"Host: img.talk.kakao.co.kr") && boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
	    num++;
		if(num % 2 == 0)
		{
			num = 0;
			Push_Action_Message();
			AndroidkakaotalkText = true;
		}
	}

	return AndroidkakaotalkText;
}

