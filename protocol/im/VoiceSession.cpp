#include "VoipExtractor.h"
#include "VoiceSession.h"
#include "../clue/ProtocolID.h"
//#include "../clue/Clue.h"
#include "XmlStorer.h"

IpPair::IpPair(const u_int  srcIp, const u_short srcPort, const u_int  destIp, const u_short destPort)
{
    if (srcIp < destIp) {
        bigIp     = destIp;
        bigPort   = destPort;
        smallIp   = srcIp;
        smallPort = srcPort;
    } else if (srcIp > destIp) {
        bigIp     = srcIp;
        bigPort   = srcPort;
        smallIp   = destIp;
        smallPort = destPort;
    } else if (srcPort < destPort) {
        bigIp     = destIp;
        bigPort   = destPort;
        smallIp   = srcIp;
        smallPort = srcPort;
    } else {
        bigIp     = srcIp;
        bigPort   = srcPort;
        smallIp   = destIp;
        smallPort = destPort;
    }
}

bool IpPair::operator <(const IpPair& ipPair) const
{
    if (bigIp < ipPair.bigIp) {
        return true;
    } else if (bigIp > ipPair.bigIp){
        return false;
    } else if (smallIp < ipPair.smallIp) {
        return true;
    } else if (smallIp > ipPair.smallIp) {
        return false;
    } else if (bigPort < ipPair.bigPort) {
        return true;
    } else if (bigPort == ipPair.bigPort) {
        return smallPort < ipPair.smallPort;
    }

    return false;
}


#include <time.h>
#include <assert.h>
#include <iostream>
#include <arpa/inet.h>

using namespace std;

const int VOIP_MTU = 1600;
const u_int RTP_SAV_NUM = 32768;
const u_int MAX_WRONG_NUM = 4;

VoiceSession::VoiceSession(void* obj, const char* filePath) 
                                                  : rtpNum_(0),
                                                    voiceDumper_(NULL),
                                                    srcIp_(0),
                                                    srcPort_(0),
                                                    isComing_(true)
{
    //assert(obj != NULL);
    //assert(filePath != NULL);
    obj_ = obj;
    filePath_ = filePath;
}

VoiceSession::~VoiceSession()
{
    ClosePcapFile();
}

bool VoiceSession::AddPacket(RtpPkt* rtpPkt)
{
    if (rtpNum_ > RTP_BUF_NUM) {
        pcap_dump((u_char*) voiceDumper_, &(rtpPkt->pktHdr), (const u_char*) (rtpPkt->packet));
        ++rtpNum_;
        if (rtpNum_ >= RTP_SAV_NUM) {
            goto out;
        }
    } else if (rtpNum_ == RTP_BUF_NUM) {
        if (!IsNextPkt(rtpPkt) || !CreatePcapFile()) {
            goto out;
        }
        memcpy(srcMac_, rtpPkt->srcMac, 6);
        memcpy(destMac_, rtpPkt->destMac, 6);
        pcap_dump((u_char*) voiceDumper_, &(rtpPkt->pktHdr), (const u_char*) (rtpPkt->packet));
        ++rtpNum_;
    } else if (rtpNum_ == 0) {
        memcpy(&lastComingRtp_, rtpPkt->rtpHdr, sizeof(rtphdr));
        srcIp_ = rtpPkt->srcIpv4;
        srcPort_ = rtpPkt->srcPort;
        destIp_ = rtpPkt->destIpv4;
        destPort_ = rtpPkt->destPort;
        ++rtpNum_;
    } else {
        if (!IsNextPkt(rtpPkt)) {
            goto out;
        } else if (isComing_) {
            ++rtpNum_; 
        }
    }

    delete rtpPkt;
    return true;

out:
    delete rtpPkt;
    return false;
}

bool VoiceSession::IsNextPkt(RtpPkt* rtpPkt)
{
    if (rtpPkt->srcIpv4 == srcIp_ && rtpPkt->srcPort == srcPort_) {
        isComing_ = true;
        if ((rtpPkt->rtpHdr->source == lastComingRtp_.source) && 
            (ntohs(rtpPkt->rtpHdr->seq) - ntohs(lastComingRtp_.seq) == 1)) {
            memcpy(&lastComingRtp_, rtpPkt->rtpHdr, sizeof(rtphdr));
            return true;
        } else {
            return false;
        }
    } else {
        isComing_ = false;
        return true;
    }

    return true;
}

bool VoiceSession::CreatePcapFile()
{
    time_t currentTime;
    time(&currentTime);
    sprintf(fileName_, 
            "%s/%lu-%u_%lu-%u_%lu.pcap\0",
            filePath_,
            srcIp_,
            srcPort_,
            destIp_,
            destPort_,
            currentTime);
    voiceDumper_ = pcap_dump_open(pcap_open_dead(DLT_EN10MB, VOIP_MTU), fileName_);
    if (!voiceDumper_) {
       // cout << "Create pcap file " << fileName_ << " failed!" << endl;
       LOG_ERROR("Create pcap file %s failed\n",fileName_);
        return false;
    }

    return true;
}

const u_int MIN_RTP_PKT = 1024;

void VoiceSession::ClosePcapFile()
{
    if (voiceDumper_) {
        pcap_dump_close(voiceDumper_);
        if (rtpNum_ < MIN_RTP_PKT) {
            ::remove(fileName_);
        } else {
            SaveMsg();
        }
        voiceDumper_ = NULL;
    }
}

void VoiceSession::SaveMsg()
{
    MsgNode* msgNode = new MsgNode;
    memset(msgNode, 0, sizeof(MsgNode));
    msgNode->msgType = Text;
    msgNode->from = NULL;
    msgNode->to = NULL;
    msgNode->text = NULL;
    msgNode->time = NULL;
    time(&msgNode->timeVal);
    msgNode->path = new char[FILE_NAME_LEN];
    memcpy(msgNode->path, fileName_, FILE_NAME_LEN);
    memcpy(msgNode->srcMac, srcMac_, 6);
    memcpy(msgNode->destMac, destMac_, 6);
    msgNode->srcIpv4 = srcIp_;
    msgNode->destIpv4 = destIp_;
    msgNode->srcPort = srcPort_;
    msgNode->destPort = destPort_;
	char strmac[20];
	memset(strmac,0,20);
	ParseMac(srcMac_,strmac);
	if (!(msgNode->clueId = GetClueId(PROTOCOL_VOIP, strmac, srcIp_)))
	{
		memset(strmac,0,20);
		ParseMac(destMac_,strmac);
		msgNode->clueId = GetClueId(PROTOCOL_VOIP, strmac,destIp_);
	}
    VoipExtractor* voipExtractor = reinterpret_cast<VoipExtractor*>(obj_);
    voipExtractor->SaveMsg(msgNode);
}

// End of file
