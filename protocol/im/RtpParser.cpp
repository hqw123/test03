//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 RYing Information Security Techology CO., Ltd.
// This program belongs to RYing ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise RYing    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:        RtpParser.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class RtpParser.
// 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090710 Zhao Junzhe Initial
//
//------------------------------------------------------------------------

#include <iostream>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "Public.h"
#include "RtpParser.h"
#include "../ProtocolID.h"
//#include "../clue/Clue.h"

using namespace std;

// Lenth of header of IP
#define IP_HLEN(iphdr)(4 * iphdr->ihl)
// Lenth of header of TCP
#define TCP_HLEN(tcphdr)(4 * tcphdr->doff)
// Lenth of header of UDP
const u_int UDP_HLEN = 8;
const u_int MIN_RTP_LEN = 64;
const u_int MIN_RTP_DATA_LEN = 25;
const u_char RTP_TAG = 0x80;

RtpParser::RtpParser()
{
    offsetNum_ = 6;
    offsetArray_[0] = 0;     // Regular voice
    offsetArray_[1] = 2;     // Gtalk voice
    offsetArray_[2] = 6;     // QQ voice
    offsetArray_[3] = 15;    // QQ voice
    offsetArray_[4] = 18;    // QQ voice
    offsetArray_[5] = 99;    // POPO voice
}

RtpParser::~RtpParser()
{
}

RtpPkt* RtpParser::Parse(PacketInfo* packetInfo)
{
    if (!packetInfo) {
        LOG(ERROR, "Packet is NULL! Parse the next packet.");
        return NULL;
    } else if (packetInfo->pkt->caplen != packetInfo->pkt->len || packetInfo->pkt->len < MIN_RTP_LEN) {
        return NULL;
    }
    bodyLen_ = packetInfo->bodyLen;
    switch (packetInfo->pktType) {
        case UDP: 
        case TCP: {
            if (packetInfo->srcPort < 1024 || packetInfo->destPort < 1024) {   // No any voice session below TCP port 1024
                return NULL;
            }
            break;
        }
        default:
            return NULL;
    }
    if (!ParseRtp(packetInfo->body)) {
        return NULL;
    }
    //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Is Rtp" << endl;
	char strmac[20];
	memset(strmac,0,20);
	ParseMac(packetInfo->srcMac,strmac);
	if (!GetClueId(PROTOCOL_VOIP, strmac,packetInfo->srcIpv4)
			&& !GetClueId(PROTOCOL_VOIP, strmac,packetInfo->srcIpv4))  // 有问题 。
	{
        //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Not Clue" << endl;
      return NULL;
    }
    RtpPkt* rtpPkt = new RtpPkt;
    memcpy(rtpPkt, packetInfo, COPY_BYTES);
    rtpPkt->offset = offset_;
    memcpy(&(rtpPkt->pktHdr), packetInfo->pkt, sizeof(pcap_pkthdr_n));
    memcpy(rtpPkt->packet, packetInfo->packet, packetInfo->pkt->len);
    rtpPkt->rtpHdr = reinterpret_cast<rtphdr*>(rtpPkt->packet + ((const char*)rtpHdr_ - packetInfo->packet));

    return rtpPkt;
}

/*
RtpPkt* RtpParser::Parse(pcap_pkthdr_n* pktHdr, const char* packet)
{
    if (!pktHdr || !packet) {
        LOG(ERROR, "Packet is NULL! Parse the next packet.");
        return NULL;
    } else if (pktHdr->caplen != pktHdr->len || pktHdr->len < MIN_RTP_LEN) {
        return NULL;
    // Parse on IP layer.
    } else if (!ParseIp(packet)) {
        return NULL;
    }
    RtpPkt* rtpPkt = new RtpPkt;
    rtpPkt->srcIpv4 = srcIpv4_;
    rtpPkt->destIpv4 = destIpv4_;
    rtpPkt->srcPort = srcPort_;
    rtpPkt->destPort = destPort_;
    rtpPkt->offset = offset_;
    memcpy(&(rtpPkt->pktHdr), pktHdr, sizeof(pcap_pkthdr_n));
    if (pktHdr->len < 1600) {
        memcpy(rtpPkt->packet, packet, pktHdr->len);
    }
    rtpPkt->rtpHdr = reinterpret_cast<rtphdr*>(rtpPkt->packet + ((const char*)rtpHdr_ - packet));

    return rtpPkt;
}
*/
bool RtpParser::ParseIp(const char* packet)
{
    const iphdr* ipHeader = reinterpret_cast<const struct iphdr*>(packet + ETH_HLEN);
    const char* ipBody = reinterpret_cast<const char*>(ipHeader) + IP_HLEN(ipHeader);
    bodyLen_ = ntohs(ipHeader->tot_len) - IP_HLEN(ipHeader);
    switch (ipHeader->protocol) {
        case IPPROTO_TCP: {
            const tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(ipBody);
            srcPort_ = ntohs(tcpHeader->source);
            destPort_ = ntohs(tcpHeader->dest);
            if (srcPort_ < 1024 || destPort_ < 1024) {   // No any voice session below TCP port 1024
                return false;
            }
            bodyLen_ = bodyLen_ - TCP_HLEN(tcpHeader);
            if (!ParseRtp(reinterpret_cast<const char*>(tcpHeader) + TCP_HLEN(tcpHeader))) {
                return false;
            }
            break;
        }
        case IPPROTO_UDP: {
            const udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(ipBody);
            srcPort_ = ntohs(udpHeader->source);
            destPort_ = ntohs(udpHeader->dest);
            if (srcPort_ < 2048 || destPort_ < 2048) {   // No any voice session below UDP port 2048
                return false;
            }
            bodyLen_ = bodyLen_ - UDP_HLEN;
            if (!ParseRtp(reinterpret_cast<const char*>(udpHeader) + UDP_HLEN)) {
                return false;
            }
            break;
        }
        default:
            return false;
    }
    srcIpv4_ = ipHeader->saddr;
    destIpv4_ = ipHeader->daddr;

    return true;
}

bool RtpParser::ParseRtp(const char* body)
{
    for (int i = 0; i < offsetNum_; ++i) {
        if ((bodyLen_ > offsetArray_[i] + MIN_RTP_DATA_LEN) && (*reinterpret_cast<const u_char*>(body + offsetArray_[i]) == RTP_TAG)) {
            rtpHdr_ = reinterpret_cast<const rtphdr*>(body + offsetArray_[i]);
            if (CanDecode(offsetArray_[i])) {
                offset_ = offsetArray_[i];
                return true;
            }
        }
    }

    return false;
}

bool RtpParser::CanDecode(u_short offset)
{
    if (offset == 99 && rtpHdr_->ptype != 0x67) {
        return false;
    }
    switch (rtpHdr_->ptype) {
        case 0x00:
        case 0x03:      // Flow down!
        case 0x04:
        case 0x08:
        case 0x09:
        case 0x0d:
        case 0x12:
        case 0x31:
        case 0x60:
        case 0x61:
        case 0x62:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
        case 0x69:
        case 0x6a:
        case 0x6c:
        case 0x6d:
        case 0x6e:
        case 0x6f:
        case 0x70:
        case 0x71:
        case 0x73:
        case 0x74:
        case 0x75:
        case 0x76:
        case 0x77:
        case 0x79:
            return true;
        default:
            return false;
    }

    return false;
}

// End of file
