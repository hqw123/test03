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
// Module Name:        RtpParser.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class RtpParser which is used to 
//      parse the packets from IP layer to RTP layer.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090710 Zhao Junzhe Initial
//
//------------------------------------------------------------------------

#ifndef RTP_PARSER
#define RTP_PARSER

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "PacketInfo.h"

// Head of RTP
struct rtphdr                /* header length = 12 */
{
    uint8_t  tag;            /* rtp tag */
    uint8_t  ptype:7;        /* payload type */
    uint8_t  marker:1;       /* maker */
    uint16_t seq;            /* sequence number */
    uint32_t time;           /* timestamp */
    uint32_t source;         /* source id */
};

struct RtpPkt
{
    u_char srcMac[6];   // 6 bytes
    u_char destMac[6];  // 6 bytes
    u_int srcIpv4;     // 4 bytes
    u_int destIpv4;    // 4 bytes
    u_short srcPort;    // 2 bytes
    u_short destPort;   // 2 bytes
    u_short bodyLen;    // 2 bytes
    // Keep above data sync with PakectInfo struct
    char packet[1600];
    rtphdr* rtpHdr;
    uint16_t offset;
    pcap_pkthdr_n pktHdr;
};

//-----------------------------------------------------------------------
// Class Name  : RtpParser
// Interface   : Parse
// Description : Parse the network packet from data link layer to 
//               RTP layer, and check the packets if are RTP packets.
//-----------------------------------------------------------------------
class RtpParser
{
public:
    RtpParser();
    virtual ~RtpParser();
    RtpPkt* Parse(PacketInfo* packetInfo);
    //RtpPkt* Parse(pcap_pkthdr_n* pktHdr, const char* packet);
private:
    bool ParseIp(const char* packet);
    bool ParseRtp(const char* body);
    bool CanDecode(u_short offset);
private:
    u_short bodyLen_;
    u_short offsetNum_;
    u_short offset_;
    u_short offsetArray_[20];
    u_short srcPort_;
    u_short destPort_;
    u_int srcIpv4_;
    u_int destIpv4_;
    const rtphdr* rtpHdr_;
};

#endif

// End of file
