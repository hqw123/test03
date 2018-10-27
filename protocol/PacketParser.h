//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BAIHONG Information Security Techology CO.,
//
//------------------------------------------------------------------------
//
// Module Name      :PacketParser.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class PacketParser which is used to 
//      parse the packets from IP layer.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 081212 wuzhonghua Initial
//
//------------------------------------------------------------------------

#ifndef PACKET_PARSER
#define PACKET_PARSER

#include <pcap.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Enumerate the type of each kinds of packet.
enum PacketType
{
	ETH = 0,
	IP,
	TCP,
	UDP,
	GRE,
	NUL
};

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_pkthdr_n {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

// Define a structure to store the information we need from each layer.
struct PacketInfo
{
	unsigned char  srcMac[6];
	unsigned char  destMac[6];
	unsigned int   srcIpv4;
	unsigned int   destIpv4;
	unsigned short srcPort;
	unsigned short destPort;
	unsigned short bodyLen;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	PacketType pktType;
	char* body;
	char* packet;
	const struct pcap_pkthdr_n *pkt;
	int  Flag;
	// The packet body of TCP or UDP
};
extern PacketInfo g_packetinfo;

//-----------------------------------------------------------------------
// Class Name  : PacketParser
// Interface   : Parse, GetPktInfo
// Description : Parse the network packet from data link layer to 
//               transport layer, and collect the necessary information
//               into a structure "PacketInfo".
//-----------------------------------------------------------------------
class PacketParser
{
	public:
		PacketParser();
		virtual ~PacketParser();
		bool Parse(const char* packet);
		void  PacketFilter();
		PacketInfo* GetPktInfo(const char *packet, const struct pcap_pkthdr_n *pkt);
	private:
		bool ParseEth();
		bool ParseIp();
		void ParseTcp();
		void ParseUdp();
		void ParsePPPOE();
        void ParseGre();
		void CleanParser();
	private:
   	// The original packet from network.
		char* packet_;
		struct ethhdr *ethHeader;
		struct pppoe_hdr *pppoeHeader;
		struct iphdr* ipHeader_;
		char* ipBody_;
		struct tcphdr* tcpHeader_;
		struct udphdr* udpHeader_;
		PacketInfo* pktInfo_;
		short int bodyLen_;

        char packet_buff[1514];
};

//-----------------------------------------------------------------------
// Func Name   : GetPktInfo
// Description : Return the structure from packet parsing.
// Parameter   : void
// Return      : const PacketInfo*
//-----------------------------------------------------------------------

#endif
