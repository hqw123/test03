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

#define LIBCAP_INTFACE   100
#define PFRING_INTERFACE 101

#include <pcap.h>
#include <netinet/if_ether.h>
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
	unsigned  char srcMac[6];
	unsigned  char destMac[6];
	unsigned int   srcIpv4;
	unsigned int   destIpv4;

	unsigned short int srcPort;
	unsigned short int destPort;
	unsigned short int bodyLen;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	enum PacketType pktType;
	char* body;
	char* packet;
	//struct pfring_pkthdr *pkthdr;
	struct pcap_pkthdr_n *pkthdr;
	int  Flag;
	int direction;//in:1 out:2
};
extern PacketInfo g_packetinfo;
extern	unsigned int seq4;
extern	unsigned int ack_seq4;

#endif
