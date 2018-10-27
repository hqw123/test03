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
typedef enum PacketType
{
	ETH = 0,
	IP,
	TCP,
	UDP,
	//SOCKS,
	NUL
}PacketType;

// Define a structure to store the information we need from each layer.
typedef struct PacketInfo
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
	PacketType pktType;
	char* body;
	char* packet;
	const struct pcap_pkthdr_n *pkt;
	int  Flag;
	int direction;//in:1 out:2
	// The packet body of TCP or UDP
}PacketInfo;
//-----------------------------------------------------------------------

#endif
