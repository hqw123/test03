//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BAIHONG Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     PacketParser.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class PacketParser.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 081127  wu zhonghua Initial
// $d1=----------1.0  002 2010209 wu zhonghua modify GetPktInfo()
//
//------------------------------------------------------------------------
#include <iostream>
  // For mkdir().
#include "PacketParser.h"
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/if_pppox.h>
#include <arpa/inet.h>
#include <sys/socket.h> 
#include <arpa/inet.h>

using namespace std;

// Lenth of header of IP
#define IP_HLEN(iphdr)(4 * iphdr->ihl)
// Lenth of header of TCP
#define TCP_HLEN(tcphdr)(4 * tcphdr->doff)
// Lenth of header of UDP
const int UDP_HLEN = 8;
const int MIN_TCP_HLEN = 20;

struct PacketInfo  g_packetinfo;

//-----------------------------------------------------------------------
// Func Name   : PacketParser
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
PacketParser::PacketParser() : packet_(NULL),
                               ipHeader_(NULL),
			       tcpHeader_(NULL),
			       udpHeader_(NULL),
			       bodyLen_(0)
{
}

//-----------------------------------------------------------------------
// Func Name   : ~PacketParser
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
PacketParser::~PacketParser()
{
    // Do nothing.
}

//-----------------------------------------------------------------------
// Func Name   : CleanParser
// Description : Clean the members. 
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void PacketParser::CleanParser()
{
	ethHeader =NULL;
	packet_ = NULL;
	ipHeader_ = NULL;
	ipBody_ = NULL;
	tcpHeader_ = NULL;
	udpHeader_ = NULL;
	pktInfo_ = NULL;
	bodyLen_ = 0;
}

//-----------------------------------------------------------------------
// Func Name   : Parser
// Description : Parse the packet from network.
// Parameter   : const char*
// Return      : bool
//-----------------------------------------------------------------------
bool PacketParser::Parse(const char* packet)
{
	bool parseOkey = true;
    // Clean the members of class on beginning of each packet parsing.
  /*  CleanParser();
	packet_ = packet;

	if (!packet_) {
	LOG(ERROR, "Packet is NULL! Parse the next packet.");
	parseOkey = false;
    // Parse on IP layer.
} else if (!ParseIp()) {
	parseOkey = false;
}*/

	return parseOkey; 
}

//-----------------------------------------------------------------------
// Func Name   : ParseIp
// Description : Parse the packet on IP layer.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool PacketParser::ParseIp()
{ 
	bool parseOkey = false;
    //ipHeader_ = reinterpret_cast<const struct iphdr*>(packet_ + ETH_HLEN);
	ipBody_ = (char*)(ipHeader_) + IP_HLEN(ipHeader_);
	bodyLen_ = ntohs(ipHeader_->tot_len) - IP_HLEN(ipHeader_);
	switch (ipHeader_->protocol) {
		case IPPROTO_TCP:
			if (bodyLen_ < MIN_TCP_HLEN) {
				break;
			}
			
			tcpHeader_ = ( struct tcphdr*)ipBody_;
			bodyLen_ = bodyLen_ - TCP_HLEN(tcpHeader_);
			if (bodyLen_ <0) {
				break;
			}
			parseOkey=true;
			ParseTcp();
			break;
		case IPPROTO_UDP:
			if (bodyLen_ < UDP_HLEN) {
				break;
			}
			udpHeader_ = ( struct udphdr *)(ipBody_);
			bodyLen_ = bodyLen_ - UDP_HLEN;
			if (bodyLen_ <= 0) {
				break;
			}
			parseOkey=true;
			ParseUdp();
			break;
		default:
      //printf("Uninterested packet, discard it.");
            //LOG(INFO, "Uninterested packet, discard it.");
			break;
	}
	if (parseOkey) {
		g_packetinfo.ip=ipHeader_;
		g_packetinfo.srcIpv4 = ipHeader_->saddr;
		g_packetinfo.destIpv4 = ipHeader_->daddr;
		g_packetinfo.bodyLen=bodyLen_;

	}else {
		g_packetinfo.Flag=0;
	}

	return parseOkey;
}

//-----------------------------------------------------------------------
// Func Name   : ParserTcp
// Description : Parse the packet on TCP layer.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
void PacketParser::ParseTcp()
{
	g_packetinfo.tcp =tcpHeader_;
	g_packetinfo.pktType = TCP;
    // Get the source port and destination port from TCP header.
	g_packetinfo.srcPort = ntohs(tcpHeader_->source);
	g_packetinfo.destPort = ntohs(tcpHeader_->dest);
    // Store the pointer of packet body and lenth of body.
	g_packetinfo.body = ( char * )(tcpHeader_) + TCP_HLEN(tcpHeader_);
}

//-----------------------------------------------------------------------
// Func Name   : ParserUdp
// Description : Parse the packet on UDP layer.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void PacketParser::ParseUdp()
{
	g_packetinfo.pktType = UDP;
    // Get the source port and destination port from UDP header.
	g_packetinfo.srcPort = ntohs(udpHeader_->source);
	g_packetinfo.destPort = ntohs(udpHeader_->dest);
    // Store the pointer of packet body and lenth of body.
	g_packetinfo.body = (char *)(udpHeader_) + UDP_HLEN;
}

struct pppoe_hdr *pppoe=NULL;
void PacketParser::ParsePPPOE()
{
	unsigned short *ppp;
	char *temp=(char *)pppoe;
	temp+=(sizeof(struct pppoe_hdr));
	ppp=(unsigned short *)temp;
	if(ntohs(*ppp)==0xc023|ntohs(*ppp)==0x8021|ntohs(*ppp)==0xc223) //peer-id and password or ipcp or chap
	{
		//cout<<"This is  pppoe chap !!!"<<endl;
		g_packetinfo.pktType=ETH;
		g_packetinfo.body=(char*)pppoe;
	}
	else
	{
		g_packetinfo.Flag=0;
	}



}

//-----------------------------------------------------------------------
// Func Name   : GetPktInfo
// Description : create g_packetinfo before  analyze l4;
// Parameter   : packet is all data packet .*pkt is pkthdr   .
// Return      : PacketInfo
//-----------------------------------------------------------------------
PacketInfo* PacketParser::GetPktInfo(const char *packet, const struct pcap_pkthdr_n *pkt)
{//int i=0;while(i == 0){printf("\n00000000000000000000000 %s\n",packet);i=1;}
	CleanParser();

 	
	packet_ = (char *)packet;

	
	ethHeader=(struct ethhdr*)packet_;
	g_packetinfo.packet=packet_;
	g_packetinfo.Flag=1;
	g_packetinfo.pkt = pkt;
	unsigned short *vlantype;
	unsigned short vlanLen=0;
	memcpy(g_packetinfo.srcMac,ethHeader->h_source,6);
	memcpy(g_packetinfo.destMac,ethHeader->h_dest,6);
	unsigned short ethType=ntohs(ethHeader->h_proto);
	switch(ethType){
		case 0x8100:                               //vlan and ppp
			while(ethType==0x8100)  //valan * n
			{
				vlantype=(unsigned short *)(packet_ + ETH_HLEN+2+vlanLen);
				ethType=ntohs(*vlantype);
				vlanLen+=4;
			}
			switch(ethType)
			{
				case 0x8864:
					unsigned short *ppptype;
					ppptype=(unsigned short *)(packet_ + ETH_HLEN+vlanLen+6); //vlanlean + pppseion (6)
					if(ntohs(*ppptype)==0x0021)
					{
						ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN+vlanLen+8); //extra ppp +2  is ipheader
						ParseIp();
					}
					else
					{
						pppoe =(struct pppoe_hdr *)(packet_ + ETH_HLEN+vlanLen);
						ParsePPPOE();
					}
					break;
						
				case 0x0800:
					//ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN +4);
					ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN +vlanLen);
					ParseIp();
					break;
				default:
					g_packetinfo.pktType=NUL;
					g_packetinfo.Flag=0;
					break;		   
			}
			break;
		case 0x0800:
// #ifdef VPDNLZ
// 			ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN + 38);
// #else
			ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN);
// #endif
			ParseIp();
			/*if(pkt->parsed_pkt.l3_proto==0x06)
			{
				g_packetinfo.pktType=SOCKS;
				g_packetinfo.Flag=1;
			}*/
			break;
		case 0x8864:
			unsigned short *ppptype2;
			ppptype2=(unsigned short *)(packet_ + ETH_HLEN +6); //pppseion (6)
			if(ntohs(*ppptype2)==0x0021)
			{
				ipHeader_=(struct iphdr *)(packet_ + ETH_HLEN +8); //+ppp is ipheader
				ParseIp();
			}
			else
			{
				pppoe =(struct pppoe_hdr *)(packet_ + ETH_HLEN);
				ParsePPPOE();
			}
			break;
		default:
			g_packetinfo.pktType=NUL;
			g_packetinfo.Flag=0;
			break;		   
	}

	if(!g_packetinfo.Flag) return NULL;
	return &g_packetinfo;
}

// End of file
