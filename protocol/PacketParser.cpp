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

using namespace std;

// Lenth of header of IP
#define IP_HLEN(iphdr)(4 * iphdr->ihl)
// Lenth of header of TCP
#define TCP_HLEN(tcphdr)(4 * tcphdr->doff)
// Lenth of header of UDP
const int MIN_UDP_HLEN = 8;
const int MIN_TCP_HLEN = 20;
const int MIN_GRE_HLEN = 4;  /*GRE protocol length range : 4~20bytes*/

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
	ethHeader = NULL;
	packet_ = NULL;
	ipHeader_ = NULL;
	ipBody_ = NULL;
	tcpHeader_ = NULL;
	udpHeader_ = NULL;
	pktInfo_ = NULL;
	bodyLen_ = 0;

	memset(&g_packetinfo, 0, sizeof(struct PacketInfo));
	g_packetinfo.pktType = NUL;

    memset(packet_buff, 0, 1514);
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
    unsigned int tmp_srcip = 0;
    //ipHeader_ = reinterpret_cast<const struct iphdr*>(packet_ + ETH_HLEN);
	ipBody_ = (char*)(ipHeader_) + IP_HLEN(ipHeader_);
	bodyLen_ = ntohs(ipHeader_->tot_len) - IP_HLEN(ipHeader_);
	switch (ipHeader_->protocol) 
    {
		case IPPROTO_TCP:
        {
			if (bodyLen_ < MIN_TCP_HLEN) 
            {
				break;
			}
			
			tcpHeader_ = ( struct tcphdr*)ipBody_;
			bodyLen_ = bodyLen_ - TCP_HLEN(tcpHeader_);
			if (bodyLen_ < 0 || bodyLen_ > 1460) 
            {
				break;
			}
            
			parseOkey = true;
			ParseTcp();
			break;
        }
        
		case IPPROTO_UDP:
        {
			if (bodyLen_ < MIN_UDP_HLEN) 
            {
				break;
			}
            
			udpHeader_ = ( struct udphdr *)(ipBody_);
			bodyLen_ = bodyLen_ - MIN_UDP_HLEN;
			if (bodyLen_ <= 0) 
            {
				break;
			}
            
			parseOkey = true;
			ParseUdp();
			break;
        }

        case IPPROTO_GRE:
        {
            if (bodyLen_ < MIN_GRE_HLEN)
            {
                break;
            }

            parseOkey = true;
            g_packetinfo.pktType = GRE;
            tmp_srcip = ipHeader_->saddr;
            ParseGre();
            /*don't parse GRE protocol here, parse data in VPN pptp.*/
            break;
        }
        
		default:
            /*Uninterested packet, discard it.*/
			break;
	}
    
	if (parseOkey) 
    {
		g_packetinfo.ip = ipHeader_;
		g_packetinfo.srcIpv4 = ipHeader_->saddr;
		g_packetinfo.destIpv4 = ipHeader_->daddr;
		g_packetinfo.bodyLen = bodyLen_;
        if(tmp_srcip)
        {
           g_packetinfo.srcIpv4 = tmp_srcip;
        }
	}
    else 
    {
		g_packetinfo.Flag = 0;
	}

	return parseOkey;
}

//-----------------------------------------------------------------------
// Func Name   : ParserGre
// Description : Parse the packet on GRE layer.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
void PacketParser::ParseGre()
{
    ipHeader_ = (struct iphdr*)((char*)ipHeader_ + 36);
    ipBody_ = (char*)(ipHeader_) + IP_HLEN(ipHeader_);
    bodyLen_ = ntohs(ipHeader_->tot_len) - IP_HLEN(ipHeader_);
    switch(ipHeader_->protocol)
    {
        case IPPROTO_TCP:
        {
            if (bodyLen_ < MIN_TCP_HLEN) 
            {
				break;
			}
			
			tcpHeader_ = ( struct tcphdr*)ipBody_;
			bodyLen_ = bodyLen_ - TCP_HLEN(tcpHeader_);
			if (bodyLen_ < 0 || bodyLen_ > 1460) 
            {
				break;
			}
            
			ParseTcp();
			break;
        }

        case IPPROTO_UDP:
        {
            if (bodyLen_ < MIN_UDP_HLEN) 
            {
				break;
			}
            
			udpHeader_ = ( struct udphdr *)(ipBody_);
			bodyLen_ = bodyLen_ - MIN_UDP_HLEN;
			if (bodyLen_ <= 0) 
            {
				break;
			}
            
			ParseUdp();
			break;
            break;
        }

        default:
            break;
    }
}

//-----------------------------------------------------------------------
// Func Name   : ParserTcp
// Description : Parse the packet on TCP layer.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
void PacketParser::ParseTcp()
{
	g_packetinfo.tcp = tcpHeader_;
	g_packetinfo.pktType = TCP;
    // Get the source port and destination port from TCP header.
	g_packetinfo.srcPort = ntohs(tcpHeader_->source);
	g_packetinfo.destPort = ntohs(tcpHeader_->dest);
    // Store the pointer of packet body and lenth of body.
	//g_packetinfo.body = (char *)(tcpHeader_) + TCP_HLEN(tcpHeader_);
	if (bodyLen_ > 0)
	    memcpy(packet_buff, (char *)(tcpHeader_) + TCP_HLEN(tcpHeader_), bodyLen_);
    g_packetinfo.body = (char *)packet_buff;
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
	g_packetinfo.body = (char *)(udpHeader_) + MIN_UDP_HLEN;
}

struct pppoe_hdr *pppoe=NULL;
void PacketParser::ParsePPPOE()
{
	unsigned short *ppp;
	char *temp = (char *)pppoe;
	temp += (sizeof(struct pppoe_hdr));
	ppp = (unsigned short *)temp;
	if((ntohs(*ppp) == 0xc023) | (ntohs(*ppp) == 0x8021) | (ntohs(*ppp) == 0xc223)) //peer-id and password or ipcp or chap
	{
		//cout<<"This is  pppoe chap !!!"<<endl;
		g_packetinfo.pktType = ETH;
		g_packetinfo.body = (char*)pppoe;
	}
	else
	{
		g_packetinfo.Flag = 0;
	}

}

//-----------------------------------------------------------------------
// Func Name   : GetPktInfo
// Description : create g_packetinfo before  analyze l4;
// Parameter   : packet is all data packet .*pkt is pkthdr   .
// Return      : PacketInfo
//-----------------------------------------------------------------------
PacketInfo* PacketParser::GetPktInfo(const char *packet, const struct pcap_pkthdr_n *pkt)
{
    CleanParser();
    packet_ = (char *)packet;

    ethHeader = (struct ethhdr*)packet_;
    g_packetinfo.packet = packet_;
    g_packetinfo.Flag = 1;
    g_packetinfo.pkt = pkt;

    unsigned short *vlantype;
    unsigned short vlanLen = 0;
    
    memcpy(g_packetinfo.srcMac, ethHeader->h_source, 6);
    memcpy(g_packetinfo.destMac, ethHeader->h_dest, 6);
    unsigned short ethType = ntohs(ethHeader->h_proto);
	switch(ethType)
    {
        case 0x8100:                               //vlan and ppp
            while(ethType == 0x8100)  //valan * n
            {
            	vlantype = (unsigned short *)(packet_ + ETH_HLEN + 2 + vlanLen);
            	ethType = ntohs(*vlantype);
            	vlanLen += 4;
            }
            
            switch(ethType)
            {
            	case 0x8864:
            		unsigned short *ppptype;
            		ppptype=(unsigned short *)(packet_ + ETH_HLEN + vlanLen + 6); //vlanlean + pppseion (6)
            		if(ntohs(*ppptype) == 0x0021)
            		{
            			ipHeader_ = (struct iphdr *)(packet_ + ETH_HLEN + vlanLen + 8); //extra ppp +2  is ipheader
            			ParseIp();
            		}
            		else
            		{
            			pppoe = (struct pppoe_hdr *)(packet_ + ETH_HLEN + vlanLen);
            			ParsePPPOE();
            		}
            		break;
            			
            	case 0x0800:
            		ipHeader_ = (struct iphdr *)(packet_ + ETH_HLEN + vlanLen);
            		ParseIp();
            		break;
                    
            	default:
            		g_packetinfo.pktType = NUL;
            		g_packetinfo.Flag = 0;
            		break;		   
            }
            break;
            
        case 0x0800:
        	ipHeader_ = (struct iphdr *)(packet_ + ETH_HLEN);
        	ParseIp();
        	break;
            
        case 0x8864:
        	unsigned short *ppptype2;
        	ppptype2 = (unsigned short *)(packet_ + ETH_HLEN + 6); //pppseion (6)
        	if (ntohs(*ppptype2) == 0x0021)
        	{
        		ipHeader_ = (struct iphdr *)(packet_ + ETH_HLEN + 8); //+ppp is ipheader
        		ParseIp();
        	}
        	else
        	{
        		pppoe = (struct pppoe_hdr *)(packet_ + ETH_HLEN);
        		ParsePPPOE();
        	}
        	break;
            
        default:
        	g_packetinfo.pktType = NUL;
        	g_packetinfo.Flag = 0;
        	break;		   
	}

    if(!g_packetinfo.Flag)
    	return NULL;
/*
	you can use "else if" to add some primary key, get print info only you want.
	for example:
    else if ((g_packetinfo.bodyLen != 0) && (NULL != g_packetinfo.body) && (NULL != strstr(g_packetinfo.body, "bbs.ice.reply") || 
            NULL != strstr(g_packetinfo.body, "params.content=")))
*/
#if 0  //for test, 'else' or 'else if'
    else
    {
        struct in_addr addr;
        
        printf("src MAC:%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", g_packetinfo.srcMac[0], g_packetinfo.srcMac[1],
                g_packetinfo.srcMac[2], g_packetinfo.srcMac[3], g_packetinfo.srcMac[4], g_packetinfo.srcMac[5]);
        
        printf("dst MAC:%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", g_packetinfo.destMac[0], g_packetinfo.destMac[1],
                g_packetinfo.destMac[2], g_packetinfo.destMac[3], g_packetinfo.destMac[4], g_packetinfo.destMac[5]);

        addr.s_addr = g_packetinfo.srcIpv4;
        printf("src IP:%s\n", inet_ntoa(addr));
        addr.s_addr = g_packetinfo.destIpv4;
        printf("dst IP:%s\n", inet_ntoa(addr));

        
        printf("src Port:%d\n", g_packetinfo.srcPort);
        printf("dst Port:%d\n", g_packetinfo.destPort);

        char *tmp_data = g_packetinfo.body;
        unsigned short tmp_len = g_packetinfo.bodyLen;

        printf("HTTP body, bodyLen=%d:\n", tmp_len);
        for (; tmp_data && tmp_len-- > 0; tmp_data++)
		    printf("%c", isprint(*tmp_data) ? *tmp_data : '.');
	    printf("\r\n\r\n");
    }
#endif

    return &g_packetinfo;
}

// End of file
