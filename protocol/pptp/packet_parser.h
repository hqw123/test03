

#ifndef _PACKET_PARSER_
#define _PACKET_PARSER_

//#include <pcap.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "../PacketParser.h"

#define FLAG_VLAN    0x00000001
#define FLAG_PPPOE   0x00000002
#define FLAG_LINK    0x00000004
#define FLAG_IP      0x00000008

#define FLAG_TCP     0x00000010
#define FLAG_UDP     0x00000020
#define FLAG_GRE     0x00000040

#define FLAG_L2TP    0x00000080
#define FLAG_PPP     0x00000100


#if 0  //close by zhangzm
// Define a structure to store the information we need from each layer.
struct packet_struct{	
	int flag;
	unsigned  char srcMac[6];
	unsigned  char destMac[6];
	unsigned  int   srcIpv4;
	unsigned  int   destIpv4;
	unsigned short  srcPort;
	unsigned short  destPort;
	unsigned short  bodyLen;
	struct iphdr  *ip;
	union{
		struct tcphdr *tcp;
		struct udphdr* udp;
		struct pptp_gre_struct* gre;
	}transL;	
	char* body;
	char* packet;
	int  pktLen;
	unsigned int cap_time;
};
#endif

#endif  /*_PACKET_PARSER_*/
