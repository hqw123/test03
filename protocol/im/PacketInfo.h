#ifndef PACKET_INFO
#define PACKET_INFO

extern "C" {
//#include <pfring.h>
#include "../PacketParser.h"
}
/*
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>*/
#include <assert.h>
/*
enum PacketType
{
    ETH = 0,
    IP,
    TCP,
    UDP,
    NUL
};

struct PacketInfo
{
    unsigned char   srcMac[6];
    unsigned char   destMac[6];
    unsigned int   srcIpv4;
    unsigned int   destIpv4;
    unsigned short  srcPort;
    unsigned short  destPort;
    unsigned short  bodyLen;
    iphdr*          ip;
    tcphdr*         tcp;
    enum PacketType pktType;
    char*           body;
    char*           packet;
    pfring_pkthdr*  pktHdr;
    int             flag;
};
*/
#define COPY_BYTES 26

char* ParseMac(const u_char* packet, char* mac);

#endif
