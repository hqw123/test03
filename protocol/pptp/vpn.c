
#include "vpn.h"
#include "l2tp.h"
#include "pptp.h"

static int parse_packet(struct PacketInfo *pinfo)
{
    int flag = 0;

    if(UDP == pinfo->pktType)
    {
        flag |= FLAG_UDP;
        if(pinfo->srcPort == 1701 || pinfo->destPort == 1701)
            flag |= FLAG_L2TP;

        pinfo->Flag = flag;
	}
	else if(GRE == pinfo->pktType)
    {
        flag |= FLAG_GRE;
        char* end = (char*)pinfo->ip + ntohs(pinfo->ip->tot_len);

        struct pptp_gre_struct* gre = (struct pptp_gre_struct*)((char*)pinfo->ip + pinfo->ip->ihl*4);
        pinfo->bodyLen = ntohs(gre->payload_len);
        if(pinfo->bodyLen)
            pinfo->body = (char*)end - pinfo->bodyLen;

        if(gre->protocol == 0x0B88)   //0x880B : PPP protocol
            flag |= FLAG_PPP;

        pinfo->Flag = flag;
	}

    return flag;
}

int parse_vpn(struct PacketInfo* pktInfo)
{
    int flag = 0;
    int inner_rt = 0;

    flag = parse_packet(pktInfo);

    if (flag & FLAG_GRE)
        inner_rt = parse_pptp_packet(pktInfo);
    else if (flag & FLAG_L2TP)
        inner_rt = parse_l2tp_packet(pktInfo);

    return inner_rt;
}

