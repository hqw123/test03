#ifndef LZ_VPN_H
#define LZ_VPN_H

#include "packet_parser.h"

#ifdef __cplusplus
extern "C"{
#endif

int parse_vpn(struct PacketInfo* pktInfo);

#ifdef __cplusplus
}
#endif

#endif

