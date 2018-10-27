#ifndef LZ_L2TP_H
#define LZ_L2TP_H

#include "packet_parser.h"

struct l2tp_len_struct
{
    unsigned char  type;
    unsigned char  ver;
    unsigned short len;
    unsigned short tunnel_id;
    unsigned short session_id;
};

struct l2tp_struct
{
    unsigned char  type;
    unsigned char  ver;
    unsigned short tunnel_id;
    unsigned short session_id;
};

struct l2tp_ppp_struct{
	unsigned short proto;
};

// struct ppp_password_struct{
// 	unsigned char code;
// 	unsigned char id;
// 	unsigned short len;
// 	unsigned char peer_id_len;
// 	unsigned char peer_id;
// 	unsigned char password_len;
// 	unsigned char password;
// };

struct ppp_password_struct
{
    unsigned char code;
    unsigned char id;
    unsigned short len;
    unsigned char peer_id_len;
    unsigned char peer_id[0];
};

struct ppp_ip_struct
{
    unsigned char code;
    unsigned char id;
    unsigned short len;
    // 	unsigned char Ipv4[6];
    unsigned short Ipv4_t;
    unsigned short Ipv4_first;
    unsigned short Ipv4_last;
    // 	unsigned int Ipv4;
    // 	unsigned short prim_dns_Ipv4_t;
    // 	unsigned int prim_dns_Ipv4;
    // 	unsigned short second_dns_Ipv4_t;
    // 	unsigned int second_dns_Ipv4;
};

int parse_l2tp_packet(struct PacketInfo* pkinfo);

#endif
