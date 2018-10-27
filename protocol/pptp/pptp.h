#ifndef LZ_PPTP_H
#define LZ_PPTP_H

#include "packet_parser.h"

struct pptp_start_req_struct
{
    unsigned short len;
    unsigned short msg_type;
    unsigned int cookie;
    unsigned short ctl_type;
    unsigned short reserved;
    unsigned short proto_ver;
    unsigned short reserved2;
    unsigned int 	frame_cap;
    unsigned int 	bearer_cap;
    unsigned short max_channel;
    unsigned short firmware_revision;
    unsigned char	host[64];
    unsigned char 	vendor[64];
};

struct pptp_start_reply_struct
{
    unsigned short len;
    unsigned short msg_type;
    unsigned int cookie;
    unsigned short ctl_type;
    unsigned short reserved;
    unsigned short proto_ver;
    unsigned char result;
    unsigned char error;
    unsigned int 	frame_cap;
    unsigned int 	bearer_cap;
    unsigned short max_channel;
    unsigned short firmware_revision;
    unsigned char	host[64];
    unsigned char 	vendor[64];
};

struct pptp_call_req_struct
{
    unsigned short len;
    unsigned short msg_type;
    unsigned int cookie;
    unsigned short ctl_type;
    unsigned short reserved;
    unsigned short call_id;
    unsigned short serial;
    unsigned int 	mini_bps;
    unsigned int 	max_bps;
    unsigned int 	bearer_cap;
    unsigned int 	frame_cap;
    unsigned short max_channel;
    unsigned short window_size;
    unsigned short	process_delay;
    unsigned short phone_size;
    unsigned short reserved2;
    unsigned char  phone_nu[64];
    unsigned char 	sub_addr[64];
};

struct pptp_call_reply_struct
{
    unsigned short len;
    unsigned short msg_type;
    unsigned int 	cookie;
    unsigned short ctl_type;
    unsigned short reserved;
    unsigned short call_id;
    unsigned short peer_id;
    unsigned char 	result;
    unsigned char	error;
    unsigned short cause_cod;
    unsigned int 	connect_speed;
    unsigned short window_size;
    unsigned short	process_delay;
    unsigned int 	channel_id;
    unsigned short reserved2;
};

struct pptp_link_struct
{
    unsigned short len;
    unsigned short msg_type;
    unsigned int 	cookie;
    unsigned short ctl_type;
    unsigned short reserved;
    unsigned short peer_id;
    unsigned short reserved2;
    unsigned int 	send_accm;
    unsigned int 	recv_accm;
};


struct pptp_gre_struct
{
    unsigned char  flags;
    unsigned char  ver;
    unsigned short protocol;
    unsigned short payload_len;
    unsigned short call_id;
    unsigned int seq;
    unsigned int ack;
};

struct gre_ppp_struct
{
    unsigned char	addr;
    unsigned char	ctl;
    unsigned short proto;
};

struct gre_ppp_challenge_struct{
	unsigned short proto;
};

struct ppp_challenge_struct
{
    unsigned char code;
    unsigned char id;
    unsigned short len;
    unsigned char size;
    unsigned char val[0];
};

#ifdef __cplusplus
extern "C"{
#endif
int parse_pptp_packet(struct PacketInfo* pkinfo);
#ifdef __cplusplus
}
#endif

#endif
 
