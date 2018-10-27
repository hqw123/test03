#ifndef LZ_VPN_INFO_H
#define LZ_VPN_INFO_H

#define INFO_FLAG_ID	0x00000001
#define INFO_FLAG_PASS	0x00000002

#define SAVE_INFO_SQL	1

#define BREAK_THROUGH	12

#define TYPE_SOCKS5		1001
#define TYPE_VPN 		1002
#define TYPE_NETHTTPS	1003

struct user_struct
{
    int flag;
    unsigned int breakID;
    unsigned int objectID;
    int readFlag;
    unsigned int ip_src;
    unsigned int ip_dest;
    char src_ip[16];
    char dest_ip[16];
    unsigned short port_src;
    unsigned short port_dest;
    char src_port[6];
    char dest_port[6];
    unsigned int time;
    char mac_src[7];
    char mac_dest[7];
    char src_mac[18];
    char dest_mac[18];
    char id[40];
    char pass[40];
    unsigned short info_type;
};

#ifdef __cplusplus
extern "C"{
#endif

int save_user_info(struct user_struct* user, int type, int release);

#ifdef __cplusplus
}
#endif

#endif

