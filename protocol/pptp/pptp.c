
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "pptp.h"
#include "save_info.h"
#include "clue_c.h"
#include "Analyzer_log.h"

static int get_handshake_info(void* data,int len,struct user_struct* user);
static int trans_format_user(struct user_struct* user);

int parse_pptp_packet(struct PacketInfo* pkinfo)
{
	int release = 1;
    
	if(pkinfo->Flag&FLAG_PPP && pkinfo->bodyLen)
	{
		struct gre_ppp_challenge_struct* ppp = 0;
		if(memcmp(pkinfo->body, "\xff\x03", 2) == 0)
			pkinfo->body += 2;

 		ppp = (struct gre_ppp_challenge_struct*)pkinfo->body;
		if(ppp->proto == 0x23C2)
		{
			struct user_struct* vpn_user = NULL;
			vpn_user = (struct user_struct*)malloc(sizeof(struct user_struct));
			if(!vpn_user)
			{
				LOG_ERROR("malloc for user_struct fail...\n");
				return 1;
			}
            
			memset(vpn_user, 0, sizeof(*vpn_user));
			get_handshake_info((ppp+1), pkinfo->bodyLen-sizeof(*ppp), vpn_user);
            
			if(vpn_user->flag & INFO_FLAG_ID)
			{
				vpn_user->breakID = 12;
				vpn_user->ip_src = pkinfo->srcIpv4;
				vpn_user->ip_dest = pkinfo->destIpv4;
				memcpy(vpn_user->mac_src, pkinfo->srcMac, 6);
				memcpy(vpn_user->mac_dest, pkinfo->destMac, 6);
				vpn_user->time = (unsigned int)pkinfo->pkt->ts.tv_sec;
				vpn_user->info_type = TYPE_VPN;
				trans_format_user(vpn_user);
				save_user_info(vpn_user, SAVE_INFO_SQL, !release);
                
				if(release)
					free(vpn_user);
                
				return 1;
			}
		}
	}
    
	return 0;
}

static int get_handshake_info(void* data,int len,struct user_struct* user)
{
	user->flag &= ~INFO_FLAG_ID;
	struct ppp_challenge_struct* handshake = NULL;
    
	handshake = (struct ppp_challenge_struct*)data;
	if(handshake->code != 2)
		return 0;
    
	char* id = (char*)(&handshake->size + handshake->size + 1);
	memcpy(user->id , id, ntohs(handshake->len)-5-handshake->size);
	user->flag |= INFO_FLAG_ID;
    
	return 1;
}

static int trans_format_user(struct user_struct* user)
{
	struct in_addr addr;
	addr.s_addr = user->ip_src;
	memcpy(user->src_ip, inet_ntoa(addr), 16);
    
	addr.s_addr = user->ip_dest;
	memcpy(user->dest_ip, inet_ntoa(addr), 16);
    
	sprintf(user->src_mac, "%02x-%02x-%02x-%02x-%02x-%02x",
			  user->mac_src[0]&0xff, user->mac_src[1]&0xff, user->mac_src[2]&0xff,
			  user->mac_src[3]&0xff, user->mac_src[4]&0xff, user->mac_src[5]&0xff);

	user->objectID = get_clue_id(user->src_mac, user->src_ip);

	sprintf(user->src_port, "%d", user->port_src);
	sprintf(user->dest_port, "%d", user->port_dest);

    return 0;
}
