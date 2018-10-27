
#include <arpa/inet.h>

#include "clue_c.h"
#include "analyse_telnet.h"
#include "db_data.h"

Telnet::Telnet()
{
	s_to_c = false;
	packet_info = NULL;
	c_index = 0;
	s_index = 0;
}

Telnet::~Telnet()
{
	
}


void Telnet::store_database()
{
	struct in_addr addr;
	unsigned int clueid = 0;
	unsigned char* chpMac = packet_info->destMac;

	/*write webaccount data to shared memory, by zhangzm*/
	WEBACCOUNT_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));

	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", chpMac[0]&0xff, 
			chpMac[1]&0xff, chpMac[2]&0xff, chpMac[3]&0xff, chpMac[4]&0xff, chpMac[5]&0xff);

	addr.s_addr = packet_info->destIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);

	tmp_data.p_data.clueid = clueid;
	tmp_data.p_data.readed = 0;
	sprintf(tmp_data.p_data.clientPort, "%d", packet_info->destPort);
	addr.s_addr = packet_info->srcIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", packet_info->srcPort);

	tmp_data.p_data.captureTime = (unsigned int)packet_info->pkt->ts.tv_sec;
	strcpy(tmp_data.url, "telnet");
	strncpy(tmp_data.username, user_message[c_index].username.c_str(), 64);
	strncpy(tmp_data.password, user_message[c_index].password.c_str(), 64);

	tmp_data.p_data.proType = 205;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

bool Telnet::analyse_server()
{
	map<unsigned long,Pack_Elem_telnet>::iterator it;
	it = user_message.find(s_index);
	
	if(!strncmp(packet_info->body,"login:",6) && it == user_message.end())
	{
		Pack_Elem_telnet telnet_data;
		telnet_data.flag = 1;
		user_message.insert(pair<unsigned long,Pack_Elem_telnet>(s_index,telnet_data));
	}
	else if(strstr(packet_info->body,"Password:") && it != user_message.end())
	{
		user_message[s_index].flag = 2;
	}
	else if(!strncmp(packet_info->body,"Last login:",11) && it != user_message.end())
	{
		store_database();
		user_message.erase(it);
	}
	else if(!strncmp(packet_info->body,"Login incorrect",15) && it != user_message.end())
	{
		user_message.erase(it);
	}
	else
	{
		return false;
	}
	
	return true;
}

bool Telnet::analyse_client()
{
	map<unsigned long,Pack_Elem_telnet>::iterator it;
	it = user_message.find(c_index);
	if(it != user_message.end())
	{
		if(user_message[c_index].flag == 1)
		{
			if(bodylen == 3 && body[2] == 0x01)
			{
				return false;
			}
			
			if(bodylen == 2 && body[0] == 0x0d && body[1] == 0x0a)
			{
				return true;
			}
				
			if(bodylen > 0 && it != user_message.end())
			{
				user_message[c_index].username.append(body,bodylen);
			}
			
		}
	
		if(user_message[c_index].flag == 2)
		{
			if(bodylen == 2 && body[0] == 0x0d && body[1] == 0x0a)
			{
				return true;
			}
			
			if(bodylen > 0 && it != user_message.end())
			{
				user_message[c_index].password.append(body,bodylen);
			}
		}
	
		if(packet_info->tcp->fin)
		{
			user_message.erase(it);
		}
	}
	
	return true;
}

void Telnet::init()
{
	c_index = packet_info->ip->saddr<<32|packet_info->ip->daddr;
	s_index = packet_info->ip->daddr<<32|packet_info->ip->saddr;
	body = packet_info->body;
	bodylen = packet_info->bodyLen;
}

bool Telnet::analyse_telnet(PacketInfo* pktInfo)
{
	if(pktInfo->srcPort == 23)
	{
		s_to_c = true;
	}
	else if(pktInfo->destPort == 23)
	{
		s_to_c = false;
	}
	else 
	{
		return false;
	}

	packet_info = pktInfo;
	init();
	
	if(s_to_c)
	{
		analyse_server();
	}
	else
	{
		analyse_client();
	}

	return true;
}

