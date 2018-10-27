
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "httpproxy.h"
#include "db_data.h"

Http_proxy::Http_proxy()
{
	m_tcp = NULL;
	m_http = NULL;
	objectid = 0;
}

Http_proxy::~Http_proxy()
{

}

void Http_proxy::storedb()
{
	/*write netproxy data to shared memory, by zhangzm*/
	NETPROXY_T tmp_data;
    struct in_addr addr;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = objectid;
	tmp_data.p_data.readed = 0;
	
	addr.s_addr = m_tcp->srcIp;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", m_tcp->srcMac[0]&0xff,
			m_tcp->srcMac[1]&0xff, m_tcp->srcMac[2]&0xff, m_tcp->srcMac[3]&0xff, m_tcp->srcMac[4]&0xff, m_tcp->srcMac[5]&0xff);
	sprintf(tmp_data.p_data.clientPort, "%d", m_tcp->srcPort);
	addr.s_addr = m_tcp->destIp;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", m_tcp->destPort);
    
	strcpy(tmp_data.username, "");
    strncpy(tmp_data.proxy_url, proxy_url.c_str(), 255);
    strncpy(tmp_data.real_url, real_url.c_str(), 255);

    tmp_data.p_data.captureTime = m_tcp->timevalCapture;
	tmp_data.p_data.proType = 1003;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(NETPROXY, (void *)&tmp_data, sizeof(tmp_data));
}

int Http_proxy::get_realurl()
{
	char* data = m_http->http_content;
	if(!strncmp(data, "u=", 2))
	{
		char* addr = data + 2;
		int i = 0;
		while(addr[i] != '&')
		{
			real_url.append(1, addr[i]);
			i++;
		}
	}
	else
	{
		return -1;
	}
	
	return 0;
}

int Http_proxy::get_http_proxy(common_tcp* tcp, common_http* http, int id)
{
	m_tcp = tcp;
	m_http = http;
	objectid = id;
	
	proxy_url.assign(m_http->hostUrl);
    real_url = "";
	get_realurl();
	storedb();
	
	return 0;
}