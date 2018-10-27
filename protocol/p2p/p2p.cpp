
#include  <stdio.h>
#include  <arpa/inet.h>

#include  "p2p.h"
#include  "db_data.h"

p2p* p2p::instance_ = 0;

p2p::p2p()
{
	// add more handlers here if any
	// make the pair composed with <http host> and handler functions
	p2p_cli_maps_.insert(std::make_pair("stat.login.xunlei.com", &p2p::parse_thunder_client));
}

p2p::~p2p()
{

}

int p2p::push(up_info_t* upinfo)
{
	this->handler_call(upinfo);	
}

void p2p::parse_thunder_client(up_info_t* upinfo)
{
	if (upinfo->rqi.uri.find("loginstat") != std::string::npos)
		this->save_result(upinfo, act_thunder_login, 1801);
}

void p2p::save_result(up_info_t* up, int type, int pro_type)
{
    /*write p2p data to shared memory, by zhangzm*/
    struct in_addr addr;
    APP_BEHAVIOR_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));

	addr.s_addr = up->ep.srcip;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", up->ep.srcmac[0]&0xff, up->ep.srcmac[1]&0xff, 
            up->ep.srcmac[2]&0xff, up->ep.srcmac[3]&0xff, up->ep.srcmac[4]&0xff, up->ep.srcmac[5]&0xff);
	sprintf(tmp_data.p_data.clientPort, "%d", up->ep.srcport);
	addr.s_addr = up->ep.dstip;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", up->ep.dstport);

    tmp_data.p_data.clueid = up->clueid;
    tmp_data.p_data.readed = 0;

    tmp_data.p_data.captureTime = up->captime;
    tmp_data.optype = type;
    tmp_data.p_data.proType = pro_type;
    tmp_data.p_data.deleted = 0;

    msg_queue_send_data(P2P_INFO, (void *)&tmp_data, sizeof(tmp_data));
}

