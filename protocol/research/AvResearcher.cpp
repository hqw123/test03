//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     AvResearcher.cpp
//
//------------------------------------------------------------------------
// Notes:
//		Antivirus Researcher
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101228 ZhengLin    Initial
//
//------------------------------------------------------------------------

#include <stdio.h>
#include <arpa/inet.h>
#include <boost/regex.hpp>
#include <iostream>

#include "AvResearcher.h"
//#include "../PacketParser.h"
#include "clue_c.h"
#include "db_data.h"

using namespace std;
using namespace boost;

static char *ParseMac(const u_char *packet, char *mac);

AvResearcher::AvResearcher()
{

}

int AvResearcher::Match(const boost::regex &rule, const PacketInfo *pktInfo, const string &objInfo)
{
	if (pktInfo == 0 || pktInfo->bodyLen <= 0)
		return 0;

	const char *b = pktInfo->body;
	const char *e = pktInfo->body + pktInfo->bodyLen;
	boost::cmatch m;
	if(boost::regex_search(b, e, m, rule))
	{
		if (m.size() > 1)	
			SetResearchInfo(pktInfo, objInfo + " " + m[1]);
		else
			SetResearchInfo(pktInfo, objInfo);
		return 1;
	}

	return 0;
}

void AvResearcher::Store()
{
	/*write research_host data to shared memory, by zhangzm*/
	struct in_addr addr;
	RESEARCH_HOST_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = objectId_;
	tmp_data.p_data.readed = 0;
	addr.s_addr = clientIp_;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	ParseMac(clientMac_, tmp_data.p_data.clientMac);
	sprintf(tmp_data.p_data.clientPort, "%d", clientPort_);
	addr.s_addr = serverIp_;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", serverPort_);

	tmp_data.p_data.captureTime = timeVal_;
	strncpy(tmp_data.osinfo, objectInfo_.c_str(), 1999);
	tmp_data.p_data.proType = type_;
	tmp_data.p_data.deleted = 0;
	
	msg_queue_send_data(RESEARCH_HOST, (void *)&tmp_data, sizeof(tmp_data));
}

void AvResearcher::SetResearchInfo(const PacketInfo *pktInfo, const string& objInfo)
{
	char strMac[20] = {0};
	struct in_addr addr;

	readFlag_ = 0;
	clientIp_ = pktInfo->srcIpv4;
	serverIp_ = pktInfo->destIpv4;
	clientPort_ = pktInfo->srcPort;
	serverPort_ = pktInfo->destPort;
	objectInfo_ = objInfo;
	memcpy(clientMac_, pktInfo->srcMac, 6);
	ParseMac(pktInfo->srcMac, strMac);
	type_ = 703;
	timeVal_ = (unsigned int)pktInfo->pkt->ts.tv_sec;
#ifdef VPDNLZ
	objectId_ = GetObjectId2(clientIp_,pppoe_);
#else
	//objectId_ = GetObjectId(strMac);
	addr.s_addr = pktInfo->srcIpv4;
	objectId_ = get_clue_id(strMac, inet_ntoa(addr));
#endif
}

static char *ParseMac(const u_char *packet, char *mac)
{
	if (packet == 0 || mac == 0)
		return mac;

	sprintf(mac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x", 
		*reinterpret_cast<const u_char *>(packet),
		*reinterpret_cast<const u_char *>(packet + 1),
		*reinterpret_cast<const u_char *>(packet + 2),
		*reinterpret_cast<const u_char *>(packet + 3),
		*reinterpret_cast<const u_char *>(packet + 4),
		*reinterpret_cast<const u_char *>(packet + 5));

	return mac;
}
