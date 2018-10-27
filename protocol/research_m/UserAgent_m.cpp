
#include <arpa/inet.h>
#include <boost/regex.hpp>
#include <string>
#include <iostream>

#include "UserAgent_m.h"
#include "clue_c.h"
#include "db_data.h"

using namespace std;
using namespace boost;

static char userAgentm_[1024];

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

void analyse_useragent_m(const PacketInfo *pPkt)
{
	memset(userAgentm_, 0, 1024);
	std::string regstr = "\r\nUser-Agent:\\s(.*?)\r\n";
	boost::regex expression(regstr);

	boost::cmatch matchedStr;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;

	if(boost::regex_search(begin, end, matchedStr, expression))
	{
		u_short tmplen = matchedStr[1].length();
		if(tmplen < 1024)
		{
			char *tmp = new char[tmplen+1];
			tmp[tmplen]=0;
			memcpy(tmp, matchedStr[1].first, tmplen);
			sprintf(userAgentm_,"%s",tmp);
			delete tmp;

			analyse_research_info_m(pPkt);
		}
	}
}

void  analyse_research_info_m(const PacketInfo *pktInfo)
{
	string os, browser, model;
	if (get_research_info_os_m(os))
	{
		store_research_info_m(pktInfo, 701, os.c_str());
	}
	if (get_research_info_browser_m(browser))
	{
		store_research_info_m(pktInfo, 702, browser.c_str());
	}
	if (get_research_info_model_m(model))
	{
		store_research_info_m(pktInfo, 703, model.c_str());
	}
}

bool get_research_info_os_m(string &os)
{
	if (is_os_android_m(os))
	{
		return true;
	}
	if (is_os_ios_m(os))
	{
		return true;
	}
	return false;
}

bool get_research_info_browser_m(string &browser)
{
	if (is_browser_uc_m(browser))
	{
		return true;
	}
	if (is_browser_safari_m(browser))
	{
		return true;
	}
	return false;
}

bool get_research_info_model_m(string &model)
{
	if (is_model_android_m(model))
	{
		return true;
	}
	return false;
}

bool is_os_android_m(string &os)
{
	boost::cmatch match;
	if (boost::regex_search(userAgentm_, match, boost::regex("Android ([\\w\\.]+)")))	
	{
		os = "Android " + match[1];
		return true;
	}
	return false;
}

bool is_os_ios_m(string &os)
{
	boost::cmatch match;
	if (boost::regex_search(userAgentm_, match, boost::regex("(iPhone|iPod);.*?OS ([\\w]+) like Mac OS X")))	
	{
		os = "iPhone OS " + match[2];
		return true;
	}
	if (boost::regex_search(userAgentm_, match, boost::regex("iPad;.*?OS ([\\w]+) like Mac OS X")))	
	{
		os = "iPad OS " + match[1];
		return true;
	}
	return false;
}

bool is_browser_uc_m(string &browser)
{
	boost::cmatch match;
	const boost::regex reg("UCWEB([\\da-zA-Z\\.]+)?");
	if (boost::regex_search(userAgentm_, match, reg))
	{
		browser = "UC " + match[1];
		return true;
	}
	const boost::regex reg1("UC");
	if (boost::regex_search(userAgentm_, match, reg1))
	{
		browser = "UC ";
		return true;
	}

	return false;
}

bool is_browser_safari_m(string &browser)
{
	boost::cmatch match;
	const boost::regex reg("Safari");
	if (boost::regex_search(userAgentm_, match, reg))
	{
		browser = "Safari ";
		return true;
	}

	return false;
}

bool is_model_android_m(string &model)
{
	boost::cmatch match;
	const boost::regex reg("\\s(\\S+?)\\sBuild/");
	if (boost::regex_search(userAgentm_, match, reg))
	{
		model = match[1];
		return true;
	}
	return false;
}

void store_research_info_m(const PacketInfo *pktInfo, const int nType, const char* info)
{
	char strMac[18] = {0};
	struct in_addr addr;

	unsigned int clientIp_ = pktInfo->srcIpv4;
	unsigned int serverIp_ = pktInfo->destIpv4;
	unsigned short clientPort_ = pktInfo->srcPort;
	unsigned short serverPort_ = pktInfo->destPort;
	ParseMac(pktInfo->srcMac, strMac);

	//struct in_addr addr;
	addr.s_addr = pktInfo->srcIpv4;
	unsigned int clue_id = get_clue_id(strMac, inet_ntoa(addr));

	/*write research_host data to shared memory, by zhangzm*/
	RESEARCH_HOST_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = clue_id;
	tmp_data.p_data.readed = 0;
	addr.s_addr = clientIp_;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	strncpy(tmp_data.p_data.clientMac, strMac, 17);
	sprintf(tmp_data.p_data.clientPort, "%d", clientPort_);
	addr.s_addr = serverIp_;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", serverPort_);

	tmp_data.p_data.captureTime = (unsigned int)pktInfo->pkt->ts.tv_sec;
	strncpy(tmp_data.osinfo, info, 1999);
	tmp_data.p_data.proType = nType;
	tmp_data.p_data.deleted = 0;
	
	msg_queue_send_data(RESEARCH_HOST, (void *)&tmp_data, sizeof(tmp_data));
}
