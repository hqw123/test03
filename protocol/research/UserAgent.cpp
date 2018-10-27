
#include <arpa/inet.h>
#include <boost/regex.hpp>
#include <string>
#include <iostream>

#include "UserAgent.h"
#include "clue_c.h"
#include "db_data.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

using namespace std;
using namespace boost;

static char userAgent_[1024] = {0};

static boost::regex* g_user_agent;
static boost::regex* g_mac_osn;
static boost::regex* g_mac_os;

static boost::regex* g_msie;
static boost::regex* g_firefox;
static boost::regex* g_chrome;
static boost::regex* g_safari_n0;
static boost::regex* g_safari_n1;
static boost::regex* g_safari_n2;
static boost::regex* g_opera_n0;
static boost::regex* g_opera_n1;
static boost::regex* g_maxthon_n0;
static boost::regex* g_maxthon_n1;
static boost::regex* g_sogou;
static boost::regex* g_qqbrowser;
static boost::regex* g_tencenttraveler;
static boost::regex* g_konqueror;

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

int useragent_init(void)
{
	g_user_agent = new boost::regex("\r\nUser-Agent:\\s(.*?)\r\n");
	g_mac_osn = new boost::regex("Macintosh;.*?Mac OS X ([\\w]+)");
	g_mac_os = new boost::regex("Macintosh;.*?Mac OS X");
	
	g_msie = new boost::regex("MSIE (\\d+\\.\\d+)");
	g_firefox = new boost::regex("Firefox/([\\da-zA-Z\\.]+)?");
	g_chrome = new boost::regex("Chrome/([\\d\\.a-zA-Z]+)");
	g_safari_n0 = new boost::regex("Version/([\\d\\.a-zA-Z]+) Safari/[\\d\\.a-zA-Z]+");
	g_safari_n1 = new boost::regex("Version/([\\d\\.a-zA-Z]+) Mobile/[\\d\\.a-zA-Z]+ Safari/[\\d\\.a-zA-Z]+");
	g_safari_n2 = new boost::regex("Safari/[\\d\\.a-zA-Z]+");
	g_opera_n0 = new boost::regex("Opera/[\\d\\.a-zA-Z]+.*?Version/([\\d\\.a-zA-Z]+)");
	g_opera_n1 = new boost::regex("Opera[ /]([\\d\\.a-zA-Z]+)");
	g_maxthon_n0 = new boost::regex("Maxthon/([\\d\\.a-zA-Z]+)", boost::regex::icase);
	g_maxthon_n1 = new boost::regex("Maxthon ([\\d\\.a-zA-Z]+)", boost::regex::icase);
	g_sogou = new boost::regex("SE (\\d+\\.X)");
	g_qqbrowser = new boost::regex("QQBrowser/([\\d\\.a-zA-Z]+)");
	g_tencenttraveler = new boost::regex("TencentTraveler ([\\d\\.a-zA-Z]+)");
	g_konqueror = new boost::regex("Konqueror/([\\d\\.a-zA-Z-]+)");

	return 0;
}

void useragent_cleanup(void)
{
	delete g_user_agent;
	delete g_mac_osn;
	delete g_mac_os;
	delete g_msie;
	delete g_firefox;
	delete g_chrome;
	delete g_safari_n0;
	delete g_safari_n1;
	delete g_safari_n2;
	delete g_opera_n0;
	delete g_opera_n1;
	delete g_maxthon_n0;
	delete g_maxthon_n1;
	delete g_sogou;
	delete g_qqbrowser;
	delete g_tencenttraveler;
	delete g_konqueror;
}

void analyse_useragent(const PacketInfo *pPkt)
{
	memset(userAgent_, 0, 1024);
	boost::cmatch matchedStr;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;

	if (boost::regex_search(begin, end, matchedStr, *g_user_agent))
	{
		u_short tmplen = matchedStr[1].length();
		if (tmplen < 1024)
		{
			memcpy(userAgent_, matchedStr[1].first, tmplen);
			analyse_research_info(pPkt);
		}
	}
}

void  analyse_research_info(const PacketInfo *pktInfo)
{
	string os, browser;
	if (get_research_info_os(os))
	{
		store_research_info(pktInfo, 701, os.c_str());
	}

	if (get_research_info_browser(browser))
	{
		store_research_info(pktInfo, 702, browser.c_str());
	}
}

bool get_research_info_os(string &os)
{
	if (is_os_windows(os))
	{
		return true;
	}
	if (is_os_linux(os))
	{
		return true;
	}
	if (is_os_mac(os))
	{
		return true;
	}

	return false;
}

bool get_research_info_browser(string &browser)
{
	if (is_browser_qqbrowser(browser))
	{
		return true;
	}
	if (is_browser_tencenttraveler(browser))
	{
		return true;
	}
	if (is_browser_maxthon(browser))
	{
		return true;
	}
	if (is_browser_360se(browser))
	{
		return true;
	}
	if (is_browser_sogou(browser))
	{
		return true;
	}
	if (is_browser_theworld(browser))
	{
		return true;
	}
	if (is_browser_opera(browser))
	{
		return true;
	}
	if (is_browser_konqueror(browser))
	{
		return true;	
	}	

	// These judgments must be placed in the final 
	// Best not to change their order
	if (is_browser_chrome(browser))
	{
		return true;
	}
	if (is_browser_safari(browser))
	{
		return true;
	}
	if (is_browser_firefox(browser)) 
	{
		return true;
	}
	if (is_browser_msie(browser))
	{
		return true;
	}

	return false;
}

bool is_os_windows(string &os)
{
	if (NULL != strstr(userAgent_, "Windows NT 5.1"))
	{
		os = "Windows XP";
	}
	else if (NULL != strstr(userAgent_, "Windows NT 6.1"))
	{
		if (NULL != strstr(userAgent_, "WOW64") || NULL!=strstr(userAgent_, "Win64") || NULL!=strstr(userAgent_, "x64"))
		{
			os = "Windows 7 x64";
		}
		else
		{
			os = "Windows 7 x32";
		}
	}
	else if (NULL != strstr(userAgent_, "Windows NT 6.0"))
	{
		os = "Windows Vista";
	}
	else if (NULL != strstr(userAgent_, "Windows NT 5.2"))
	{
		os = "Windows Server 2003";
	}
	else if (NULL != strstr(userAgent_, "Windows NT 5.0"))
	{
		os = "Windows 2000";
	}
	else if (NULL != strstr(userAgent_, "Windows NT"))
	{
		os = "Windows NT";
	}
	else if (NULL != strstr(userAgent_, "Windows CE"))
	{
		os = "Windows CE";
	}
	else if (NULL != strstr(userAgent_, "Windows 9x 4.90"))
	{
		os = "Windows Me";
	}
	else if (NULL != strstr(userAgent_, "Windows 98"))
	{
		os = "Windows 98";
	} 
	else if (NULL != strstr(userAgent_, "Windows 95"))
	{
		os = "Windows 95";
	}
	else
	{
		return false;
	}

	return true;
}

bool is_os_linux(string &os)
{
	if (NULL != strstr(userAgent_, "Linux"))
	{
		os = "Linux";
		return true;
	}

	return false;
}

bool is_os_mac(string &os)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_mac_osn))
	{
		os = "Macintosh; Mac OS X " + match[1];
		return true;
	}
	if (boost::regex_search(userAgent_, match, *g_mac_os))
	{
		os = "Macintosh; Mac OS X";
		return true;
	}

	return false;
}

bool is_browser_msie(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_msie))
	{
		browser = "Internet Explorer " + match[1];
		return true; 
	}

	return false;
}

bool is_browser_firefox(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_firefox))
	{
		browser = "Firefox " + match[1];
		return true;
	}

	if (NULL != strstr(userAgent_, "Firefox"))
	{
		browser = "Firefox";
		return true;
	}

	return false;
}

bool is_browser_chrome(string& browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_chrome))
	{
		browser = "Chrome " + match[1];
		return true;
	}

	if (NULL != strstr(userAgent_, "Chrome"))
	{
		browser = "Chrome";
		return true;
	}

	return false;
}

bool is_browser_safari(string& browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_safari_n0))
	{
		browser = "Safari " + match[1];
		return true;
	}

	if (boost::regex_search(userAgent_, match, *g_safari_n1))
	{
		browser = "Safari " + match[1];
		return true;
	}

	if (boost::regex_search(userAgent_, match, *g_safari_n2))
	{
		browser = "Safari";
		return true;
	}

	return false;
}

bool is_browser_opera(string& browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_opera_n0))
	{
		browser = "Opera " + match[1];
		return true;
	}
	
	if (boost::regex_search(userAgent_, match, *g_opera_n1))
	{
		browser = "Opera " + match[1];
		return true;
	}

	if (NULL != strstr(userAgent_, "Opera"))
	{
		browser = "Opera";
		return true;
	}

	return false;
}

bool is_browser_maxthon(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_maxthon_n0))
	{
		browser = "Maxthon " + match[1];
		return true;
	}

	if (boost::regex_search(userAgent_, match, *g_maxthon_n1))
	{
		browser = "Maxthon " + match[1];
		return true;
	}

	if (NULL != strcasestr(userAgent_, "Maxthon"))
	{
		browser = "Maxthon";
		return true;
	}

	return false;
}

bool is_browser_360se(string &browser)
{
	if (NULL != strstr(userAgent_, "360SE"))
	{
		browser = "360SE";
		return true;
	}

	return false;
}

bool is_browser_sogou(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_sogou))
	{
		browser = "Sogou " + match[1];
		return true;
	}

	return false;
}

bool is_browser_qqbrowser(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_qqbrowser))
	{
		browser = "QQBrowser " + match[1];
		return true;
	}

	return false;
}

bool is_browser_tencenttraveler(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_tencenttraveler))
	{
		browser = "TencentTraveler " + match[1];
		return true;
	}

	return false;
}

bool is_browser_theworld(string &browser)
{
	if (NULL != strstr(userAgent_, "TheWorld"))
	{
		browser = "TheWorld";
		return true;
	}

	return false;
}

bool is_browser_konqueror(string &browser)
{
	boost::cmatch match;
	if (boost::regex_search(userAgent_, match, *g_konqueror))
	{
		browser = "Konqueror " + match[1];
		return true;
	}

	return false;
}

void store_research_info(const PacketInfo *pktInfo, const int nType, const char* info)
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
