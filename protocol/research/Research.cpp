//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.       
//                                                                       
// Copyright (C) 2010 BAIHONG Software CO., Ltd.         
//
//------------------------------------------------------------------------
//
// Module Name:     Research.cpp
//
//------------------------------------------------------------------------
// Notes:
//
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- ---------------------------------
// $d0= -------- 1.0  001 101228 ZhengLin    Initial
//
//------------------------------------------------------------------------

#include <iostream>
#include <string>
#include <boost/regex.hpp>

#include "Research.h"
#include "AvResearcher.h"
#include "ImeResearcher.h"
#include "QQVersion.h" //add by tz at 2012-04-11
//#include "../PacketParser.h"
#include "clue_c.h"
#include "Analyzer_log.h"


using namespace std;
using namespace boost;

static void print(const string &, const string &);

AvResearcher av;
ImeResearcher ime;
QQVersion qqVersion;

const char *av360sd = "360杀毒";
const boost::regex av360Up("GET\\s/sdup(exe|beta)m?.cab\\sHTTP/1.1.*?Host: sdl.360safe.com\r\n");

const char *av360safe = "360安全卫士";
const boost::regex av360safeUp("^GET /v3/safeup_lib.cab.*?&ver=([\\.\\d]+).*?Host: update.360safe.com\r\n");

const char *avKis = "金山毒霸";
const boost::regex avKisUp("^GET /duba/update/.*?Host: fu010.www.duba.net\r\n");
const boost::regex avKisUp2("^GET /duba/kisengine/app/.*?Host: cu005.www.duba.net\r\n");
const boost::regex avKisUp3("^GET /duba/kisengine/data/.*?Host: cu005.www.duba.net\r\n");
const boost::regex avKisUp4("^GET /duba/kisengine/lib/.*?Host: cu010.www.duba.net\r\n");

const char *avKsave = "金山卫士";
// 金山卫士 (Version 2.3.0.1196)
const boost::regex avKsaveUp("^GET /safe/ksafeupdate\\.ini.*?Host: up\\.ijinshan\\.com\r\n");
const boost::regex avKsaveUp2("^GET /safe/msg\\.pack.*?ver=(.*?).*?Host: up\\.ijinshan\\.com\r\n");

const char *avJiangMin = "江民杀毒软件";
const boost::regex avJiangMinUp("^GET /\\d{2}/\\d{2}/updatefile/Server.ini .*?Host: 08update\\d{1,}.jiangmin.com\r\n");
const boost::regex avJiangMinUp2("^GET //\\d{2}/\\d{2}/UpdateFile/.*?Host: 08update\\d{1,}.jiangmin.com\r\n");
const boost::regex avJiangMinUp3("^GET /\\d{2}/Server.ini.*?Host: update\\d{1,}.jiangmin.com\r\n");
const boost::regex avJiangMinUp4("^GET //\\d{2}/updatefile/.*?Host: 08update\\d{1,}.jiangmin.com\r\n");

const char *avRiSing = "瑞星杀毒软件";
// 瑞星杀毒软件 (Version: 23.00.18.16)
const boost::regex avRiSingUp("^GET /rs.*?Host: rsup10\\.rising\\.com\\.cn\r\n");
const boost::regex avRiSingUp2("^GET /rs.*?Host: rsdownauto\\.rising\\.com\\.cn\r\n");

const char *avKav = "卡巴斯基安全部队"; 
const boost::regex avKavUp("^GET /index/u\\d{4}g.xml.*?Host: dnl-\\d{2}\\.geo\\.kaspersky.com\r\n");

const char *avAvira = "小红伞";
const boost::regex avAviraUp("^GET /update/.*?Host: personal.avira-update.com\r\n");

const char *avNorton = "诺顿";
const boost::regex avNortonUp("^GET /minitri.flg.*?HOST: liveupdate.symantecliveupdate.com\r\n");
const boost::regex avNortonUp2("^GET /product-update\\?.*?Host: updatecenter.norton.com\r\n");

const char *avNod32 = "NOD32";
const boost::regex avNod32Up("^GET /eset_upd/update.ver .*?Host: u7.eset.com.cn\r\n");
const boost::regex avNod32Up2("^GET /download/engine3/.*?nup .*?Host: u7.eset.com.cn\r\n");

const char *avBitDefender = "BitDefender Internet Security";
const boost::regex avBitDefenderUp("^GET /antispam_sig/versions.id.*?Host: upgrade.bitdefender.com");

const char *avAvast = "AVAST Software Security";
const boost::regex avAvastUp("^GET /iavs5x/prod-ais.vpx");

const char *avMcAfee = "McAfee Security Center";
const boost::regex avMcAfeeUp("^GET /data/manifest/.*?User-Agent: MPFv");

const char *avAvg = "AVG Internet Security";
const boost::regex avAvgUp("^GET /softw/\\d{2}free/update/avg\\d{2}infoavi.ctf");

const char *avMse = "Microsoft Security Essentials";
const boost::regex avMseUp("^HEAD /v9/microsoftupdate/redir/muauth.cab.*?User-Agent: Windows-Update-Agent\r\n");

const char *avQQPCMgr = "QQ电脑管家";
const boost::regex avQQPCMgrUp("^POST / HTTP/1.1\r\nHost: masterconn.qq.com\r\n.*?\r\n\r\n\\x00\\x02\\x00\\x12.*?(\\d+\\.+\\d+\\.+\\d+\\.+\\d+)");

// Sogou Pinyin(Version: 5.1.1.4845)
const char *imeSogouPinyin = "搜狗拼音输入法";
const boost::regex imeSogouPinyinUpdate("^GET /version.txt.*?&v=([\\.\\d]+).*?User-Agent: SOGOU_UPDATER\r\n");

// QQ Pinyin(Version: 4.0)
const char *imeQQPinyin = "QQ拼音输入法";
const boost::regex imeQQPinyinUpdate("^GET /cgi-bin/pyupdate.*?Host: srf.qq.com\r\n");

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

/*
*-----------------------------------------------------------------------
* Func Name   : research
* Description : get enviroment information
* Parameter   : pktInfo, sqlConn
* Return      : bool
*-----------------------------------------------------------------------
*/
bool research(const PacketInfo *pktInfo)
{
	if (pktInfo->bodyLen < 14)
	{
		return false;
	}
	
	if (!memcmp(pktInfo->body, "GET", 3) || !memcmp(pktInfo->body, "POST", 4) || 
        !memcmp(pktInfo->body, "HEAD", 4))
	{
		char strMac[20] = {0};
		struct in_addr addr;
		addr.s_addr = pktInfo->srcIpv4;
		ParseMac(pktInfo->srcMac, strMac);
		unsigned int clue_id = get_clue_id(strMac, inet_ntoa(addr));
		if (clue_id == 0)
			return false;
	
		if (!memcmp(pktInfo->body, "GET / HTTP/1.1", 14))
			analyse_useragent(pktInfo);	

#if 0  //zhangzm
		if (research_antivirus(pktInfo))
			return true;
		if (research_input_method(pktInfo))
			return true;
#endif
	}
#if 0  //zhangzm
	//research QQ Version
	if(qqVersion.Match(pktInfo))
	{
		qqVersion.Store();
		return true;
	}
#endif

	return false;
}

/*
*-----------------------------------------------------------------------
* Func Name   : research_antivirus
* Description : get antivirus information
* Parameter   : pktInfo, sqlConn
* Return      : bool
*-----------------------------------------------------------------------
*/
bool research_antivirus(const PacketInfo *pktInfo)
{
	if (av.Match(av360Up, pktInfo, av360sd))
	{
		print(av360sd, "update");
	}
	else if (av.Match(av360safeUp, pktInfo, av360safe)) 
	{
		print(av360safe, "update");
	} 
	else if (av.Match(avKisUp, pktInfo, avKis)) 
	{
		print(avKis, "update");
	}
	else if (av.Match(avKisUp2, pktInfo, avKis)) 
	{
		print(avKis, "update");
	}
	else if (av.Match(avKisUp3, pktInfo, avKis)) 
	{
		print(avKis, "update");
	}
	else if (av.Match(avKisUp4, pktInfo, avKis)) 
	{
		print(avKis, "update");
	}
	else if (av.Match(avKsaveUp, pktInfo, avKsave))
	{
		print(avKsave, "update");
	}
	else if (av.Match(avKsaveUp2, pktInfo, avKsave))
	{		
		print(avKsave, "update");
	}
	else if (av.Match(avJiangMinUp, pktInfo, avJiangMin))
	{
		print(avJiangMin, "update");
	}
	else if (av.Match(avJiangMinUp2, pktInfo, avJiangMin))
	{
		print(avJiangMin, "update");
	}
	else if (av.Match(avJiangMinUp3, pktInfo, avJiangMin))
	{
		print(avJiangMin, "update");
	}
	else if (av.Match(avJiangMinUp4, pktInfo, avJiangMin))
	{
		print(avJiangMin, "update");
	}
	else if (av.Match(avRiSingUp, pktInfo, avRiSing))
	{
		print(avRiSing, "update");
	}
	else if (av.Match(avRiSingUp2, pktInfo, avRiSing))
	{
		print(avRiSing, "update");
	}
	else if (av.Match(avKavUp, pktInfo, avKav))
	{
		print(avKav, "update");
	}
	else if (av.Match(avAviraUp, pktInfo, avAvira))
	{
		print(avAvira, "update");
	}
	else if (av.Match(avNortonUp, pktInfo, avNorton))
	{
		print(avNorton, "update");
	}
	else if (av.Match(avNortonUp2, pktInfo, avNorton))
	{
		print(avNorton, "update");
	}
	else if (av.Match(avNod32Up, pktInfo, avNod32))
	{
		print(avNod32, "update");
	}
	else if (av.Match(avNod32Up2, pktInfo, avNod32))
	{
		print(avNod32, "update");
	}
   	else if (av.Match(avBitDefenderUp, pktInfo, avBitDefender))
	{
		print(avBitDefender, "update");
	}
   	else if (av.Match(avAvastUp, pktInfo, avAvast))
	{
		print(avAvast, "update");
	}
   	else if (av.Match(avMcAfeeUp, pktInfo, avMcAfee))
	{
		print(avMcAfee, "update");
	}
   	else if (av.Match(avAvgUp, pktInfo, avAvg))
	{
		print(avAvg, "update");
	}
   	else if (av.Match(avMseUp, pktInfo, avMse))
	{
		print(avMse, "update");
	}
	else if (av.Match(avQQPCMgrUp, pktInfo, avQQPCMgr))
	{
		print(avQQPCMgr, "update");
	}
	else
	{
		return false;
	}

	av.Store();

	return true;
}

/*
*-----------------------------------------------------------------------
* Func Name   : research_input_method
* Description : get input method information
* Parameter   : pktInfo, sqlConn
* Return      : bool
*-----------------------------------------------------------------------
*/
bool research_input_method(const PacketInfo *pktInfo)
{
	if (ime.Match(imeSogouPinyinUpdate, pktInfo, imeSogouPinyin))
	{
		print(imeSogouPinyin, "Update");
	}
	else if (ime.Match(imeQQPinyinUpdate, pktInfo, imeQQPinyin))
	{
		print(imeQQPinyin, "Update");
	}
	else
	{
		return false;
	}

	ime.Store();

	return true;
}

/*
*-----------------------------------------------------------------------
* Func Name   : print
* Description : print information
* Parameter   : s1, s2
* Return      : void
*-----------------------------------------------------------------------
*/
static void print(const string &s1, const string &s2)
{
	//cout << "[" << s1 << "]" << " " << s2 << endl;
	LOG_INFO("[%s] %s\n", s1.c_str(), s2.c_str());
}
