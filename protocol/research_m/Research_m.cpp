//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.       
//                                                                       
// Copyright (C) 2010 BAIHONG Software CO., Ltd.         
//
//------------------------------------------------------------------------
//
// Module Name:     Research_m.cpp
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

#include "Research_m.h"
#include "UserAgent_m.h"
#include "../PacketParser.h"
#include <iostream>
#include <string>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

/*
*-----------------------------------------------------------------------
* Func Name   : research
* Description : get enviroment information
* Parameter   : pktInfo, sqlConn
* Return      : bool
*-----------------------------------------------------------------------
*/
bool research_m(const PacketInfo *pktInfo)
{
	if (pktInfo->bodyLen < 14)
	{
		return false;
	}
	
	if (!memcmp(pktInfo->body, "GET", 3) || !memcmp(pktInfo->body, "POST", 4) || 
        !memcmp(pktInfo->body, "HEAD", 4))
	{
		if (!memcmp(pktInfo->body, "GET / HTTP/1.1", 14))
			analyse_useragent_m(pktInfo);
	}
	
	return false;
}
