//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2010 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     Research.h
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

#ifndef RESEARCH_H
#define RESEARCH_H

#include "../PacketParser.h"
#include "UserAgent.h"

void research_useragent(const PacketInfo *pPkt);
bool research(const PacketInfo *pktInfo);
bool research_antivirus(const PacketInfo *pktInfo);
bool research_input_method(const PacketInfo *pktInfo);

#endif /* RESEARCH_H */
