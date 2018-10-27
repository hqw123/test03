//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2010 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     Research_m.h
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

#ifndef RESEARCH_M_H
#define RESEARCH_M_H

#include "../PacketParser.h"

//void research_useragent(const PacketInfo *pPkt);
bool research_m(const PacketInfo *pktInfo);

#endif /* RESEARCH_M_H */
