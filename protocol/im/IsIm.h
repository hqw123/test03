//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2010 baihong software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name      :IsIm.h
//
//------------------------------------------------------------------------
// Notes:
//      The file define the interface of IM processor.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 081126 Wuzhonghua Initial
//
//------------------------------------------------------------------------

#ifndef IS_IM
#define IS_IM

#include "PacketInfo.h"

bool IsIm(PacketInfo* pktInfo);
void OnImSysInit();
void OnSysClosed(int signal);
//void AddFilterPort(int ProtocolID, int port);
void ClearFilterPort();
void SetStatus(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing, u_int miniSize=0);

#endif
