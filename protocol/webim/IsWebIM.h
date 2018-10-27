//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2010 BaiHong Information Security Techology CO., Ltd.
// This program belongs to BaiHong ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise BaiHong    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name      :IsWebIM.h
//
//------------------------------------------------------------------------
// Notes:
//      The file define the interface of WEBIM processor.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100622 tz Initial
//
//------------------------------------------------------------------------

#ifndef IS_WEBIM
#define IS_WEBIM

#include "PacketInfo.h"

bool IsWebIM(PacketInfo* pktInfo/*const char* packet*/);
//void OnSysInit(const char* dbUser, const char* dbPassword, const char* dbName, int deviceNum);
void OnWebIMSysInit();
void OnWebIMSysClosed(int signal);
//void AddFilterPort(int ProtocolID, int port);
//void ClearFilterPort();
void SetStatus(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing);

#endif
