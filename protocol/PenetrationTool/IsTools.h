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
// Module Name      :IsTools.h
//
//------------------------------------------------------------------------
// Notes:
//      The file define the interface of PenetrationTool processor.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100507  Initial
//
//------------------------------------------------------------------------

#ifndef IS_TOOLS
#define IS_TOOLS

#include "PacketInfo.h"
bool IsTools(PacketInfo* pktInfo/*const char* packet*/);
//void OnSysInit(const char* dbUser, const char* dbPassword, const char* dbName, int deviceNum);
void OnToolsSysInit();
void OnToolsSysClosed(int signal);
//void AddFilterPort(int ProtocolID, int port);
//void ClearFilterPort();
void SetStatu(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing);

#endif
