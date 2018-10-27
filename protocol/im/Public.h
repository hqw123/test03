//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 RYing Information Security Techology CO., Ltd.
// This program belongs to RYing ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise RYing    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     Public.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declare some public functions and macroes.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 081126 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef _PUBLIC_
#define _PUBLIC_

#include <string>
#include <sys/types.h>

#include "Analyzer_log.h"

// A temporary macro to log the system information.
#define LOG(errorlevel, text)(cout << "[" << #errorlevel << "]" << __FILE__ << " : " << __LINE__ << " : " \
    << __FUNCTION__<< " : " << text << endl)

// A function to get current time in standard format.
extern const char* LzDataPath;
void SetDeviceNum(int devNum);
int GetDeviceNum();
std::string* GetCurrentTime();
const char* GetTimeStr();
size_t GetUTF8LenFromUCS4(const u_int* ucs4, size_t len = 0);
size_t GetUTF8LenFromUCS2(const u_short* ucs2, size_t len = 0);
char* UCS4ToUTF8(const u_int* ucs4, size_t len = 0);
char* UCS2ToUTF8(const u_short* ucs2, size_t len = 0);
char* GBK2UTF8(char* gbk, size_t len = 0);
int DecodeQuoted(unsigned char* pDst, const char* pSrc, int nSrcLen);
char* GBK_B2UTF8(const char* base64, size_t len);
char* GBK_Q2UTF8(const char* qp, size_t len);
char* Base2UTF8(const char* base64, size_t len);
char* QP2UTF8(const char* qp, size_t len);

#endif
//End of file
