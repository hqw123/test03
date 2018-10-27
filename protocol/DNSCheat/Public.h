//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG Information Security Techology CO.,
//
//------------------------------------------------------------------------
//
// Module Name      :Public.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class Public 
//
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101108 tianzhao    Initial
//
//------------------------------------------------------------------------
#ifndef PUBLIC_H
#define PUBLIC_H

#include <iostream>

#include "PacketParser.h"
#include "Analyzer_log.h"

//extern Device Info for the system
extern const char * server;
extern const char * database;
extern const char * user;
extern const char * password;
extern const char * A_OUT_ETH;
extern const char * B_IN_ETH;
extern const char * C_PROXY_ETH;
extern const char * SSL_RUN;
extern const char*  SSL_DOMAIN_NAME;
extern const char*  SSL_PROXY_MODE;
extern int	AnlyzerStatus;
extern const char * lzDataPath;
extern const char * lzWebCfgPath;


#define EXE_TAG 0x6578652e // ".exe"
#define RAR_TAG 0x7261722e // ".rar"
#define ZIP_TAG 0x70697a2e // ".zip"
#define TXT_TAG 0x7478742e // ".txt"
#define DOC_TAG 0x636f642e // ".doc"
#define XLS_TAG 0x7369782e // ".xls"
using namespace std;
enum FileType
{
    FILE_EXE = 0,
    FILE_RAR = 1,
    FILE_ZIP = 2,
    FILE_TXT = 3,
    FILE_DOC = 4,
    FILE_XLS = 5,
    TYPE_NUM = 6
};

typedef struct elemType
{
	int objectid;
	string mac;
}ELEMTYPE;

//-----------------------------------------------------------------------
// Class Name  : Public
// Interface   : CheckEnvironment
// Description : 
//-----------------------------------------------------------------------
class Public
{
public:
	Public();
	virtual ~Public();
	bool CheckEnvironment();
	
	
public:
	bool DbCanConnect();
	bool CreateDir();
	bool ReadConfig();
	bool ReadSysConfig();
};

#endif
// End of file



