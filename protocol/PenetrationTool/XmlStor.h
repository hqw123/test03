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
// Module Name:     XmlStore.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class XmlStore. And defines 
//      some structure for the class. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100507 tz Initial
//
//------------------------------------------------------------------------
#ifndef XML_STOR
#define XML_STOR
//#include "PacketParser.h"
#include "PacketInfo.h"
#include <sys/time.h>
#include <string>
#include <list>
#include <map>
#include <fstream>
#include <boost/regex.hpp>

using namespace std;



// Define the presentation of a message node in a message list.
struct MsNode
{
    u_char srcMac[6];   // 6 bytes
    u_char destMac[6];  // 6 bytes
    u_int srcIpv4;     // 4 bytes
    u_int destIpv4;    // 4 bytes
    u_short srcPort;    // 2 bytes
    u_short destPort;   // 2 bytes
    u_short bodyLen;    // 2 bytes
    // Keep above data sync with PakectInfo struct 26 Bytes
    u_short nothing;

    const char* fileName; // IP and port of soure address are used to name a session.
    const char* time;
    time_t timeVal;

    
    u_int clueId;
    u_int device;
 
    int affixFlag;
	u_int protocolType;
	char pppoe[60];
};

#define TIME_STR_SIZE 22

typedef list<MsNode*> MsgList;

// A session contain a message stream from 2 address.
struct Session
{
    char* fileName; // IP and port of soure address are used to name a session.
    int msgNum;
    MsgList* msgList;
};

// Map the session with the source IP and port.
typedef map<string, Session*> SessionMap;

//-----------------------------------------------------------------------
// Class Name  : XmlStore
// Interface   : DeclareXml; InsertMsgNode; InsertMsgList
// Description : The class is used to store IM messages to XML files.
//               It provides some functions to create a XML file, to 
//               insert a message or a message list to an existed XML 
//               file anytime.
//-----------------------------------------------------------------------
class XmlStor
{
public:
    XmlStor();
    virtual ~XmlStor();
    bool DeclareXml(const char* fileName, const char* tableName, const char* version, const char* code);
    bool InsertNode(MsNode* node, fstream& file);
    void ClearNode(MsNode* node);
    //const char* ParseSubject(char*& subject);
    //bool InsertMsgNode(MsgNode* msgNode, const char* tableName);
    //bool InsertMsgList(const char* filename, list<MsgNode*>* msgList);
private:
    
    void WriteMsg(fstream& file, MsNode* node);
   // boost::regex* subjectDecodeRule_;
    //boost::regex* filterRule_;
    //boost::regex* andRule_;
    //boost::regex* littleRule_;
    /*
    void WriteLogMsg(fstream& file, const MsgNode* msgNode);
    void WriteTextMsg(fstream& file, const MsgNode* msgNode);
    void WriteFileMsg(fstream& file, const MsgNode* msgNode);
    */
};

#endif
// End of file
