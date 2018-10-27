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
// $d0= -------- 1.0  001 100622 tz Initial
//
//------------------------------------------------------------------------
#ifndef XML_STORE
#define XML_STORE
//#include "PacketParser.h"
#include "PacketInfo.h"
#include <sys/time.h>
#include <string>
#include <list>
#include <map>
#include <fstream>
#include <boost/regex.hpp>

using namespace std;
// We are interested in 2 types of message of IM, login message and text message.
enum MsgType
{
	Login = 1,
	Logout = 2,
	Text = 3,
	Qun,
	Dis
};
enum ContentType
{
	Rests =0,
	Msg = 1,
	News = 2,
	Status
};

// Define the presentation of a message node in a message list.
struct Node
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
	MsgType msgType;
	const char* fileName; // IP and port of soure address are used to name a session.
	const char* time;
	time_t timeVal;
	const char* from;
	const char* fromId;
	const char* to;
	const char* toId;
	char* text;
	u_int clueId;
	u_int device;
	int affixFlag;
	ContentType contentType;
	char* attchmentname;
	char* attchmentpath;
	u_int protocolType;
};

#define TIME_STR_SIZE 22

typedef list<Node*> MsgList;

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
class XmlStore
{
public:
    XmlStore();
    virtual ~XmlStore();
    bool DeclareXml(const char* fileName, const char* tableName, const char* version, const char* code);
    bool InsertNode(Node* node, fstream& file);
    //const char* ParseSubject(char*& subject);
    //bool InsertMsgNode(MsgNode* msgNode, const char* tableName);
    //bool InsertMsgList(const char* filename, list<MsgNode*>* msgList);
    void ClearNode(Node* node);
private:
    
    void WriteMsg(fstream& file, Node* node);
   // boost::regex* subjectDecodeRule_;
  //  boost::regex* filterRule_;
   // boost::regex* andRule_;
   // boost::regex* littleRule_;
    /*
    void WriteLogMsg(fstream& file, const MsgNode* msgNode);
    void WriteTextMsg(fstream& file, const MsgNode* msgNode);
    void WriteFileMsg(fstream& file, const MsgNode* msgNode);
    */
};

#endif
// End of file
