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
// Module Name:     YahooTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the class YahooTextExtractor to process the 
//      text messages from Yahoo. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081205 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef YAHOO_TEXT_EXTRACTOR
#define YAHOO_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
//#include <boost/regex.hpp>
#include <string>
#include <map>
using namespace std;
// The lenth of header of Yahoo protocol.
const int YAHOO_HLEN = 20;
// The structure defines the header of Yahoo application protocol.
struct YahooHead
{
    u_int id;
    u_int ver;
    u_short contentLen;
    u_short service;
    u_int status;
    u_int session;
};
struct LogIn{
	string from;
};

//-----------------------------------------------------------------------
// Class Name  : YahooTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Yahoo.
//               It checks the packets if are from Yahoo. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class YahooTextExtractor : public BaseTextExtractor
{
public:
    YahooTextExtractor();
    virtual ~YahooTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
    void ClearFilterPort();
private:
    bool PushMassage();
    //static void ProcYahooSession(MsgNode* msgNode, void* obj);
    int GetItemLen(const char* body, short bodylen, int offset);
    bool ParseYahooMsg(const char* body,
                       short bodylen,
                       MsgNode* sendNode);
    void StoreMsg2Text(const string& from, const string& to, const string& text);
    bool CheckPort(u_short port);
	void StoreMsg2DB(MsgNode* msgNode);
private:
    // The rule of regular expression to match a Yahoo text message.
    //boost::regex* msgRule_;
    // Header pointer of Yahoo protocol.
    const YahooHead* yahooHead_;
    map<uint64_t,LogIn>keyMap;
    char DIRECTORY[255];
};

#endif
// End of file
