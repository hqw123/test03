//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 baihong Information Security Techology CO., Ltd.
// This program belongs to baihong ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise baihong    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     MSNTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file define the class MSNTextExtractor to process the 
//      text messages from MSN. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081129 Zhao Junzhe Initial
// $d1= -------- 1.01 001 081202 Zhao Junzhe Refactor the class
//
//------------------------------------------------------------------------
#ifndef MSN_TEXT_EXTRACTOR
#define MSN_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>
#include <map>
using namespace std;
struct Chat{
	string sender;
	string recver;
};
//-----------------------------------------------------------------------
// Class Name  : MSNTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from MSN.
//               It checks the packets if are from MSN. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class MSNTextExtractor : public BaseTextExtractor
{
public:
    MSNTextExtractor();
    virtual ~MSNTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
    void ClearFilterPort();
private:
    //bool MatchMSN();
   // bool GetFriends();
    //void StoreUsrInfo2Text(const string& usrName);
    //void StoreRecvInfo2Text(const string& from, const string& text);
    //void StoreSendInfo2Text(const string& text);
    //bool ParseMSN(char*& from, char*& text);
    //bool ParseRecvMSN(char*& from, char*& text);
    //bool ParseSendlxMSN(char*& to, char*& text);
    bool CheckPort(u_short port);
    //void GetBuddy(char* data);
	void StoreMsg2DB(MsgNode* msgNode);
private:
    // The rule of regular expression to match a message while the user login.
   /* boost::regex* loginRule_;
    // The rule of regular expression to match a message receiving from an address.
    boost::regex* recvHeadRule_;
    boost::regex* sendlxHeadRule_;
    // The rule of regular expression to match a message sending from an address.
    //boost::regex* sendRule_;
    boost::regex* headRule_;
    boost::regex* msgRule_;
    boost::regex* pingRule_;
    boost::regex* listRule_;
    u_int msnTag_;*/
	boost::regex* loginRule_;
	boost::regex* logoutRule_;
	//boost::regex* senderRule_;
	boost::regex* recverRule_;
	boost::regex* sendMsgRule_;
	boost::regex* recvMsgRule_;
	boost::regex* sendlxMsgRule_;
	boost::regex* listRule_;
	boost::regex* groupRule_;
	boost::regex * list1_;
	boost::regex * list2_;
	map<uint64_t,Chat>keyMap;
	char DIRECTORY[255];
};

#endif
// End of file
