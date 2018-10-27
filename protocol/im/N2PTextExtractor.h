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
// Module Name:     N2PTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file define the class N2PTextExtractor to process the 
//      text messages from Net2Phone. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081202 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef N2P_TEXT_EXTRACTOR
#define N2P_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>

using namespace std;

//-----------------------------------------------------------------------
// Class Name  : N2PTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Net2Phone.
//               It checks the packets if are from Net2Phone. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class N2PTextExtractor : public BaseTextExtractor
{
public:
    N2PTextExtractor();
    virtual ~N2PTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchN2P();
    void StoreUsrInfo2Text(const string& usrName);
    void StoreRecvInfo2Text(const string& usrName, const string& text);
    void StoreSendInfo2Text(const string& usrName, const string& text);
private:
    // The rule of regular expression to match a message while the user login.
    boost::regex* loginRule_;
    // The rule of regular expression to match a message receiving from an address.
    boost::regex* recvRule_;
    // The rule of regular expression to match a message sending from an address.
    boost::regex* sendRule_;
    char DIRECTORY[255];
};

#endif
// End of file
