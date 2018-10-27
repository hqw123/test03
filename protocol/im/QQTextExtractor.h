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
// Module Name:     QQTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the class QQTextExtractor to process the 
//      text messages from QQ. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081229 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef QQ_TEXT_EXTRACTOR
#define QQ_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
#include <string>
using namespace std;

//-----------------------------------------------------------------------
// Class Name  : QQTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from QQ.
//               It checks the packets if are from QQ. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class QQTextExtractor : public BaseTextExtractor
{
public:
    QQTextExtractor();
    virtual ~QQTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
    void ClearFilterPort();
private:
    void PushMassage();
    void StoreMsg2Text(const string& from, const string& to, const string& text);
    bool MatchQQ();
 
    bool MatchTM();
    bool GetQunNum();
    bool CheckPort(u_short port);
private:
    u_char qqCommand_;
    u_short offside_;
    
    u_int devNum_;//add
    char DIRECTORY[255];
};

#endif
// End of file
