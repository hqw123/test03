//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2010 BaiHong Information Security Techology CO., Ltd.
// This program belongs to RYing ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise BaiHong    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     QQMsgExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the class QQMsgExtractor to process the 
//      text messages from QQ. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100831 tz Initial
//
//------------------------------------------------------------------------
#ifndef QQ_MSG_EXTRACTOR
#define QQ_MSG_EXTRACTOR

#include "BaseTextExtractor.h"
#include <string>
#include <map>

using namespace std;
struct QQkey{
    	char qqnum[11];
    	unsigned char* key1;
 	unsigned char* key2;
	unsigned char* key3_1;
	unsigned char* key3_2;
	unsigned char* key4;
	unsigned char* msgkey;
};

class QQMsgExtractor : public BaseTextExtractor
{
public:
    virtual ~QQMsgExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
    void ClearFilterPort();
    QQMsgExtractor();
	
private:
    void PushMassage();

    bool MatchQQ();
    bool MatchQQ2011();
    bool MatchTM();
    bool GetQunNum();
    bool CheckPort(u_short port);
    bool get_qqcommunication();
    //int str_to_num(char* size,int len);
	void StoreMsg2DB(MsgNode* msgNode);
	char* chang(char* str);
	
private:
    map<uint64_t,QQkey> keyMap;
    map<uint64_t,char*> myMap;
    u_short qqCommand_;
    u_short offside_;
    
    u_int devNum_;//add
    char DIRECTORY[255];
};

#endif
// End of file
