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
// Module Name:     BaseTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class PacketParser. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 081212 Zjz Initial
//
//------------------------------------------------------------------------
#ifndef BASE_TEXT_EXTRACTOR
#define BASE_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "PacketInfo.h"
#include "Public.h"
#include "XmlStorer.h"
#include "Buffer.h"
//#include "../clue/Clue.h"
//#include "threadpool/include/threadpool.hpp"
// Compiling with -lboost_thread.
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>
#include <string>
#include <fstream>
#include <set>

using namespace std;

typedef void (*SessionProc)(MsgNode*&, void*);

//-----------------------------------------------------------------------
// Class Name  : BaseTextExtractor
// Interface   : IsImText
// Description : The basic class of each text extractor for IM.
//               It contain a buffer to buffer packets which are belong 
//               to IM text message. It has a thread pool also, to get
//               the message from buffer in loop, and store them to XML.
//-----------------------------------------------------------------------
class BaseTextExtractor
{
public:
    BaseTextExtractor();
    virtual ~BaseTextExtractor();
    // Each derivative class should implement this interface.
    virtual bool IsImText(PacketInfo* pktInfo) = 0;
    void OnSysClosed();
    bool IsSysClosed();
   // void AddFilterPort(int port);
    //void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing);
protected:
    void PushNode(MsgNode* msgNode);
    void RegSessionFunc(SessionProc sessionProc);
	void StoreImDb(Im_MsgNode* msgNode);
	
private:
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(MsgNode* msgNode);
   // void StoreMsg2DB(MsgNode* msgNode, u_int clueId);
    void ProcessSession(MsgNode*& msgNode);
protected:
	boost::regex* MLoginRule_;
	
    u_int protoType_;
    //u_int protoId_;
    u_int devNum_;
    PacketInfo* pktInfo_;
    SessionProc sessionProc_;
    char tableName_[20];
    char dataFile_[160];
    set<u_short> portSet_;
    boost::mutex setMut_;
    bool isRunning_;
    u_int attachSize_;
    bool isDeepParsing_;
	XmlStorer xmlStorer_;
private:
    // The mutex for message buffer. (Need Boost lib)
    //boost::mutex bufMut_;
    // Thread pool. (Need Boost lib)
    //boost::threadpool::pool threadPool_;
    // Map each chat session with IP and port.
    //map<string, Session*>* sessionMap_;
    // Message buffer.
    Buffer<MsgNode*>* msgBuf_;
    // Xml file handler.
    
    boost::mutex sigMut_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
};

#endif
// End of file
