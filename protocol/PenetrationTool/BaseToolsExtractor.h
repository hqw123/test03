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
// Module Name:     BaseToolsExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class PacketParser. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100507 tz Initial
//
//------------------------------------------------------------------------
#ifndef BASE_TOOLS_EXTRACTOR
#define BASE_TOOLS_EXTRACTOR
//#include "PacketParser.h"
#include "PacketInfo.h"
#include "Public.h"
#include "XmlStor.h"
#include "Buffer.h"
//#include "Occi.h"
//#include "../clue/Clue.h"
//#include "threadpool/include/threadpool.hpp"
// Compiling with -lboost_thread.
#include <boost/thread/mutex.hpp>
#include <string>
#include <fstream>
#include <set>

using namespace std;

typedef void (*SessionProc)(MsNode*&, void*);

//-----------------------------------------------------------------------
// Class Name  : BaseToolsExtractor
// Interface   : IsTools
// Description : The basic class of each text extractor for PenetrationTool.
//               It contain a buffer to buffer packets which are belong 
//               to PenetrationTool message. It has a thread pool also, to get
//               the message from buffer in loop, and store them to XML.
//-----------------------------------------------------------------------
class BaseToolsExtractor
{
public:
    BaseToolsExtractor();
    virtual ~BaseToolsExtractor();
    // Each derivative class should implement this interface.
    virtual bool IsTool(PacketInfo* pktInfo) = 0;
    void OnSysClosed();
    bool IsSysClosed();
    void AddFilterPort(int port);
    void SetStatu(bool isRunning, u_int attachSize, bool isDeepParsing);
protected:
    void PushNode(MsNode* node);
    void RegSessionFunc(SessionProc sessionProc);
private:
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(MsNode* node);
    void StoreMsg2DB(MsNode* node, u_int clueId);
    void ProcessSession(MsNode*& node);
protected:
    u_int protoType_;   
    u_int devNum_;
    PacketInfo* pktInfo_;
    SessionProc sessionProc3_;
    char tableName_[20];
    char dataFile_[160];
    set<u_short> portSet_;
    boost::mutex setMut3_;
    bool isRunning_;
    u_int attachSize_;
    bool isDeepParsing_;
    XmlStor xmlStor_;
private:
    // The mutex for message buffer. (Need Boost lib)
    //boost::mutex bufMut_;
    // Thread pool. (Need Boost lib)
    //boost::threadpool::pool threadPool3_;
    // Map each chat session with IP and port.
    //map<string, Session*>* sessionMap_;
    // Message buffer.
    Buffer<MsNode*>* msgBuf3_;
    // Xml file handler.
   
    boost::mutex sigMut3_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
};

#endif
// End of file
