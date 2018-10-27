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
// Module Name:     BaseWebIMExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class PacketParser. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100622 tz Initial
//
//------------------------------------------------------------------------
#ifndef BASE_WEBIM_EXTRACTOR
#define BASE_WEBIM_EXTRACTOR
//#include "PacketParser.h"
#include "PacketInfo.h"
#include "Public.h"
#include "XmlStore.h"
#include "Buffer.h"
// #include "Occi.h"
// #include "../clue/Clue.h"
//#include "threadpool/include/threadpool.hpp"
// Compiling with -lboost_thread.
#include <boost/thread/mutex.hpp>
#include <string>
#include <fstream>
#include <set>

using namespace std;

typedef void (*SessionProc)(Node*&, void*);

//-----------------------------------------------------------------------
// Class Name  : BaseWebIMExtractor
// Interface   : IsTools
// Description : The basic class of each text extractor for WebIM.
//               It contain a buffer to buffer packets which are belong 
//               to WebIM message. It has a thread pool also, to get
//               the message from buffer in loop, and store them to XML.
//-----------------------------------------------------------------------
class BaseWebIMExtractor
{
public:
    BaseWebIMExtractor();
    virtual ~BaseWebIMExtractor();
    // Each derivative class should implement this interface.

    virtual bool IsWebIMText(PacketInfo* pktInfo) = 0;

    void OnSysClosed();
    bool IsSysClosed();
    void AddFilterPort(int port);
    void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing);
protected:
    void PushNode(Node* node);
    void RegSessionFunc(SessionProc sessionProc);
private:
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(Node* node);
    void StoreMsg2DB(Node* node, u_int clueId);
    void ProcessSession(Node*& node);
protected:
    u_int protoType_;
    u_int devNum_;
    PacketInfo* pktInfo_;
    SessionProc sessionProc2_;
    char tableName_[20];
    char dataFile_[160];
    set<u_short> portSet_;
    boost::mutex setMut2_;
    bool isRunning_;
    u_int attachSize_;
    bool isDeepParsing_;
    XmlStore xmlStore_;
private:
    // The mutex for message buffer. (Need Boost lib)
    //boost::mutex bufMut_;
    // Thread pool. (Need Boost lib)
//    boost::threadpool::pool threadPool2_;
    // Map each chat session with IP and port.
    //map<string, Session*>* sessionMap_;
    // Message buffer.
    Buffer<Node*>* msgBuf2_;
    // Xml file handler.
    
    boost::mutex sigMut2_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
};

#endif
// End of file
