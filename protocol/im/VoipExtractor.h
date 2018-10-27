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
// Module Name:     VoipExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class for getting voip session. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090710 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef VOIP_EXTRACTOR
#define VOIP_EXTRACTOR
// Compiling with -lboost_thread.
#include "RtpParser.h"
#include "VoiceSession.h"
#include "XmlStorer.h"
#include "Buffer.h"
#include "Occi.h"
#include "Public.h"
#include "DampedMap.h"
//#include "threadpool/include/threadpool.hpp"
//#include "../clue/Clue.h"
#include <pcap.h>
#include <boost/thread/mutex.hpp>
#include <string>
#include <fstream>
#include <sys/stat.h>
using namespace std;

//-----------------------------------------------------------------------
// Class Name  : BaseFileExtractor
// Interface   : IsImFile
// Description : The basic class of each text extractor for IM.
//               It contain a buffer to buffer packets which are belong 
//               to IM text message. It has a thread pool also, to get
//               the message from buffer in loop, and store them to XML.
//-----------------------------------------------------------------------

class VoipExtractor
{
public:
    VoipExtractor();
    virtual ~VoipExtractor();
    // Each derivative class should implement this interface.
    virtual bool IsRtp(PacketInfo* packetInfo);
    void OnSysClosed();
    bool IsSysClosed();
    void SaveMsg(MsgNode* msgNode);
    void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing);
private:
    void PushNode(RtpPkt* rtpPkt);
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(MsgNode* msgNode);
    void StoreMsg2DB(MsgNode* msgNode, u_int clueId);
private:
    u_int protoType_;
    PublicOcci* occi_;
    oracle::occi::Statement* stmt_;
    u_int devNum_;
    char tableName_[20];
    char dataFile_[128];
    char filePath_[96];
    // Thread pool. (Need Boost lib)
//    boost::threadpool::pool threadPool_;
    RtpParser rtpParser_;
    DampedMap<IpPair>* dampedMap_;
    // Message buffer.
    Buffer<RtpPkt*>* rtpBuf_;
    // Xml file handler.
    XmlStorer xmlStorer_;
    boost::mutex sigMut_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
    bool isRunning_;
    u_int attachSize_;
    bool isDeepParsing_;
};

#endif
// End of file
