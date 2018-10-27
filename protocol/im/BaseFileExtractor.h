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
// Module Name:     BaseFileExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the functions of class BaseFileExtractor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081212 Zhao Junzhe Initial
// $d1= -------- 1.00 002 090806 Zhao Junzhe Using the FileStream class to 
//                                           refine the FileSession
//
//------------------------------------------------------------------------
#ifndef BASE_FILE_EXTRACTOR
#define BASE_FILE_EXTRACTOR
#include "PacketInfo.h"
#include "XmlStorer.h"
#include "Buffer.h"
#include "Public.h"
//#include "threadpool/include/threadpool.hpp"
#include "DampedMap.h"
#include "FileStream.h"
//#include "../clue/Clue.h"
// Compiling with -lboost_thread.
#include <boost/thread/mutex.hpp>
#include <string>
#include <fstream>
using namespace std;

class FileSession : public DampedData
{
public:
    FileSession();
    virtual ~FileSession();
    virtual bool AddPacket(PacketInfo* pktInfo) = 0;
protected:
    FileStream* fileStream_;
};

//-----------------------------------------------------------------------
// Class Name  : BaseFileExtractor
// Interface   : IsImFile
// Description : The basic class of each text extractor for IM.
//               It contain a buffer to buffer packets which are belong 
//               to IM text message. It has a thread pool also, to get
//               the message from buffer in loop, and store them to XML.
//-----------------------------------------------------------------------
typedef void (*SessionProc)(MsgNode*&, void*);
class BaseFileExtractor
{
public:
    BaseFileExtractor();
    virtual ~BaseFileExtractor();
    // Each derivative class should implement this interface.
    virtual bool IsFile(PacketInfo* pktInfo) = 0;
    void OnSysClosed();
    bool IsSysClosed();
	void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing,u_int miniSizes);
protected:
    void PushNode(MsgNode* msgNode);
    void RegSessionFunc(SessionProc sessionProc);
    virtual void StoreMsg2DB(MsgNode* msgNode) = 0;
private:
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(MsgNode* msgNode);
   
    void ProcessSession(MsgNode*& msgNode);
protected:
    u_int protoType_;
    u_int protoId_;

    u_int devNum_;
    PacketInfo* pktInfo_;
    SessionProc sessionProc_;
    char tableName_[20];
    char dataFile_[256];
    bool isRunning_;
    u_int attachSize_;
	u_int miniSize_;
    bool isDeepParsing_;
    // Xml file handler.
    XmlStorer xmlStorer_;
private:
    // Thread pool. (Need Boost lib)
    //boost::threadpool::pool threadPool_;
    // Message buffer.
    Buffer<MsgNode*>* msgBuf_;
    boost::mutex sigMut_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
};

#endif
// End of file
