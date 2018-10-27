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
// Module Name:     VoipExtractor.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class VoipExtractor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081210 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#include "VoipExtractor.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>

const int BUF_SIZE = 512;
const u_int MAP_SIZE = 512;
const u_short CHECK_TIME = 2;
const u_short DEL_TIMES = 3;
#define MOVE_PATH          "/home/nodeData"
#define DIRECTORY          "/home/nodeData/moduleData/VOIP"
#define SUB_DIREC          "/home/nodeData/moduleData/VOIP/File"
#define TABLE_NAME         "VOIP"


//-----------------------------------------------------------------------
// Func Name   : VoipExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
VoipExtractor::VoipExtractor()
{
    protoType_ = PROTOCOL_VOIP;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    sprintf(filePath_, "%s\0", SUB_DIREC);

    sprintf(dataFile_, "%s/VOIP\0", DIRECTORY);
    sprintf(tableName_, "VOIP\0");
    msgNum_ = 0;
    devNum_ = GetDeviceNum();
    dampedMap_ = new DampedMap<IpPair>(MAP_SIZE, CHECK_TIME, DEL_TIMES);
    rtpBuf_ = new Buffer<RtpPkt*>(BUF_SIZE);
    sysClosed_ = false;
    //threadPool_.size_controller().resize(1);
    //threadPool_.schedule(boost::bind(&LoopStore, this));
}

//-----------------------------------------------------------------------
// Func Name   : ~VoipExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
VoipExtractor::~VoipExtractor()
{
#if 0  //zhangzm
    occi_->TerminateStmt(stmt_);
#endif
    delete rtpBuf_;
    delete dampedMap_;
}

//-----------------------------------------------------------------------
// Func Name   : ~VoipExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void VoipExtractor::OnSysClosed()
{
    {
        boost::mutex::scoped_lock lock(sigMut_);
        sysClosed_ = true;
    }
    //threadPool_.wait();
   // cout << typeid(*this).name() << " is closed." << endl;
   LOG_INFO("%s is closed.\n",typeid(*this).name());
}

bool VoipExtractor::IsSysClosed()
{
    bool isClosed;
    {
        boost::mutex::scoped_lock lock(sigMut_); 
        isClosed = sysClosed_;
    }

    return isClosed;
}

bool VoipExtractor::IsRtp(PacketInfo* packetInfo)
{
    RtpPkt* rtpPkt = rtpParser_.Parse(packetInfo);
    if (rtpPkt) 
	{
        //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "IsRtp!" << endl;
        PushNode(rtpPkt);
        return true;
    }

    return false;
}

//-----------------------------------------------------------------------
// Func Name   : PushNode
// Description : Push the message nodes into messge list in a session.
// Parameter   : fileName: The name of file you want to put the node in.
//               msgNode: Interested information in a network packet.
// Return      : void
//-----------------------------------------------------------------------
void VoipExtractor::PushNode(RtpPkt* rtpPkt)
{
    //assert(rtpPkt != NULL);
	if (rtpPkt == NULL)
		return;
	
    rtpBuf_->Push(rtpPkt);
}

//-----------------------------------------------------------------------
// Func Name   : LoopStore
// Description : Store the session into XML in loop. Thread function.
// Parameter   : obj: the object of this class for thread function.
// Return      : void
//-----------------------------------------------------------------------
void VoipExtractor::LoopStore(void* obj)
{
    //assert(obj != NULL);
    if (obj == NULL)
		return;
	
    // Impress an object of VoipExtractor into this thread function.
    VoipExtractor* extractor = reinterpret_cast<VoipExtractor*>(obj);
    // Do loop.
    while (true) 
	{
        if (extractor->IsSysClosed()) 
		{
           // cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Sys closed!" << endl;
           LOG_INFO("Sys closed!\n");
            break;
        }
        usleep(50);
        extractor->CheckBuf();
    }
}

//-----------------------------------------------------------------------
// Func Name   : CheckBuf
// Description : Get the session from the session buffer.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void VoipExtractor::CheckBuf()
{
    VoiceSession* voiceSession = NULL;
    RtpPkt* rtpPkt = rtpBuf_->Pop();
    if (rtpPkt) {
        IpPair ipPair(rtpPkt->srcIpv4, rtpPkt->srcPort, rtpPkt->destIpv4, rtpPkt->destPort);
        //cout << "Find ipPair" << endl;
        voiceSession = reinterpret_cast<VoiceSession*>(dampedMap_->Find(ipPair));
        //cout << "Find OK" << endl;
        if (voiceSession) {
            if (!voiceSession->AddPacket(rtpPkt)) {
                //cout << "Pop IpPair" << endl;
                dampedMap_->Pop(ipPair);
                //cout << "Pop OK" << endl;
                return;
            }
            voiceSession->SetZero();
        } else {
            voiceSession = new VoiceSession(this, filePath_);
            voiceSession->AddPacket(rtpPkt);
            voiceSession->SetZero();
            //cout << "Push a session" << endl;
            dampedMap_->Push(ipPair, voiceSession);
            //cout << "Push OK" << endl;
            return;
        }
    }
}

void VoipExtractor::MoveDataFile()
{
    char destPath[256];
    time_t timeVal;
    time(&timeVal);
    sprintf(destPath, "%s/%lu/%s_%lu.xml\0", MOVE_PATH, (timeVal/300)%12, TABLE_NAME, timeVal);
    ::rename(dataFile_, destPath);
}

void VoipExtractor::SaveMsg(MsgNode* msgNode)
{
    if (!msgNode) {
        return;
    }
    if (msgNode->clueId) {
       // cout << "[" << tableName_ << "]: Data for case! Clue ID is " << msgNode->clueId << endl;
        LOG_INFO("%s: Data for case! Clue ID is %d\n",tableName_,msgNode->clueId);
        StoreMsg2DB(msgNode, msgNode->clueId);
    }
    if (msgNum_ >= 10) {
        file_.close();
        MoveDataFile();
        msgNum_ = 0;
    }
    if (msgNum_ == 0) {
        xmlStorer_.DeclareXml(dataFile_, tableName_, NULL, NULL);
        file_.open(dataFile_, ios::out | ios::in);
    }
    StoreMsg2Xml(msgNode);
    ++msgNum_;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2Xml
// Description : Create XML file and store the messges into it.
// Parameter   : session: A session correspond to an XML file.
// Return      : void
//-----------------------------------------------------------------------
void VoipExtractor::StoreMsg2Xml(MsgNode* msgNode)
{
    //assert(msgNode != NULL);
	if (msgNode == NULL)
		return;
	
    // Check the file if exist.
    xmlStorer_.InsertMsgNode(msgNode, file_);
}


void VoipExtractor::StoreMsg2DB(MsgNode* msgNode, u_int clueId)
{
#if 0  //zhangzm VOIP
    struct in_addr addr;
    occi_->SetInt(stmt_, 1, devNum_);
    occi_->SetInt(stmt_, 2, clueId);
    addr.s_addr = msgNode->srcIpv4;
    occi_->SetString(stmt_, 3, inet_ntoa(addr));
    occi_->SetInt(stmt_, 4, msgNode->srcPort);
    addr.s_addr = msgNode->destIpv4;
    occi_->SetString(stmt_, 5, inet_ntoa(addr));
    occi_->SetInt(stmt_, 6, msgNode->destPort);
    occi_->SetTime(stmt_, 7, msgNode->timeVal);
    occi_->SetString(stmt_, 8, msgNode->path);
    occi_->DoSql(stmt_);
#endif
}

void VoipExtractor::SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing)
{
    isRunning_ = isRunning;
    attachSize_ = attachSize;
    isDeepParsing_ = isDeepParsing;
}

// End of file.
