//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 baihong Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     PopSession.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class for POP session catching
//
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100227  zhonghua Initial
//
//------------------------------------------------------------------------
#ifndef POP_SESSION
#define POP_SESSION

#include "PacketInfo.h"
#include "BaseFileExtractor.h"
#include <boost/regex.hpp>
#include <iostream>
#include <fstream>

enum PopStatus
{
    POP_LOGIN_STAT = 0,
	POP_RETRIEVE = 1,
	POP_QUIT=3
};

const u_short POP_STATUS_NUM = 8;
const u_short POP_HEAD_BUF_SIZE = 4096;

class PopSession : public FileSession
{
public:
    PopSession(void* obj,
               const char* filePath,
               boost::regex** statusRule,
			   boost::regex* dateRule,
			   boost::regex* fromRule,
			   boost::regex* toRule,
			   boost::regex* ccRule,
			   boost::regex* subjectRule,
			   boost::regex* contentTypeRule,
			   boost::regex* mailAddressRule,
               const char* user,
               u_int maxSize);
    ~PopSession();
    bool AddPacket(PacketInfo* packetInfo);
private:
	void AnalysisEmlBuf();
    void PushMsg();
	void OnLoginStat();
    void OnRetr();
    void Clear();
    bool IsQuit();
	void GetTag(char*& tag, boost::regex* tagRule,bool loop);
	bool CreateFile();
private:
    PacketInfo* packetInfo_;
    PopStatus popStatus_;
    void* obj_;
    char* fileName_;
    bool validMail_;
	bool isStartList_;
    const char* filePath_;
    boost::regex* statusRule_[POP_STATUS_NUM];
    u_int* emailList_;
    u_int emailSum_;
    u_int emailNum_;
    u_int maxSize_;
	u_int fistBodyLen_;
	
	//login info
	const char* user_;
	char* pass_;
	
	//emlbuf sotre packet
	char* emlBuf_;
	u_int emlBufSize;
	u_int baseSeq_;
	u_int retrMailSize_;

	//email head
	char* date_;
    char* from_;
    char* to_;
	char* cc_;  //  抄送人
    char* subject_;
	char* contentType_;
	char* boundary_;
    

	boost::regex* dateRule_;
    boost::regex* fromRule_;
    boost::regex* toRule_;
	boost::regex* ccRule_;
    boost::regex* subjectRule_;
	boost::regex* contentTypeRule_;
	boost::regex* mailAddressRule_;

//	const char *strLocalIP_;
};

#endif

// End of file
