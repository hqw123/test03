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
// Module Name:     PopExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the classes for the email extraction from 
//      POP sessions.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090812 wu zhonghua Initial
//
//------------------------------------------------------------------------
#ifndef POP_EXTRACTOR
#define POP_EXTRACTOR

#include "PacketInfo.h"
#include "DampedMap.h"
#include "PopSession.h"
#include "BaseFileExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <iostream>
#include <string>
using namespace std;


class PopExtractor : public BaseFileExtractor
{
	public:
		PopExtractor();
		virtual ~PopExtractor();
		bool IsFile(PacketInfo* packetInfo);
		void PushMsg(MsgNode* msgNode) { PushNode(msgNode); }
		void StoreMsg2DB(MsgNode* msgNode);
	
	private:
		uint64_t GetKey(PacketInfo* packetInfo);
		const char* GetUser(PacketInfo* packetInfo);
		
	private:
		boost::regex* statusRule_[POP_STATUS_NUM];
		boost::regex* dateRule_;
		boost::regex* fromRule_;
		boost::regex* toRule_;
		boost::regex* ccRule_;
		boost::regex* subjectRule_;
		boost::regex* contentTypeRule_;
		boost::regex* mailAddressRule_;
		char filePath_[96];
		DampedMap<uint64_t>* dampedMap_;
		char DIRECTORY[255];
		char SUB_DIREC[255];
	
};

#endif

// End of file.
