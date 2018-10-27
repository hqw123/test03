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
// Module Name:     UCFileExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the classes for the file extraction from 
//      transfering between SinaUCs.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090212 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef UC_FILE_EXTRACTOR
#define UC_FILE_EXTRACTOR

//#include "PacketParser.h"
#include "BaseFileExtractor.h"
#include <iostream>

class UCFileExtractor : public BaseFileExtractor
{
public:
    UCFileExtractor();
    virtual ~UCFileExtractor();
    bool IsImFile(PacketInfo* pktInfo);
private:
    void PushMassage(char* srcFileName, const char* timeStr);
private:
    DampedMap<uint64_t>* dampedMap_;
    char DIRECTORY[255];
    char SUB_DIREC[255];
};

#endif
// End of file.
