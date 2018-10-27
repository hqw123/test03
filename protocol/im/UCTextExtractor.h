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
// Module Name:     UCTextExtractor.h
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the class UCTextExtractor to process the 
//      text messages from UC. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081205 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#ifndef UC_TEXT_EXTRACTOR
#define UC_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
#include "UCCrypt.h"
#include <string>
using namespace std;
// The lenth of header of UC protocol.
#define UC_HLEN      0x0D
#define UC_BEGIN_TAG 0x01
#define UC_UNKNOWN2  0x00010000
// Types of UC message.
#define UC_STORE_1   0x008D
#define UC_STORE_2   0x008E
#define UC_TALK_1    0x03E9
#define UC_TALK_2    0x0487
#define UC_CMD_REDIR 0x00A2

// Memory alignment with 1 byte for this structure.
/*
#pragma pack(1)
// The structure defines the header of UC application protocol.
struct UCHead
{
    u_char  beginTag;  //always 0x01.
    u_short sn;        //uc packet sequence number.
    u_int   unknown1;  //unknown yet. 
    u_int   unknown2;  //always 0x00010000.
    u_short cipherLen; //cipher data length.
    u_char data[1]; //cipher data length.
};
#pragma pack()
*/
//-----------------------------------------------------------------------
// Class Name  : UCTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from UC.
//               It checks the packets if are from UC. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class UCTextExtractor : public BaseTextExtractor
{
public:
    UCTextExtractor();
    virtual ~UCTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool IsRoomText();
    void PushMassage();
    static void ProcUCSession(MsgNode*& msgNode, void* obj);
    void StoreMsg2Text(const string& from, const string& to, const string& text);
private:
    // Header pointer of UC protocol.
    //const UCHead* ucHead_;
    u_short cipherLen_;
    UCCrypt ucCrypt_;
    char DIRECTORY[255];
};

#endif
// End of file
