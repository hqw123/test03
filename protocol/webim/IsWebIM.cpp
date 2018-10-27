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
// Module Name:     IsWebIM.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the interface of WEBIM processor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100622 tz Initial
// $d1= -------- 1.01 001 100622 tz Add the WebQQ module
//
//------------------------------------------------------------------------

#include "WebMSNExtractor.h"
#include "WebQQExtractor.h"
#include "WebWWExtractor.h"
#include "WebSearchExtractor.h"

#include "IsWebIM.h"
#include "Public.h"
//#include "../clue/ProtocolID.h"

#include <iostream>

#define DB_INFO_LEN 128

bool runn = false;

//WebQQExtractor *webQQExtractor = NULL;
//WebMSNExtractor *webMSNExtractor = NULL;
WebWWExtractor *webWWExtractor = NULL;
WebSearchExtractor *webSearchExtractor = NULL;

void OnWebIMSysInit()
{
    runn = true;
   
    //webQQExtractor = new WebQQExtractor();
    //webMSNExtractor = new WebMSNExtractor();
    webWWExtractor = new WebWWExtractor();
    webSearchExtractor = new WebSearchExtractor();
}

void OnWebIMSysClosed(int signal)
{
	runn = false;

	//delete webQQExtractor;
	//delete webMSNExtractor;
	delete webWWExtractor;
	delete webSearchExtractor;
	
	//std::cout << "System is closed." << std::endl;
}

//-----------------------------------------------------------------------
// Func Name   : IsWebIM
// Description : To check and process the WebIM message.
// Parameter   : packet: The original packet from network. 
// Return      : bool
//-----------------------------------------------------------------------
bool IsWebIM(PacketInfo* pktInfo)
{
    bool isWebIM = false;
    switch (pktInfo->pktType) {
        case TCP:
            // All the process modules will delete the "pktInfo",
            // if the packet is the corresponding message.
          
		/*if (webQQExtractor->IsWebIMText(pktInfo)) {
                isWebIM = true;

		}*/
		/*   //closed by zhangzm
		else if (webMSNExtractor->IsWebIMText(pktInfo)) {
                isWebIM = true;
		}
		*/
		/*   //closed by zhangzm
		if (webWWExtractor->IsWebIMText(pktInfo)) {
                isWebIM = true;
		}*/
		if (webSearchExtractor->IsWebIMText(pktInfo)) {
                isWebIM = true;
		}

            break;
        case UDP:
			
            break;
        default:
            break;
    }

    return isWebIM;
}

void SetStatus(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing)
{
//     switch (ProtocolID) {
// 	    case PROTOCOL_ID_WEBPAGECHAT:
// 			webQQExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 			webMSNExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
//             break; 
// 		
//         default:
//             return; 
//     }
}

// End of file
