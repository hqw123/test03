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
// Module Name:     IsWebSNS.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the interface of WEBSNS processor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100622 tz Initial
// $d1= -------- 1.01 001 100622 tz Add the WebQQ module
//
//------------------------------------------------------------------------

//#include "WebQQExtractor.h"
#include "WebFACEBOOKExtractor.h"
#include "IsWebSNS.h"
#include "Public.h"
//#include "../clue/ProtocolID.h"
#include <iostream>

#define DB_INFO_LEN 128

bool sns_run;

//WebQQExtractor*  webQQExtractor;
WebFACEBOOKExtractor* webFACEBOOKExtractor = NULL;

void OnWebSNSSysInit()
{
	sns_run = true;
	//webQQExtractor = new WebQQExtractor();
	webFACEBOOKExtractor = new WebFACEBOOKExtractor();
}

void OnWebSNSSysClosed(int signal)
{
	sns_run = false;
	//std::cout << "System is closed." << std::endl;
}

//-----------------------------------------------------------------------
// Func Name   : IsWebSNS
// Description : To check and process the WebIM message.
// Parameter   : packet: The original packet from network. 
// Return      : bool
//-----------------------------------------------------------------------
bool IsWebSNS(PacketInfo* pktInfo)
{
	bool isWebSNS = false;
	switch (pktInfo->pktType) {
		case TCP:
		// All the process modules will delete the "pktInfo",
		// if the packet is the corresponding message.
			if /*(webQQExtractor->IsWebSNSText(pktInfo)){
				isWebSNS = true;

			}else if*/(webFACEBOOKExtractor->IsWebSNSText(pktInfo)){
				isWebSNS = true;

			}

            break;
        case UDP:
			
            break;
        default:
            break;
    }

    return isWebSNS;
}





//void SetStatus(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing)
//{
//     switch (ProtocolID) {
// 	    case PROTOCOL_ID_WEBPAGECHAT:
// 			webQQExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 			webMSNExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
//             break; 
// 		
//         default:
//             return; 
//     }
//}

// End of file
