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
// Module Name:     IsTools.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the interface of PenetrationTool processor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100507 tz Initial
// $d1= -------- 1.01 001 100507 tz Add the UnBoundedExtractor module
//
//------------------------------------------------------------------------

//#include "FreeGateExtractor.h"
//#include "UnBoundedExtractor.h"
#include "PenetrationToolExtractor.h"
#include "IsTools.h"

#include "Public.h"
//#include "../clue/ProtocolID.h"

#include <iostream>

#define DB_INFO_LEN 128



bool run;

//UnBoundedExtractor* unBoundedExtractor;
//FreeGateExtractor* freeGateExtractor;
PenetrationToolExtractor* penetrationToolExtractor;
void OnToolsSysInit()
{
	run = true;
	penetrationToolExtractor = new PenetrationToolExtractor();
}

void OnToolsSysClosed(int signal)
{
	run = false;

	//delete occ;
	//std::cout << "System is closed." << std::endl;
}

//-----------------------------------------------------------------------
// Func Name   : IsTools
// Description : To check and process the Tools message.
// Parameter   : packet: The original packet from network. 
// Return      : bool
//-----------------------------------------------------------------------
bool IsTools(PacketInfo* pktInfo)
{
    bool isTools = false;
    switch (pktInfo->pktType) {
        case TCP:
            // All the process modules will delete the "pktInfo",
            // if the packet is the corresponding message.
          
			if (penetrationToolExtractor->IsTool(pktInfo)) {
				isTools = true;
			}
            
			
           
            break;
        case UDP:
			if (penetrationToolExtractor->IsTool(pktInfo)){
				isTools = true;
			}
            break;
	/*case SOCKS:
			if (penetrationToolExtractor->IsTool(pktInfo)){
				isTools = true;
			}
            break;*/
        default:
            break;
    }

    return isTools;
}





void SetStatu(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing)
{
//     switch (ProtocolID) {
// 		case PROTOCOL_ID_PENETRATION:
// 			penetrationToolExtractor->SetStatu(isRunning, attachSize, isDeepParsing);
//             break; 
// 		
//         default:
//             return; 
//     }
}

// End of file
