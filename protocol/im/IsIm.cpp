//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 Baihong Information Security Techology CO., Ltd.
// This program belongs to Baihong ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise Baihong    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     IsIm.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the interface of IM processor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081126 Zhao Junzhe Initial
// $d1= -------- 1.01 001 081129 Zhao Junzhe Add the MSN text module
// $d2= -------- 1.02 001 081202 Zhao Junzhe Add the Net2Phone text module
// $d3= -------- 1.03 001 081205 Zhao Junzhe Add the Yahoo text module
// $d4= -------- 1.04 001 081211 Zhao Junzhe Add the Fetion text module
//
//------------------------------------------------------------------------

#include "PopExtractor.h"
#include "FetionTextExtractor.h"
#include "SkypeTextExtractor.h"
#include "MSNTextExtractor.h"
#include "YahooTextExtractor.h"
#include "QQMsgExtractor.h"
#include "QQFileExtractor.h"
#include "GambleAccountExtractor.h"
#include "AndroidFetionTextExtractor.h"
#include "AndroidMiliaoTextExtractor.h"
#include "AndroidWeixinTextExtractor.h"
#include "WangwangTextExtractor.h"
#include "GtalkTextExtractor.h"
#include "AndroidQQTextExtractor.h"
#include "AndroidMomoTextExtractor.h"
#include "AndroidQtalkTextExtractor.h"
#include "AndroidYYTextExtractor.h"
#include "AndroidTangoTextExtractor.h"
#include "AndroidCocoTextExtractor.h"
#include "AndroidTalkboxTextExtractor.h"
#include "AndroidKuaiyaTextExtractor.h"
#include "AndroidHiTextExtractor.h"
#include "AndroidVoxerTextExtractor.h"
#include "AndroidWhatsappTextExtractor.h"
#include "AndroidZelloTextExtractor.h"
#include "AndroidTelegramTextExtractor.h"
#include "AndroidSkypeTextExtractor.h"
#include "AndroidBBMTextExtractor.h"
#include "AndroidKaKaotalkTextExtractor.h"
#include "AndroidOovooTextExtractor.h"
#include "AndroidZaloTextExtractor.h"
#include "AndroidAireTalkTextExtractor.h"
#include "AndroidNimbuzzTextExtractor.h"
#include "AndroidLineTextExtractor.h"
#include "AndroidViberTextExtractor.h"
#include "AndroidDropboxTextExtractor.h"
#include "AndroidKeechatTextExtractor.h"
#include "IsIm.h"
//#include "Occi.h"
#include "Public.h"
//#include "../ProtocolID.h"

#include <iostream>

#define DB_INFO_LEN 128
#define IS_IM_MOVE 1

bool running;

PopExtractor* popExtractor = NULL;
FetionTextExtractor* fetionTextExtractor = NULL;
SkypeTextExtractor* skypeTextExtractor = NULL;
//MSNTextExtractor* msnTextExtractor = NULL;
YahooTextExtractor* yahooTextExtractor = NULL;
QQMsgExtractor* qqMsgExtractor = NULL;
QQFileExtractor* qqFileExtractor = NULL;
GambleAccountExtractor* gambleAccountExtractor = NULL;
AndroidFetionTextExtractor* androidFetionTextExtractor = NULL;
AndroidMiliaoTextExtractor* androidMiliaoTextExtractor = NULL;
WangwangTextExtractor * wangwangTextExtractor = NULL;
GtalkTextExtractor * gtalkTextExtractor = NULL;
AndroidWeixinTextExtractor* androidWeixinTextExtractor = NULL;
AndroidQQTextExtractor* androidQQTextExtractor = NULL;
AndroidMomoTextExtractor* androidMomoTextExtractor = NULL;
AndroidQtalkTextExtractor* androidQtalkTextExtractor = NULL;
AndroidYYTextExtractor* androidYYTextExtractor = NULL;
AndroidTangoTextExtractor* androidTangoTextExtractor = NULL;
AndroidCocoTextExtractor* androidCocoTextExtractor = NULL;
AndroidTalkboxTextExtractor* androidTalkboxTextExtractor = NULL;
AndroidKuaiyaTextExtractor* androidKuaiyaTextExtractor = NULL;
AndroidHiTextExtractor* androidHiTextExtractor = NULL;
AndroidVoxerTextExtractor* androidVoxerTextExtractor = NULL;
AndroidWhatsappTextExtractor* androidWhatsappTextExtractor = NULL;
AndroidZelloTextExtractor* androidZelloTextExtractor = NULL;
AndroidTelegramTextExtractor* androidTelegramTextExtractor = NULL;
AndroidSkypeTextExtractor* androidSkypeTextExtractor = NULL;
AndroidBBMTextExtractor* androidBBMTextExtractor = NULL;
AndroidKaKaotalkTextExtractor* androidKaKaotalkTextExtractor = NULL;
AndroidOovooTextExtractor* androidOovooTextExtractor = NULL;
AndroidZaloTextExtractor* androidZaloTextExtractor = NULL;
AndroidAireTalkTextExtractor* androidAireTalkTextExtractor = NULL;
AndroidNimbuzzTextExtractor* androidNimbuzzTextExtractor = NULL;
AndroidLineTextExtractor* androidLineTextExtractor = NULL;
AndroidViberTextExtractor* androidViberTextExtractor = NULL;
AndroidDropboxTextExtractor* androidDropboxTextExtractor = NULL;
AndroidKeechatTextExtractor* androidKeechatTextExtractor = NULL;

void OnImSysInit()
{
    //SetDeviceNum(deviceNum);
	running = true;
    
	popExtractor = new PopExtractor();
	if(popExtractor == NULL)
	{
		//cout<<"create error!"<<endl;
		LOG_ERROR("create error!\n");
	}
	fetionTextExtractor = new FetionTextExtractor();
	skypeTextExtractor = new SkypeTextExtractor();
	//msnTextExtractor = new MSNTextExtractor();
	yahooTextExtractor = new YahooTextExtractor();
	qqMsgExtractor = new QQMsgExtractor();
	qqFileExtractor = new QQFileExtractor();
	gambleAccountExtractor = new GambleAccountExtractor();
	androidFetionTextExtractor = new AndroidFetionTextExtractor();
	androidMiliaoTextExtractor = new AndroidMiliaoTextExtractor();
	androidWeixinTextExtractor = new AndroidWeixinTextExtractor();
	androidQQTextExtractor = new AndroidQQTextExtractor();
	androidMomoTextExtractor = new AndroidMomoTextExtractor();
	androidQtalkTextExtractor = new AndroidQtalkTextExtractor();
	androidYYTextExtractor = new AndroidYYTextExtractor();
	androidTangoTextExtractor = new AndroidTangoTextExtractor();
	androidCocoTextExtractor = new AndroidCocoTextExtractor();
	androidTalkboxTextExtractor = new AndroidTalkboxTextExtractor();
	androidKuaiyaTextExtractor = new AndroidKuaiyaTextExtractor();
	androidHiTextExtractor = new AndroidHiTextExtractor();
	androidVoxerTextExtractor = new AndroidVoxerTextExtractor();
	androidWhatsappTextExtractor = new AndroidWhatsappTextExtractor();
	androidZelloTextExtractor = new AndroidZelloTextExtractor();
	androidTelegramTextExtractor = new AndroidTelegramTextExtractor();
	androidSkypeTextExtractor = new AndroidSkypeTextExtractor();
	androidBBMTextExtractor = new AndroidBBMTextExtractor();
	androidKaKaotalkTextExtractor = new AndroidKaKaotalkTextExtractor();
	androidOovooTextExtractor = new AndroidOovooTextExtractor();
	androidZaloTextExtractor = new AndroidZaloTextExtractor();
	androidAireTalkTextExtractor = new AndroidAireTalkTextExtractor();
	androidNimbuzzTextExtractor = new AndroidNimbuzzTextExtractor();
	androidLineTextExtractor = new AndroidLineTextExtractor();
	androidViberTextExtractor = new AndroidViberTextExtractor();
	androidDropboxTextExtractor = new AndroidDropboxTextExtractor();
	androidKeechatTextExtractor = new AndroidKeechatTextExtractor();
	wangwangTextExtractor = new WangwangTextExtractor();
	gtalkTextExtractor = new GtalkTextExtractor();
//     //qqTextExtractor = new QQTextExtractor(occi);
//     
//     //ucTextExtractor = new UCTextExtractor(occi);
	//     
	//   
//     gameExtractor = new GameExtractor(occi);
//     qqFileExtractor = new QQFileExtractor(occi);
// 	msnFileExtractor = new MSNFileExtractor(occi);

	/*
	   //voipExtractor = new VoipExtractor(occi);
	n2pTextExtractor = new N2PTextExtractor(occi);
    
	*/
}

void OnSysClosed(int signal)
{
	running = false;
/*	//qqTextExtractor->OnSysClosed();
	
	//ucTextExtractor->OnSysClosed();
	*/
	popExtractor->OnSysClosed();
	fetionTextExtractor->OnSysClosed();
	//msnTextExtractor->OnSysClosed();
	yahooTextExtractor->OnSysClosed();
	qqMsgExtractor->OnSysClosed();
	gambleAccountExtractor->OnSysClosed();
	androidFetionTextExtractor->OnSysClosed();
	androidMiliaoTextExtractor->OnSysClosed();
	wangwangTextExtractor->OnSysClosed();
	gtalkTextExtractor->OnSysClosed();
	
    /*
	voipExtractor->OnSysClosed();
	n2pTextExtractor->OnSysClosed();
    */

	//delete qqTextExtractor;
	
	//delete msnTextExtractor;
	//delete yahooTextExtractor;
	
	//delete ucTextExtractor;
	//delete fetionTextExtractor;
	
	//delete popExtractor;
    
   /*
			delete voipExtractor;
	delete n2pTextExtractor;
    
   */
//	cout<<"111"<<endl;

	std::cout << "System is closed." << std::endl;
}

//-----------------------------------------------------------------------
// Func Name   : IsIm
// Description : To check and process the IM message.
// Parameter   : packet: The original packet from network. 
// Return      : bool
//-----------------------------------------------------------------------
bool IsIm(PacketInfo* pktInfo)
{
	bool isIm = false;
	switch (pktInfo->pktType)
	{
		case TCP:
			// All the process modules will delete the "pktInfo",
			// if the packet is the corresponding message.
			if (popExtractor->IsFile(pktInfo)) 
			{
				isIm = true;
          	} // Check and process the text message of Fetion.
#if 0  //zhangzm
			else if (fetionTextExtractor->IsImText(pktInfo)) 
			{
		        isIm = true;
	        } // Check and process the text message of Skype.
			else if (skypeTextExtractor->IsImText(pktInfo)) 
			{
                 isIm = true;
			}
#endif
            // Check and process the text message of Yahoo.
			else if (yahooTextExtractor->IsImText(pktInfo))
			{
                 isIm = true;
			} // Check and process the text message of QQ.
			else if (qqMsgExtractor->IsImText(pktInfo))
			{
                 isIm = true;
			} // Check and process the text message of GambleAccount.
			else if (gambleAccountExtractor->IsImText(pktInfo)) 
			{
				isIm = true;
			} // Check and process the text message of Wangwang.
			else if (wangwangTextExtractor->IsImText(pktInfo)) 
			{
                 		isIm = true;
			} // Check and process the text message of Gtalk.
#if 0  //zhangzm
			else if (gtalkTextExtractor->IsImText(pktInfo)) 
			{
                 		isIm = true;
			} // Check and process the text message of AndroidFetion.
#endif
			else if (IS_IM_MOVE && androidFetionTextExtractor->IsImText(pktInfo)) 
			{
				isIm = true;
			} // Check and process the text message of AndroidMiliao.
			else if (IS_IM_MOVE && androidMiliaoTextExtractor->IsImText(pktInfo))
			{
				isIm = true;
			}
			else if(IS_IM_MOVE && androidQQTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidQtalkTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidYYTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidTangoTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidCocoTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidTalkboxTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidKuaiyaTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidHiTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidVoxerTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidZelloTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidTelegramTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidSkypeTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidBBMTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidOovooTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidZaloTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidAireTalkTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidNimbuzzTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidLineTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidDropboxTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidKeechatTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}else if(IS_IM_MOVE && androidKaKaotalkTextExtractor->IsImText(pktInfo)){
				isIm = true;
			}
			break;
		case UDP:
             	// Check and process the text message of QQ.
 	     		if (qqMsgExtractor->IsImText(pktInfo)) {
                 		isIm = true;
            		} 
					else if (qqFileExtractor->IsFile(pktInfo)){
						isIm = true;
					}
					else if(androidWhatsappTextExtractor->IsImText(pktInfo)){
						isIm = true;
					}
					else if(androidViberTextExtractor->IsImText(pktInfo)){
						isIm = true;
					}
					else if(androidWeixinTextExtractor->IsImText(pktInfo)){
						isIm = true;
					}else if(androidMomoTextExtractor->IsImText(pktInfo)){
                        isIm = true;
                    }
					
			break;
		default:
			break;
	}

	return isIm;
}
/*
void AddFilterPort(int ProtocolID, int port)
{
	switch (ProtocolID) {
		case PROTOCOL_ID_QQ:
            //qqTextExtractor->AddFilterPort(port);
	//	qqMsgExtractor->AddFilterPort(port);
			break; 
		case PROTOCOL_ID_MSN: 
           // msnTextExtractor->AddFilterPort(port);
			break; 
		case PROTOCOL_ID_YMSG: 
          //  yahooTextExtractor->AddFilterPort(port);
			break;
		case PROTOCOL_ID_FETION:
          //  fetionTextExtractor->AddFilterPort(port);
		default:
			return; 
	}
}*/

void ClearFilterPort()
{
    //qqTextExtractor->ClearFilterPort();
   // qqMsgExtractor->ClearFilterPort();
   // msnTextExtractor->ClearFilterPort();
   // yahooTextExtractor->ClearFilterPort();
    //fetionTextExtractor->ClearFilterPort();
}

void SetStatus(int ProtocolID, bool isRunning, u_int attachSize, bool isDeepParsing ,u_int miniSize)
{
//     switch (ProtocolID) {
// 		case PROTOCOL_ID_QQ:
//             //qqTextExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 		qqMsgExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
//             break; 
// 		case PROTOCOL_ID_MSN: 
//             msnTextExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
//             break; 
// 		case PROTOCOL_ID_YMSG: 
//             yahooTextExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
//             break;
// 		case PROTOCOL_ID_FETION:
// 			fetionTextExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 	    break;
// 		case PROTOCOL_ID_SKYPE:
// 			skypeTextExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 	    break;
// 		case PROTOCOL_ID_POP3: 
//             popExtractor->SetStatus(isRunning, attachSize, isDeepParsing,0);
//             break; 
// 		case PROTOCOL_ID_QQFILE:
// 			qqFileExtractor->SetStatus(isRunning, attachSize, isDeepParsing, miniSize);
// 			break;
// 		case PROTOCOL_ID_MSNFILE:
// 			msnFileExtractor->SetStatus(isRunning, attachSize, isDeepParsing, miniSize);
// 			break;
// 		case PROTOCOL_ID_GAME:
// 			gameExtractor->SetStatus(isRunning, attachSize, isDeepParsing);
// 			break; 
//         default:
//             return; 
//     }
	return;
}

// End of file
