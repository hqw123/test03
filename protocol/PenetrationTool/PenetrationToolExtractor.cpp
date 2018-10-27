
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "PenetrationToolExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define UNBOUNDED_TAG  0x00010002
#define UNBOUNDED_TAG1 0x00010200
#define UNBOUNDED_TAG2 0x00000100
#define UNBOUNDED_TAG3 0x00010001
#define UNBOUNDED_TAG4 0x04
#define UNBOUNDED_TAG5 0x03
#define UNBOUNDED_FLAG 0x0001
#define FREEGATE_TAG  0x01000001
#define FREEGATE_TAG2 0x00000000  
#define FREEGATE_TAG3 0x26
#define FREEGATE_TAG4 0x20
#define FREEU_TAG  0x01000001
#define FREEU_TAG2 0x00000000
#define FREEU_TAG3 0x27
#define DYNAPASS_TAG  0x01000001
#define DYNAPASS_TAG2 0x00000000
#define DYNAPASS_TAG3 0x32
// U1006
static const char *UltraReachDns  = "\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06";
// U1008
static const char *UltraReachDnsA = "\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08";
// U1208
static const char *UltraReachDnsB  = "\x0a\x03\x00\xfc\x02\x00\x00\x01\x00\x00";
// U1210
static const char *UltraReachDnsC1 = "\x1e\x0a\x01\x02\x00";
static const char *UltraReachDnsC2 = "\x00\x00\x00\xe0";
// U
static const char *UltraReachDnsD = "\x0c\x05\x00\x00\x01\x0d\x00\x00\x00\x00";

// fg707p fg708p
static const char *FreeGateDns = "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20";
// fg710p
static const char *FreeGateDnsA = "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1e";
// fg738p
static const char *FreeGateDnsB =  "\x0a\x03\x01\x1d\x02\x00\x00\x01\x00\x00";
// fg739p
static const char *FreeGateDnsC1 = "\x1e\x0a\x01\x02\x00";
static const char *FreeGateDnsC2 = "\x00\x00\x00\xf8";
static const char *FreeGateDnsC3 = "\x00\x00\x01\x10";

PenetrationToolExtractor::PenetrationToolExtractor()
{   
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/PenetrationTools");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_PENETRATION;
    // Create a directory to store the Penetration message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	memcpy(tableName_, "PENETRATION", 12);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

PenetrationToolExtractor::~PenetrationToolExtractor()
{

}

bool PenetrationToolExtractor::IsTool(PacketInfo* pktInfo)
{
	bool isTool = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	if (pktInfo_->destPort == 53)
	{
		/*if ((*reinterpret_cast<const u_int*>(pktInfo_->body+38) == UNBOUNDED_TAG3 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body+4) == UNBOUNDED_TAG2 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body) == UNBOUNDED_TAG &&
			pktInfo_->bodyLen >= 42 && *(pktInfo_->body+12) == UNBOUNDED_TAG4) || (
			*reinterpret_cast<const u_int*>(pktInfo_->body+4) == UNBOUNDED_TAG2 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body) == UNBOUNDED_TAG1 &&
			pktInfo_->bodyLen >= 42 && *(pktInfo_->body+12) == UNBOUNDED_TAG4) || (
			*reinterpret_cast<const u_int*>(pktInfo_->body+4) == UNBOUNDED_TAG2 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body) == UNBOUNDED_TAG1 &&
			pktInfo_->bodyLen >= 42 && *(pktInfo_->body+12) == UNBOUNDED_TAG5) || (
			*reinterpret_cast<const u_int*>(pktInfo_->body+4) == UNBOUNDED_TAG2 &&
			*reinterpret_cast<const u_int*>(pktInfo_->body) == UNBOUNDED_TAG1 &&
			pktInfo_->bodyLen >= 42) || (
			*reinterpret_cast<const u_int*>(pktInfo_->body+4) == UNBOUNDED_TAG2 &&
			*reinterpret_cast<const u_int*>(pktInfo_->body) == UNBOUNDED_TAG &&
			pktInfo_->bodyLen >= 42))
		{
			isTool = MatchUnBounded();
		}
		else if (pktInfo_->bodyLen >= 42 && !memcmp(pktInfo_->body, UltraReachDns, 13))
		{
			isTool = MatchUnBounded();
		}
		else if (pktInfo_->bodyLen >= 42 && !memcmp(pktInfo_->body, UltraReachDnsA, 13))
		{
			isTool = MatchUnBounded();
		}
		else if((*(pktInfo_->body+12) == FREEGATE_TAG3 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+6) == FREEGATE_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG &&
				 pktInfo_->bodyLen >= 42) || (*(pktInfo_->body+12) == FREEU_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+6) == FREEU_TAG2 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEU_TAG &&
				pktInfo_->bodyLen >= 42) || (*(pktInfo_->body+12) == DYNAPASS_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+6) == DYNAPASS_TAG2 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+2) == DYNAPASS_TAG &&
				pktInfo_->bodyLen >= 42) || (*(pktInfo_->body+12) == FREEGATE_TAG4 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+6) == FREEGATE_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG &&
				 pktInfo_->bodyLen >= 42)){
			isTool = MatchFreeGate();
		}
		else if (pktInfo_->bodyLen >= 42 && !memcmp(pktInfo_->body + 2, FreeGateDns, 11))
		{
			isTool = MatchFreeGate();
		}
		else if (pktInfo_->bodyLen >= 42 && !memcmp(pktInfo_->body + 2, FreeGateDnsA, 11))
		{
			isTool = MatchFreeGate();
		}
		else if (pktInfo_->bodyLen > 0 && !memcmp(pktInfo_->body + 2, "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b\x64\x6f\x6e\x67\x74\x61\x69\x77\x61\x6e\x67\x03\x63\x6f\x6d\x00\x00\x01\x00\x01", 31))
		{
			isTool = MatchFreeGate();
		}
		else if ((pktInfo_->bodyLen >= 34 && !memcmp(pktInfo_->body + 2,  "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x73\x33\x09\x61\x6d\x61\x7a\x6f\x6e\x61\x77\x73\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",32)))
		{
			isTool = MatchFreeGate();
		}
		else if ((pktInfo_->bodyLen > 0 && !memcmp(pktInfo_->body + 10,  "urls=",5)))
		{
			isTool = MatchFreeGate();
		}*/
		
		if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 19  , "cloudfront"))
		{
			isTool = MatchFreeGate();
		}
// 		else if (pktInfo_->bodyLen > 0 && ((!memcmp(pktInfo_->body , FreeGateDnsB, 10) && !memcmp(pktInfo_->body + 10,  "urls=",5) && strstr(pktInfo_->body + 10  , "consume=65535,-1,0,0")) || (!memcmp(pktInfo_->body , FreeGateDnsC1, 5) && (!memcmp(pktInfo_->body+6 , FreeGateDnsC2, 4) || !memcmp(pktInfo_->body+6 , FreeGateDnsC3, 4)))))
// 		{
// 			//cout<<"MatchFreeGate"<<endl;
// // 			cout<<"pktInfo_->body: " <<pktInfo_->body +10 <<endl;
// 			isTool = MatchFreeGate();
// 		}
        else if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 16, "gstatic"))//2017.1.22 lihan UnBounded
		//else if(pktInfo_->bodyLen > 0 && !memcmp(pktInfo_->body + 16,  "amazonaws",9))
// 		else if(pktInfo_->bodyLen > 0 && (strstr(pktInfo_->body + 17, "uasxxwelo")||strstr(pktInfo_->body + 17, "exzwfpix")||strstr(pktInfo_->body + 17, "prgxohy")))
		{
			isTool = MatchUnBounded();
		}
		else if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + 160, "redirector"))//2017.1.22 dwt redirector
		{
			isTool = MatchDynaPass();                                               
		}		
		else if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 17, "mbclubsh"))//2017.1.22 ffvpn redirector
		{
			isTool = MatchFFvpn();                                               
		}		
		else if (pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 30, "fqrouter"))  //fanqiang router
		{
			isTool = MatchFQRouter();
		}
		else if (pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 12, "appcobber"))  //appcobber
		{
			isTool = MatchAppCobber();
		}
		else if (pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 12, "g.maxcdn.info"))  //goagent
		{
			isTool = MatchGAE();
		}
		else if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 14, "mopub"))
        {
            isTool = Matchsupervpn();
        }
		else if(pktInfo_->bodyLen > 0 && strstr(pktInfo_->body + pktInfo_->bodyLen - 19, "easysunnews") && strstr(pktInfo_->body + pktInfo_->bodyLen - 25, "stats"))
		{
			isTool = Matchvpnunlimited();
		}
// 		else if (pktInfo_->bodyLen > 0 && ((!memcmp(pktInfo_->body, UltraReachDnsB, 10) && !memcmp(pktInfo_->body + 10,  "urls=",5) && strstr(pktInfo_->body + 10 , "consume=65535,-1,0,0")) || (!memcmp(pktInfo_->body , UltraReachDnsC1, 5) && !memcmp(pktInfo_->body+6 , UltraReachDnsC2, 4)) || !memcmp(pktInfo_->body, UltraReachDnsD, 10)))
// 		{
// 			//cout<<"MatchUnBounded"<<endl;
// 			isTool = MatchUnBounded();
// 		}
		
	/*else if(*(pktInfo_->body+12) == FREEGATE_TAG3 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body+6) == FREEGATE_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG &&
				 pktInfo_->bodyLen >= 42) {
       // cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"FreeGateExtractor!!!"<<endl;
		isTool = MatchFreeGate();
	}
	else if(*(pktInfo_->body+12) == FREEU_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+6) == FREEU_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEU_TAG &&
				 pktInfo_->bodyLen >= 42) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"FreeUExtractor!!!"<<endl;
		isTool = MatchFreeU();
	}
	else if(*(pktInfo_->body+12) == DYNAPASS_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+6) == DYNAPASS_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == DYNAPASS_TAG &&
				 pktInfo_->bodyLen >= 42) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"DynapassExtractor!!!"<<endl;
		isTool = MatchDynapass();
				 }*/
	/*else if((//*reinterpret_cast<const u_int*>(pktInfo_->body+104) == FREEGATE_TAG3 && 
			*reinterpret_cast<const u_int*>(pktInfo_->body+90) == FREEGATE_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG)||
				(//*reinterpret_cast<const u_int*>(pktInfo_->body+106) == FREEGATE_TAG3 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+92) == FREEGATE_TAG4 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG)||
				(//*reinterpret_cast<const u_int*>(pktInfo_->body+106) == FREEGATE_TAG3 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+92) == FREEGATE_TAG5 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEGATE_TAG)) {
        cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"FreeGateExtractor!!!"<<endl;
		isTool = MatchFreeGate();
	}
	else if((//*reinterpret_cast<const u_int*>(pktInfo_->body+106) == FREEU_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+92) == FREEU_TAG2 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEU_TAG)||
				(//*reinterpret_cast<const u_int*>(pktInfo_->body+128) == FREEU_TAG3 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+114) == FREEU_TAG4 && 
				 *reinterpret_cast<const u_int*>(pktInfo_->body+2) == FREEU_TAG)) {
        cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"FreeUExtractor!!!"<<endl;
		isTool = MatchFreeU();
	}
	else if(//*reinterpret_cast<const u_int*>(pktInfo_->body+128) == DYNAPASS_TAG3 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+114) == DYNAPASS_TAG2 && 
				*reinterpret_cast<const u_int*>(pktInfo_->body+2) == DYNAPASS_TAG) {
		cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"DynapassExtractor!!!"<<endl;
		isTool = MatchDynapass();
	}
			 */
	}
	else if(pktInfo->pktType == TCP)
	{
		if ((pktInfo_->bodyLen == 2 && !memcmp(pktInfo_->body, "\x01\x00", 2))/*||(pktInfo_->bodyLen == 10 && !memcmp(pktInfo_->body, "\x05\x00\x00\x01", 4))*/)
		{//printf("SOCKS\n");
			isTool = MatchSocks();
		}
// 		else if(pktInfo_->destPort==443 && !memcmp(pktInfo_->body, "\x16\x03\x01", 3) && !memcmp(pktInfo_->body+5, "\x01", 1))
// 		{//printf("HTTPS\n");
// 			isTool = MatchHttps();
// 		}
		else if(!strncmp(pktInfo_->body, "POST" ,4) && !strncmp(pktInfo_->body + 5, "/service/getservers HTTP", 24) && strstr(pktInfo_->body, "com.ark.arkvpn"))
        {
            isTool = Matcharkvpn();
        }
		return isTool;
	}
	return isTool;
}

bool PenetrationToolExtractor::MatchHttps()
{
	bool matched = false;
#ifdef VPDNLZ
	StoreMsg2DB2(CreateNode(1203), 0);
#else
	StoreMsg2DB2(CreateNode(1003), 0);
#endif
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchSocks()
{
	bool matched = false;
#ifdef VPDNLZ
	StoreMsg2DB2(CreateNode(1202), 9000);
#else
	StoreMsg2DB2(CreateNode(1001), 9000);
#endif
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchGAE()
{
	bool matched = false;
	StoreMsg2DB(CreateNode(907));
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::Matcharkvpn()
{
    bool matched = false;
    StoreMsg2DB(CreateNode(908));
    pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::Matchvpnunlimited()
{
    bool matched = false;
    StoreMsg2DB(CreateNode(909));
    pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::Matchsupervpn()
{
    bool matched = false;
    StoreMsg2DB(CreateNode(910));
    pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchAppCobber()
{
	bool matched = false;
	StoreMsg2DB(CreateNode(906));
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchFQRouter()
{
	bool matched = false;

	StoreMsg2DB(CreateNode(905));
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchUnBounded()
{
	bool matched = false;
	/*struct in_addr addr;
	addr.s_addr = pktInfo_->destIpv4;
	
	//cout<<inet_ntoa(addr)<<endl;
	string s="192.5.53.209";
	if(inet_ntoa(addr)==s){*/

	StoreMsg2DB(CreateNode(902));
	pktInfo_ = NULL;
	matched = true;
	//}
	return matched;
}

bool PenetrationToolExtractor::MatchFreeGate()
{
	bool matched = false;
	
	
	/*struct in_addr addr;
	addr.s_addr = pktInfo_->destIpv4;
	
	//cout<<inet_ntoa(addr)<<endl;
	string s="204.141.175.106";
	if(inet_ntoa(addr)==s){*/
	StoreMsg2DB(CreateNode(901));
	pktInfo_ = NULL;
	matched = true;
	//}
	return matched;
}

bool PenetrationToolExtractor::MatchDynaPass()   //2017.1.23 dwt
{
	bool matched = false;
	StoreMsg2DB(CreateNode(903));
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

bool PenetrationToolExtractor::MatchFFvpn()   //2017.1.23 ffvpn
{
	bool matched = false;
	StoreMsg2DB(CreateNode(904));
	pktInfo_ = NULL;
	matched = true;
	return matched;
}

MsNode* PenetrationToolExtractor::CreateNode(u_int type)
{   
	u_int clueId = 0;
    // Create the message node.
	MsNode* node = new MsNode;
	memset(node, 0, sizeof(MsNode));
    // Get the current time.
	node->time = NULL;
	//time(&node->timeVal);
	node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
    // Copy basic data to message node
	memcpy(node, pktInfo_, COPY_BYTES);
	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
	clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	node->clueId = clueId;
	node->fileName = NULL;
	node->protocolType = type;
	node->affixFlag = 0;
	
	return node;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void PenetrationToolExtractor::StoreMsg2DB(MsNode* msgNode)
{
	/*write webaccount data to shared memory, by zhangzm*/
	struct in_addr addr;
	OVERWALL_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	addr.s_addr = msgNode->srcIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	ParseMac(msgNode->srcMac, tmp_data.p_data.clientMac);

	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
	addr.s_addr = msgNode->destIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;
	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(OVERWALL, (void *)&tmp_data, sizeof(tmp_data));

	xmlStor_.ClearNode(msgNode);
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB2
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void PenetrationToolExtractor::StoreMsg2DB2(MsNode* msgNode)
{
	/*write netproxy data to shared memory, by zhangzm*/
	struct in_addr addr;
	NETPROXY_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	addr.s_addr = msgNode->srcIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));

	ParseMac(msgNode->srcMac, tmp_data.p_data.clientMac);

	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
	addr.s_addr = msgNode->destIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;
	strcpy(tmp_data.username, "");
    strcpy(tmp_data.proxy_url, "");
    strcpy(tmp_data.real_url, "");
    
	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(NETPROXY, (void *)&tmp_data, sizeof(tmp_data));

	xmlStor_.ClearNode(msgNode);
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB2
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void PenetrationToolExtractor::StoreMsg2DB2(MsNode* msgNode,int affixFilag)
{
	/*write netproxy data to shared memory, by zhangzm*/
	struct in_addr addr;
	NETPROXY_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));

	msgNode->affixFlag = affixFilag;
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;

	if(msgNode->affixFlag == 9000)
	{
		addr.s_addr = msgNode->destIpv4;
		strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
		ParseMac(msgNode->destMac, tmp_data.p_data.clientMac);
		sprintf(tmp_data.p_data.clientPort, "%d", msgNode->destPort);
		addr.s_addr = msgNode->srcIpv4;
		strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
		sprintf(tmp_data.p_data.serverPort, "%d", msgNode->srcPort);
	}
	else
	{
		addr.s_addr = msgNode->srcIpv4;
		strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
		ParseMac(msgNode->srcMac, tmp_data.p_data.clientMac);
		sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
		addr.s_addr = msgNode->destIpv4;
		strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
		sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	}
	
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;
	strcpy(tmp_data.username, "");
    strcpy(tmp_data.proxy_url, "");
    strcpy(tmp_data.real_url, "");
	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(NETPROXY, (void *)&tmp_data, sizeof(tmp_data));

	xmlStor_.ClearNode(msgNode);
}

// End of file

