
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "SkypeTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define LOGIN_RULE "GET\\s/en_return_time.php.login_id=(\\w+?)&code=.+?\\sHTTP/1.1\r\nHost:\\sskypetools1.tom.com\r\n"
//for version 4.1.32.179
#define LOGINT_RULE "GET\\s/ui/0/.+/zh-Hans/getlatestversion.ver=.+&uhash=.+?\\sHTTP/1.1\r\n"
#define VERTAG2 0x2f69752f   //"/ui/"
//#define VERTAG3 0x3d726576
//#define VERTAG4 0x68736168
#define TAG  0x20544547    //"GET"
#define TAG2 0x3f706870    //php?
#define TAG3 0x69676f6c    //logi
#define TAG4 0x64695f6e    //n_id
//-----------------------------------------------------------------------
// Func Name   : SkypeTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
SkypeTextExtractor::SkypeTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/Game");
    //protoType_ = PROTOCOL_SKYPE;
    // Create a directory to store the Skype message files.
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

    loginRule_ = new boost::regex(LOGIN_RULE);
    logintRule_ = new boost::regex(LOGINT_RULE);
    memcpy(tableName_, "SKYPE", 6);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

//-----------------------------------------------------------------------
// Func Name   : ~SkypeTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
SkypeTextExtractor::~SkypeTextExtractor()
{
    delete loginRule_;
    delete logintRule_;
}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool SkypeTextExtractor::IsImText(PacketInfo* pktInfo)
{
    bool isSkypeText = false;
    //assert(pktInfo != NULL);
    pktInfo_ = pktInfo;

    if(pktInfo_->bodyLen > 32 &&
	   *reinterpret_cast<const u_int*>(pktInfo_->body) == TAG &&
       *reinterpret_cast<const u_int*>(pktInfo_->body + 20) == TAG2 &&
	   *reinterpret_cast<const u_int*>(pktInfo_->body + 24) == TAG3 &&
	   *reinterpret_cast<const u_int*>(pktInfo_->body + 28) == TAG4)
	{
        isSkypeText = MatchSkype();
    }
	else if(pktInfo_->bodyLen > 8 &&
			*reinterpret_cast<const u_int*>(pktInfo_->body) == TAG &&
            *reinterpret_cast<const u_int*>(pktInfo_->body + 4) == VERTAG2){ //&&
	     //*reinterpret_cast<const u_int*>(pktInfo_->body + 47) == VERTAG3 &&
	     //*reinterpret_cast<const u_int*>(pktInfo_->body + 63) == VERTAG4) {
	
        isSkypeText = MatchSkype();
    }

    return isSkypeText;
}

//-----------------------------------------------------------------------
// Func Name   : MatchSkype
// Description : The function matches the packet if is belong to Skype.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool SkypeTextExtractor::MatchSkype()
{
    bool matched = false;
    boost::cmatch matchedStr;
    const char* first = pktInfo_->body;
    const char* last = pktInfo_->body + pktInfo_->bodyLen;
    
    if (boost::regex_search(first, last, matchedStr, *loginRule_)) 
	{
       // cout<<"Skypelogin!!!"<<matchedStr[0]<<endl;
		
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		
		char* from =str;
	
		MsgNode* node = new MsgNode;
		memset(node, 0, sizeof(MsgNode));
		// Copy basic data to message node
	
		memcpy(node, pktInfo_, COPY_BYTES);
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		int clueId=0;
		
		//node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac,strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		//cout<<"Clue ID is : "<<clueId<<endl;
		node->clueId = clueId;
		node->fileName = NULL;
	   	node->protocolType = 507;
		node->user=NULL;
		node->pass=NULL;
		node->subject=NULL;
		node->affixFlag=0;
		node->cc=NULL;
		node->path=NULL;
		node->groupSign=0;
		node->groupNum = NULL;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
        matched = true;
    }
	else if (boost::regex_search(first, last, matchedStr, *logintRule_)) 
	{
       	MsgNode* node = new MsgNode;
		memset(node, 0, sizeof(MsgNode));
		// Copy basic data to message node
	
		memcpy(node, pktInfo_, COPY_BYTES);
		node->text=NULL;
		node->from=NULL;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		int clueId=0;
		
		//node->protocolType = PROTOCOL_ID_WEBMSN;
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
		//cout<<"Clue ID is : "<<clueId<<endl;
		node->clueId = clueId;
		node->fileName = NULL;
		node->protocolType = 507;
		node->user=NULL;
		node->pass=NULL;
		node->subject=NULL;
		node->affixFlag=0;
		node->cc=NULL;
		node->path=NULL;
		node->groupSign=0;
		node->groupNum = NULL;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
        matched = true;
    }
    return matched;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void SkypeTextExtractor::StoreMsg2DB(MsgNode* msgNode)
{
	/*write iminfo data to shared memory, by zhangzm*/
	struct in_addr addr;
	IMINFO_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	addr.s_addr = msgNode->srcIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	if(msgNode->affixFlag == 9000)
	{
		ParseMac(msgNode->destMac, tmp_data.p_data.clientMac);
	}
	else
	{
		ParseMac(msgNode->srcMac, tmp_data.p_data.clientMac);
	}
	
	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
	addr.s_addr = pktInfo_->destIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;

	tmp_data.optype = msgNode->msgType;
	if (msgNode->text != NULL)
	{
		strncpy(tmp_data.content, msgNode->text, 499);
	}
	else
	{
		strcpy(tmp_data.content, "");
	}

	if (msgNode->from != NULL)
	{
		strncpy(tmp_data.sendNum, msgNode->from, 199);
	}
	else 
	{
		strcpy(tmp_data.sendNum, "");
	}
	
	if (msgNode->to != NULL)
	{
		strncpy(tmp_data.recvNum, msgNode->to, 199);
	}
	else
	{
		strcpy(tmp_data.recvNum, "");
	}	

	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(IMINFO, (void *)&tmp_data, sizeof(tmp_data));

	xmlStorer_.ClearNode(msgNode);
}

// End of file
