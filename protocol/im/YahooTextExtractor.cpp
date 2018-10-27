
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/regex.hpp>

#include "YahooTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"

#define YAHOO 0x47534d59

#define MIN_PKT_LEN (YAHOO_HLEN + 8)
#define MESSAGE 0x0600
#define LOGIN   0x55aa555a
#define LOGOUT  0x0200
#define LOGOUT2 0x00000000
#define YMSG_MAX_NUM_LEN    60
#define YMSG_MAX_TEXT_LEN   810
#define FILTER_RULE "<[^>]*>"
#define OUT  0x01000000
#define OUT2 0x05000000
#define LOGOFF_RECV_MESSAGE 0xf100

#define DELIMITER 0x80c0
#define DELIM_LEN 2

#define KEY_FROM_SEND 0x31
#define KEY_FROM_RECV 0x34
#define KEY_TO   0x35
#define KEY_TEXT 0x3431

YahooTextExtractor::YahooTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/YMSG");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_YMSG;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	
	memcpy(tableName_, "YMSG", 5);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
	ClearFilterPort();
}

YahooTextExtractor::~YahooTextExtractor()
{
}

bool YahooTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isYahooText = false;
	//assert(pktInfo != NULL);
	if (!isRunning_) 
	{
		return false;
	}
	{
		boost::mutex::scoped_lock lock(setMut_);
		if (portSet_.find(pktInfo->srcPort) == portSet_.end() && portSet_.find(pktInfo->destPort) == portSet_.end()) 
		{
			return false;
		}
	}
	pktInfo_ = pktInfo;
	
	if (pktInfo_->bodyLen < YAHOO_HLEN)
	{
		return false;
	}
	//if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort)) {
	//	return false;
	//}
	yahooHead_ = reinterpret_cast<const YahooHead*>(pktInfo_->body);
	int bodyLen = pktInfo_->bodyLen;

	if (yahooHead_->id == YAHOO && (yahooHead_->status == LOGIN ||
					yahooHead_->service == MESSAGE ||
					(yahooHead_->service == LOGOUT && yahooHead_->status == LOGOUT2))) 
	{
		PushMassage();
		isYahooText = true;
	}
	else if(yahooHead_->id == YAHOO && (yahooHead_->service == LOGOFF_RECV_MESSAGE))
	{
		while(pktInfo_->bodyLen > 0)
		{
			pktInfo_->body = pktInfo_->body + YAHOO_HLEN + ntohs(yahooHead_->contentLen);
			pktInfo_->bodyLen = pktInfo_->bodyLen - YAHOO_HLEN - ntohs(yahooHead_->contentLen);
			yahooHead_ = reinterpret_cast<const YahooHead*>(pktInfo_->body);
			if(yahooHead_->service == MESSAGE)
			{
				PushMassage();
				isYahooText = true;
				break;
			}
		}
	}
	
	if (pktInfo_)
	{
		pktInfo_ = NULL;
	}

	return isYahooText;
}

bool YahooTextExtractor::CheckPort(u_short port)
{
	switch (port) {
		case 23:
		case 25:
		case 5100:
		case 5050:
		return true;
	}
	
	return false;
}

bool YahooTextExtractor::PushMassage()
{
	// Create and push message node for source address.
	bool pushOkay = false;
	int clueId = 0;
	MsgNode* srcNode = new MsgNode;
	memset(srcNode, 0, sizeof(MsgNode));
	if (!ParseYahooMsg(pktInfo_->body + YAHOO_HLEN, ntohs(yahooHead_->contentLen), srcNode)) {
		delete srcNode;
	} else {
		// Copy basic data to message node
		memcpy(srcNode, pktInfo_, COPY_BYTES);
		if(yahooHead_->status == OUT || yahooHead_->status == OUT2)
		{
			srcNode->srcPort = pktInfo_->destPort;
			srcNode->destPort = pktInfo_->srcPort;
			srcNode->srcIpv4 = pktInfo_->destIpv4;
			srcNode->destIpv4 = pktInfo_->srcIpv4;
		}
		struct in_addr addr;
		char strmac[20] = {0};
		if(yahooHead_->status == OUT || yahooHead_->status == OUT2)
		{
			ParseMac(pktInfo_->destMac, strmac);
			addr.s_addr = srcNode->destIpv4;
		}
		else
		{
			ParseMac(pktInfo_->srcMac, strmac);
			addr.s_addr = srcNode->srcIpv4;
		}
#ifdef VPDNLZ
		clueId = GetObjectId2(srcNode->srcIpv4,srcNode->pppoe);
#else
		//clueId = GetObjectId(strmac);
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	if(yahooHead_->service == MESSAGE)
	{
		srcNode->msgType = Text;
	}
	else if(yahooHead_->status == LOGIN)
	{
		srcNode->msgType = Login;
		LogIn login;
		login.from = srcNode->from;
		uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		keyMap.insert(pair<uint64_t,LogIn>(key,login));
	}
	else if(yahooHead_->service == LOGOUT)
	{
		srcNode->msgType = Logout;
		uint64_t key2 = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
		map<uint64_t,LogIn>::iterator it;
		it = keyMap.find(key2);
		if(it !=keyMap.end())
		{
			string f = it->second.from;
			char* from = new char[f.size()+1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());
			srcNode->from = from;
			keyMap.erase(key2);
		}
	}
        srcNode->time = NULL;
        //time(&srcNode->timeVal);
        srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
        srcNode->fileName = NULL;
	srcNode->protocolType = 503;
        srcNode->clueId = clueId;
        pktInfo_ = NULL;
		srcNode->user=NULL;
		srcNode->pass=NULL;
		srcNode->subject=NULL;
		srcNode->affixFlag=0;
	if(yahooHead_->status == OUT || yahooHead_->status == OUT2)
	{
		srcNode->affixFlag=9000;
	}
		srcNode->cc=NULL;
		srcNode->path=NULL;
		srcNode->groupSign=0;
		srcNode->groupNum = NULL;
        StoreMsg2DB(srcNode);
        pushOkay = true;
    }


    return pushOkay;
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Parse the body of Yahoo message.
// Parameter   : session: A Yahoo talk session.
// Return      : void
//-----------------------------------------------------------------------
/*
void YahooTextExtractor::ProcYahooSession(MsgNode* msgNode, void* obj)
{
    YahooTextExtractor* yahooExtractor = reinterpret_cast<YahooTextExtractor*>(obj);
    if (msgNode->text != NULL) {
        const string* originText = msgNode->text;
        yahooExtractor->ParseYahooMsg(msgNode->text->c_str(), 
                                      msgNode->text->length(),
                                      msgNode->from,
                                      msgNode->to,
                                      msgNode->text);
        if (originText) {
            delete originText;
        }
    }
}
*/

// Each entry consists of:
// <key string> <delimiter> <value string> <delimiter>
int YahooTextExtractor::GetItemLen(const char* body, short bodylen, int offset)
{
    bool gotIt = false;
    int originOffset = offset;
    const u_short* checking;
    // Detect the position of next delimiter.
    while ((bodylen - offset) >= DELIM_LEN) {
        checking = reinterpret_cast<const u_short*>(body + offset);
        if ((*checking) == DELIMITER) {
            gotIt = true;
            break;
        }
        ++offset;
    }
    int itemLen = -1;
    if (gotIt) {
        itemLen = offset - originOffset;
    }
    
    return itemLen;
}

bool YahooTextExtractor::ParseYahooMsg(const char* body,
                                       short bodylen,
                                       MsgNode* sendNode)
{
	if (body == NULL || sendNode == NULL || bodylen <= 0)
		return false;
	
	int offset = 0;
	int keyOffset = 0;
	int contentOffset = 0;
	int keyLen = 0;
	int contentLen = 0;
	char* from = NULL;
	char* to = NULL;
	char* text = NULL;
	bool getOkay = true;
	
	while ((bodylen - offset) > DELIM_LEN) {
		// Get the lenth of key.
		keyOffset = offset;
		keyLen = GetItemLen(body, bodylen, keyOffset);
	
		if (keyLen == -1) {
			getOkay = false;
			break;
		} else {
			// Put the content offset to the beginning of the content next to the key.
			contentOffset = offset + keyLen + DELIM_LEN;
			// Get the lenth of content.
			contentLen = GetItemLen(body, bodylen, contentOffset);
		}
	
		if (contentLen == -1) {
			getOkay = false;
			break;
		} else {
			// Put the offset to the beginning of the next key-content.
			offset = contentOffset + contentLen + DELIM_LEN;
		}
		// The content is the source user if the key is "1".
		if ((from == NULL) && (keyLen == 1) && (*(body + keyOffset) == KEY_FROM_SEND || *(body + keyOffset) == KEY_FROM_RECV)) {
			// Get the source user name.
			from = new char[contentLen + 1];
			from[contentLen] = 0;
			memcpy(from, body + contentOffset, contentLen);
			if (contentLen >= YMSG_MAX_NUM_LEN) {
				from[YMSG_MAX_NUM_LEN] = 0;
			}
			// The content is the destination user if the key is "5".
		} else if ((to == NULL) && (keyLen == 1) && *(body + keyOffset) == KEY_TO) {
			// Get the destination user name.
			to = new char[contentLen + 1];
			to[contentLen] = 0;
			memcpy(to, body + contentOffset, contentLen);
			if (contentLen >= YMSG_MAX_NUM_LEN) {
				to[YMSG_MAX_NUM_LEN] = 0;
			}
			// The content is the message text if the key is "14".
		} else if ((keyLen == 2) && *reinterpret_cast<const u_short*>(body + keyOffset) == KEY_TEXT) {
			if (text == NULL) {
				// Get the message text.
				if (contentLen >= bodylen) {
					getOkay = false;
					break;
				}
				text = new char[bodylen];
				memset(text, 0, bodylen);
				memcpy(text, body + contentOffset, contentLen);
			} else {
				// One packet may contain several messages.
				int textLen = strlen(text);
				if (contentLen >= bodylen - textLen) {
					delete text;
					text = NULL;
					getOkay = false;
					break;
				}
				memcpy(text + textLen, body + contentOffset, contentLen);
			}
			if (strlen(text) >= YMSG_MAX_TEXT_LEN) {
				text[YMSG_MAX_TEXT_LEN] = 0;
			}
		}
	}
	/*
	// A complete message of yahoo should include source user name, destination user name and the text.
	bool getOkay = from && to && text;
	*/
	if (!getOkay) {
		if (from) {
			delete from;
			from = NULL;
		}
		if (to) {
			delete to;
			to = NULL;
		}
		if (text) {
			delete text;
			text = NULL;
		}
	} else {
		sendNode->from = from;
		sendNode->to = to;
		sendNode->text = text;
	}
	
	return getOkay;
}
//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void YahooTextExtractor::StoreMsg2DB(MsgNode* msgNode)
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
		strncpy(tmp_data.content, regex_replace(string(msgNode->text), boost::regex(FILTER_RULE), "").c_str(), 499);
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
void YahooTextExtractor::StoreMsg2Text(const string& from, const string& to, const string& text)
{
    stringstream srcFileName;
    srcFileName << DIRECTORY << "/" << pktInfo_->srcIpv4 << ":" << pktInfo_->srcPort;
    stringstream destFileName;
    destFileName << DIRECTORY << "/" << pktInfo_->destIpv4 << ":" << pktInfo_->destPort;
    stringstream content;
    string* currentTime = ::GetCurrentTime();
    content << "\n\n++++++++++++++++++ Msg ++++++++++++++++++++\n";
    content << "Message from: " << from << "  To: " << to << endl;
    content << "Time: " << *currentTime;
    content << "Source: " << pktInfo_->srcIpv4 << " : " << pktInfo_->srcPort << endl;
    content << "Destination: " << pktInfo_->destIpv4 << " : " << pktInfo_->destPort << endl;
    content << "Text: " << text << endl;
    content << "+++++++++++++++++++++++++++++++++++++++++++++\n\n";
    ofstream srcFile(srcFileName.str().c_str(), ios::out | ios::app);
    srcFile << content.str();
    srcFile.close();
    ofstream destFile(destFileName.str().c_str(), ios::out | ios::app);
    destFile << content.str();
    destFile.close();
}

void YahooTextExtractor::ClearFilterPort()
{
    boost::mutex::scoped_lock lock(setMut_);
    portSet_.clear();
    portSet_.insert(23);
    portSet_.insert(25);
    portSet_.insert(5100);
    portSet_.insert(5050);
}
// End of file.
