//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 baihong Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     PopExtractor.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the classes for the email extraction from 
//      POP sessions.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 090812 wu zhonghua Initial
//
//------------------------------------------------------------------------
#include "PopExtractor.h"
#include <sys/stat.h>       // For mkdir().
#include <arpa/inet.h>
#include "db_data.h"

const char* USER_RULE = "^USER\\s(.+)\r\n$";
const char* PASS_RULE = "^PASS\\s(.+)\r\n$";
const char* STAT_RULE = "^\\+OK\\s(\\d+)\\s(\\d+)\r\n$";
const char* LIST_RULE = "(\\d+?)\\s(\\d+)\r\n"; 
const char* RETR_RULE = "RETR\\s(\\d+)\r\n$";
const char* RETRNEXT_RULE = "\\+OK\\s(\\d+)\\soctets\r\n$";
const char* RETRNEXT2_RULE = "\\+OK\\s(\\d+)\\soctets\\sfollow.\r\n";

const char* DATE_RULE="Date:\\s(.*?)\r\n";
const char* FROM_RULE = "\r\nFrom:\\s.*?([a-z0-9A-Z\\._-]+@[a-z0-9A-Z\\._-]+)";
//const char* TO_RULE = "\r\nTo:(\\s.*?<([a-z0-9A-Z\\._-]+@[a-z0-9A-Z\\._-]+)>,?)+?";
const char* TO_RULE = "\r\nTo:\\s(.*?)>\r\n?";
const char* CC_RULE="\r\nCC:\\s(.*?)>\r\n?";
const char* SUBJECT_RULE = "\r\nSubject:\\s(.*?)\r\n";
const char* CONTENT_TYPE="\r\nContent-Type:\\s(.*?);\r\n\\sboundary=\"(.*?)\"\r\n";
const char* MAIL_ADDRESS_RULE="<([a-z0-9A-Z\\._-]+@[a-z0-9A-Z\\._-]+)>";

const u_short POP_PORT = 110;
const int MAP_SIZE = 1024;

//qq#define MOVE_PATH          "/home/nodeData"
//#define DIRECTORY          "/home/nodeData/moduleData/POP3"
//#define SUB_DIREC          "/home/nodeData/moduleData/POP3/File"
#define TABLE_NAME         "EMAIL"

PopExtractor::PopExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/POP3");
	sprintf(SUB_DIREC,"%s%s",LzDataPath,"/spyData/moduleData/POP3/File");
	isRunning_ = true;
	attachSize_ = 100*1024*1024; //100MB
    //protoType_ = PROTOCOL_POP3;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	sprintf(filePath_, "%s\0", SUB_DIREC);
	dampedMap_ = new DampedMap<uint64_t>(MAP_SIZE, 4, 4);
	sprintf(dataFile_, "%s/POP3\0", DIRECTORY);
	sprintf(tableName_, "EMAIL\0");
	devNum_ = GetDeviceNum();
	statusRule_[0] = new boost::regex(USER_RULE);
	statusRule_[1] = new boost::regex(PASS_RULE);
	statusRule_[2] = new boost::regex(STAT_RULE);
	statusRule_[3] = new boost::regex(LIST_RULE);
	statusRule_[4] = new boost::regex(RETR_RULE);
	statusRule_[5] = new boost::regex(RETRNEXT_RULE);
	statusRule_[6] = new boost::regex(RETRNEXT2_RULE);	
	statusRule_[7] = NULL;

	//邮件头过滤规则
	dateRule_ = new boost::regex(DATE_RULE);
	fromRule_ = new boost::regex(FROM_RULE);
	toRule_ = new boost::regex(TO_RULE);
	ccRule_ = new boost::regex(CC_RULE);
	subjectRule_ = new boost::regex(SUBJECT_RULE);
	contentTypeRule_ = new boost::regex(CONTENT_TYPE);
	mailAddressRule_ = new boost::regex(MAIL_ADDRESS_RULE);
			
}

PopExtractor::~PopExtractor()
{

//	cout << __FILE__ << ":" << __FUNCTION__ << endl;
// 	if(strLocalIP)
// 	{
// 		delete strLocalIP;
// 	}
	delete dateRule_;
	delete fromRule_;
	delete toRule_;
	delete ccRule_;
	delete subjectRule_;
	delete contentTypeRule_;
	delete mailAddressRule_;
	for (int i = 0; i < POP_STATUS_NUM - 1; ++i) {
		if(statusRule_[i]!=NULL)
			delete statusRule_[i];
	}
	delete dampedMap_;
//	cout << __FILE__ << ":" << __FUNCTION__ <<"end "<< endl;
}

bool PopExtractor::IsFile(PacketInfo* packetInfo)
{
	if (!isRunning_)
	{
//      cout << __FILE__ << ":" << __FUNCTION__ << ":" << "POP Stoped!" << endl;
		return false;
	}
	
	uint64_t key = GetKey(packetInfo);
	if (!key)
	{
		//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "key" << endl;
		return false;
	}
	PopSession* popSession = NULL;
	popSession = reinterpret_cast<PopSession*>(dampedMap_->Find(key));
	if (popSession)
	{
		if (!popSession->AddPacket(packetInfo))
		{
//			cout << __FILE__ << ":" << __FUNCTION__ << ":" << "delete POP DATA session\n" << endl;
			dampedMap_->Pop(key);
			return true;
		}
		popSession->SetZero();
	}
	else
	{
		const char* user = GetUser(packetInfo);
		if (user)
		{
//			cout << __FILE__ << ":" << __FUNCTION__ << ":" << " ADD POP DATA session\n" << endl;
			popSession = new PopSession(this,
					filePath_, 
					statusRule_,
					dateRule_,
					fromRule_,
					toRule_,
					ccRule_,
					subjectRule_,
					contentTypeRule_,
					mailAddressRule_,
					user,
					attachSize_);
			popSession->SetZero();
			dampedMap_->Push(key, popSession);
		}
		else if(*reinterpret_cast<const u_int*>(packetInfo->body) == 0x52544552)
		{
//			cout << __FILE__ << ":" << __FUNCTION__ << ":" << " ADD POP DATA session by RETR\n" << endl;
			user = NULL;
			popSession = new PopSession(this,
					filePath_,
					statusRule_,
					dateRule_,
					fromRule_,
					toRule_,
					ccRule_,
					subjectRule_,
					contentTypeRule_,
					mailAddressRule_,
					user,
					attachSize_);
			popSession->SetZero();
			dampedMap_->Push(key, popSession);

			if (!popSession->AddPacket(packetInfo))
			{
//				cout << __FILE__ << ":" << __FUNCTION__ << ":" << "delete POP DATA session22\n" << endl;
				dampedMap_->Pop(key);
				return true;
			}
			popSession->SetZero();
		}
		else
		{
			return false;
		}
	}

	return true;
}

uint64_t PopExtractor::GetKey(PacketInfo* packetInfo)
{
	uint64_t key = 0;

	if (packetInfo->srcPort == POP_PORT) {
		key = packetInfo->destIpv4;
		key = (key << 16) | packetInfo->destPort;
	} else if (packetInfo->destPort == POP_PORT) {
		key = packetInfo->srcIpv4;
		key = (key << 16) | packetInfo->srcPort;
	}

	return key;
}

const char* PopExtractor::GetUser(PacketInfo* packetInfo)
{
	char* user = NULL;
	boost::cmatch matchedStr;
	if (boost::regex_search((const char*) packetInfo->body,
	    (const char*) (packetInfo->body + packetInfo->bodyLen),
	    matchedStr,
	    *statusRule_[0])) {
		    u_short userLen = matchedStr[1].length();
		    user = new char[userLen + 1];
		    user[userLen] = 0;
		    memcpy(user, matchedStr[1].first, userLen);
	    }

	    return user;
}

void PopExtractor::StoreMsg2DB(MsgNode* msgNode)
{
	/*write email data to shared memory, by zhangzm*/
	struct in_addr addr;
	EMAIL_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	addr.s_addr = msgNode->destIpv4;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	ParseMac(msgNode->destMac, tmp_data.p_data.clientMac);
	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->destPort);
	addr.s_addr = msgNode->srcIpv4;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->srcPort);
	
	tmp_data.p_data.captureTime = (unsigned int)msgNode->timeVal;
	if (msgNode->user != NULL)
	{
		strncpy(tmp_data.username, msgNode->user, 64);
	}
	else
	{
		strcpy(tmp_data.username, "");
	}
	
	if (msgNode->pass != NULL) 
	{
		strncpy(tmp_data.password, msgNode->pass, 64);
	} 
	else 
	{
		strcpy(tmp_data.password, "");
	}

	tmp_data.sendTime = (unsigned int)msgNode->timeVal;
	if (msgNode->from != NULL)
	{
		strncpy(tmp_data.sendAddr, msgNode->from, 259);
	}
	else
	{
		strcpy(tmp_data.sendAddr, "");
	}
	
	if (msgNode->to != NULL)
	{
		strncpy(tmp_data.recvAddr, msgNode->to, 259);
	}
	else
	{
		strcpy(tmp_data.recvAddr, "");
	}
	strcpy(tmp_data.ccAddr, "");
	strcpy(tmp_data.bccAddr, "");

	if (xmlStorer_.ParseSubject(msgNode->subject) != NULL) 
	{
		strncpy(tmp_data.subject, msgNode->subject, 259);
	}
	else
	{
		strcpy(tmp_data.subject, "");
	}
	
	if (msgNode->path != NULL)
	{
		strncpy(tmp_data.datafile, msgNode->path, 259);
	}
	else
	{
		strcpy(tmp_data.datafile, "");
	}	
	
	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(EMAIL, (void *)&tmp_data, sizeof(tmp_data));

	xmlStorer_.ClearNode(msgNode);
}

// End of file.
