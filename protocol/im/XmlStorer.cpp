//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 baihong Information Security Techology CO., Ltd.
// This program belongs to baihong ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise baihong    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     XmlStorer.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class XmlStorer. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081211 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#include "XmlStorer.h"
#include "Public.h"
#include <iostream>
#include <assert.h>
#include <arpa/inet.h>

// The offside to position the file pointer before close root tag.
static const int ROOT_OFFSIDE = -10;
// Match rule for filter tags in some text.
#define FILTER_RULE "<[^>]*>"
const char * SUBJECT_DECODE_RULE="=\\?(\\w).+?\\?(\\w)\\?(.+)\\?=";

//-----------------------------------------------------------------------
// Func Name   : XmlStorer
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
XmlStorer::XmlStorer()
{
	
	//filterRule_ = new boost::regex(FILTER_RULE);
	//andRule_ = new boost::regex("&");
	//littleRule_ = new boost::regex("<");
}

//-----------------------------------------------------------------------
// Func Name   : ~XmlStorer
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
XmlStorer::~XmlStorer()
{
	//delete subjectDecodeRule_;
	//delete filterRule_;
	//delete andRule_;
	//delete littleRule_;
}

//-----------------------------------------------------------------------
// Func Name   : DeclareXml
// Description : Initialize the XML file, and declare its version.
// Parameter   : fileName: The XML file you want to name
//               version: The XML version, such as 1.0.
//               encoding: The encoding type of XML, such as UTF-8.
// Return      : bool
//-----------------------------------------------------------------------
bool XmlStorer::DeclareXml(const char* fileName, const char* tableName, const char* version, const char* encoding)
{
	bool declareOkay = false;
	ofstream file(fileName, ios::ate);
	if (file != NULL) {
		if (version != NULL) {
			file << "<?xml version=\"" << version;
		} else {
        // The default version is 1.0.
			file << "<?xml version=\"1.0";
		}
		if (encoding != NULL) {
			file << "\" encoding=\"" << encoding << "\"?>\n";
		} else {
        // The default encoding is UTF-8.
			file << "\" encoding=\"UTF-8\"?>\n";
		}
        // Insert root node.
		file << "<table name=\"" << tableName << "\">\n";
        // Initialize the number of messages.
        //file << "<!--MsgNum=0-->\n";
		file.close();
		declareOkay = true;
	}

	return declareOkay;
}

//-----------------------------------------------------------------------
// Func Name   : InsertMsgNode
// Description : Insert a message node to an existed XML file.
// Parameter   : msgNode: The target message node for storing.
// Return      : bool
//-----------------------------------------------------------------------
bool XmlStorer::InsertMsgNode(MsgNode* msgNode, fstream& file)
{
	bool insertOkay = false;
	//assert(msgNode != NULL);
	if (msgNode == NULL)
		return false;
    //fstream file(fileName, ios::out | ios::in);
    // Position the file pointer to the 2nd line from the end of XML file.
    // Because the lenth of the last line of XML file is between 15 to 24.
    // So we should position the file pointer more than 24 bytes before the end of file.
    // And this position is certainly in the 2nd line from the end of file.
	//streamoff offside = ROOT_OFFSIDE;
	//file.seekp(0, ios_base::end);//offside
    /*
	switch (msgNode->msgType) {
	case Login:
	case Logout:
	WriteLogMsg(file, msgNode);
	break;
	case Text:
	WriteTextMsg(file, msgNode);
	break;
	case File:
	WriteFileMsg(file, msgNode);
	break;
}*/     
	//cout<<"start writeMsg"<<endl;
	WriteMsg(file, msgNode, msgNode->msgType);
	//cout<<"start writeMsg clear node"<<endl;
	ClearNode(msgNode);
	//cout<<"start writeMsg del msgNode"<<endl;
	delete msgNode;
    // Add the close root tag and message number, which have been covered.
	//file << "</table>";
    //file.close();
	insertOkay = true;

	return insertOkay;
}

//-----------------------------------------------------------------------
// Func Name   : ClearNode
// Description : Free the members of message node.
// Parameter   : msgNode: The message node will be free.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStorer::ClearNode(MsgNode* msgNode)
{
	//cout<<"1";
	if (msgNode->fileName) {
		delete msgNode->fileName;
		msgNode->fileName = NULL;
	}
	if (msgNode->from) {
		delete msgNode->from;
		msgNode->from = NULL;
	}
	if (msgNode->to) {
		delete msgNode->to;
		msgNode->to = NULL;
	}
	if (msgNode->text) {
		delete msgNode->text;
		msgNode->text = NULL;
	}
	if (msgNode->groupNum){
		delete msgNode->groupNum;
		msgNode->groupNum = NULL;
	}
	//cout<<"2";
	if (msgNode->time) {
		delete msgNode->time;
		msgNode->time = NULL;
	}
	if (msgNode->path) {
		delete msgNode->path;
		msgNode->path = NULL;
	}
	if (msgNode->user) {
		delete msgNode->user;
		msgNode->user = NULL;
	}
	if (msgNode->pass) {
		delete msgNode->pass;
		msgNode->pass = NULL;
	}
	if (msgNode->subject) {
		delete msgNode->subject;
		msgNode->subject = NULL;
	}
	if(msgNode->cc)	{
		//cout<< "delete"<<endl;
		delete msgNode->cc;
		msgNode->cc = NULL;
	}
	if(msgNode)
	{
		delete msgNode;
		msgNode=NULL;
	}
	//cout<<"3";
	
}

//-----------------------------------------------------------------------
// Func Name   : WriteLogMsg
// Description : Write the login and logout types message into file.
// Parameter   : file: The file stream in which the message will be stored.
//               msgNode: The message node will be stored.
//               msgNum: The number of this message node.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStorer::WriteMsg(fstream& file, MsgNode* msgNode, MsgType msgType)
{
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "  write xml start"<< endl;
	struct in_addr addr;
	file << "    <data>\n";
	file << "        <dev>" << msgNode->device << "</dev>\n";
	file << "        <clueid>" << 0 << "</clueid>\n";
	addr.s_addr = msgNode->srcIpv4;
	file << "        <src_ip>" << inet_ntoa(addr) << "</src_ip>\n";
	file << "        <src_port>" << msgNode->srcPort << "</src_port>\n";
	addr.s_addr = msgNode->destIpv4;
	file << "        <dest_ip>" << inet_ntoa(addr) << "</dest_ip>\n";
	file << "        <dest_port>" << msgNode->destPort << "</dest_port>\n";
	file << "        <time>" << msgNode->timeVal << "</time>\n";
	if(msgNode->protocolType==601||msgNode->affixFlag==9000) //pop3 DB clientmac  == node destmac
	{
		char destMac[20];
		file << "        <mac>" <<  ParseMac(msgNode->destMac, destMac) <<"</mac>\n";
	}
	else
	{
		char srcMac[20];
		file << "        <mac>" <<  ParseMac(msgNode->srcMac, srcMac) << "</mac>\n";
	}
	

	switch (msgNode->msgType) {
		case Login:
			file << "        <type>1</type>\n";
			break;
		case Logout:
			file << "        <type>2</type>\n";
			break;
		case Text:
		case File:
			file << "        <type>3</type>\n";
			break;
	}
	
	if (msgNode->text != NULL) 
	{
		boost::regex filterRule_(FILTER_RULE);
		boost::regex andRule_("&");
		boost::regex littleRule_("<");
	
        // Filter tags like "<...>".
		string filterTag(regex_replace(string(msgNode->text),filterRule_, ""));
        // Replace symbol "<" to "&lt;".
		file << "        <text>" << regex_replace(regex_replace(filterTag,andRule_, "&amp;"),
				littleRule_, "&lt;") << "</text>\n";
	} else {
		file << "        <text></text>\n";
	}
	if (msgNode->from != NULL) {
		file << "        <from>" << msgNode->from << "</from>\n";
	} else {
		file << "        <from></from>\n";
	}
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "        2"<< endl;
	if (msgNode->to != NULL) {
		file << "        <to>" << msgNode->to << "</to>\n";
	} else {
		file << "        <to></to>\n";
	}
	if (msgNode->path != NULL) {
		file << "        <path>" << msgNode->path << "</path>\n";
	} else {
		file << "        <path></path>\n";
	}
	if (msgNode->user != NULL) {
		file << "        <user>" << msgNode->user << "</user>\n";
	} else {
		file << "        <user></user>\n";
	}
	if (msgNode->pass != NULL) {
		file << "        <pass>" << msgNode->pass << "</pass>\n";
	} else {
		file << "        <pass></pass>\n";
	}
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << " Write Node message to xml file!"<< endl;
	if (ParseSubject(msgNode->subject) != NULL)  //ParseSubject
	{
		
		if (strlen(msgNode->subject) > 128)
		{
			(msgNode->subject)[128] = 0;
		}
		file << "        <subject>" <<  msgNode->subject << "</subject>\n";
	} else {
		file << "        <subject></subject>\n";
	}
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "       4"<< endl;
    file << "        <affixFlag>" <<  msgNode->affixFlag << "</affixFlag>\n";
	if(msgNode->cc!=NULL)
	{
		//cout<<"cc";
		file << "        <ccaddress>" <<  msgNode->cc << "</ccaddress>\n";
		//cout<<"cc2";
	}
	else{
	 file << "        <ccaddress></ccaddress>\n";
	}
	
    file << "        <protocolType>" <<  msgNode->protocolType << "</protocolType>\n";
    
    file << "    </data>\n";
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "write xml end " << endl;
}

const char* XmlStorer::ParseSubject(char*& subject)
{

	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "subject ParseSubject" << endl;
	boost::regex subjectDecodeRule_(SUBJECT_DECODE_RULE);
	boost::cmatch matchedStr;
	if (!subject || !boost::regex_search(subject, matchedStr, subjectDecodeRule_)) {
		return subject;
	}
	char* newSub = subject;
	switch (*matchedStr[1].first) {
		case 'G':
			case 'g': {
				switch (*matchedStr[2].first) {
					case 'B':
					case 'b':
						newSub = GBK_B2UTF8(matchedStr[3].first, matchedStr[3].length());
						delete subject;
						subject = newSub;
						break;
					case 'Q':
					case 'q':
						newSub = GBK_Q2UTF8(matchedStr[3].first, matchedStr[3].length());
						delete subject;
						subject = newSub;
						break;
					default:
						break;
				}
				break;
			}
		case 'U':
			case 'u': {
				switch (*matchedStr[2].first) {
					case 'B':
					case 'b':
						newSub = Base2UTF8(matchedStr[3].first, matchedStr[3].length());
						delete subject;
						subject = newSub;
						break;
					case 'Q':
					case 'q':
						newSub = QP2UTF8(matchedStr[3].first, matchedStr[3].length());
						delete subject;
						subject = newSub;
						break;
					default:
						break;
				}
				break;
			}
		default:
			break;
	}
	
	return newSub;
}

/*
//-----------------------------------------------------------------------
// Func Name   : WriteLogMsg
// Description : Write the login and logout types message into file.
// Parameter   : file: The file stream in which the message will be stored.
//               msgNode: The message node will be stored.
//               msgNum: The number of this message node.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStorer::WriteLogMsg(fstream& file, const MsgNode* msgNode)
{
    if (msgNode->msgType == Login) {
        file << "\n    <message type=\"login\">\n";
} else {
        file << "\n    <message type=\"logout\">\n";
}
    file << "        <from>" << msgNode->from << "</from>\n";
    file << "        <src_ip>" << msgNode->srcIpv4 << "</src_ip>\n";
    file << "        <src_port>" << msgNode->srcPort << "</src_port>\n";
    file << "        <dest_ip>" << msgNode->destIpv4 << "</dest_ip>\n";
    file << "        <dest_port>" << msgNode->destPort << "</dest_port>\n";
    file << "        <time>" << msgNode->timeVal << "</time>\n";
    file << "    </message>\n";
}

//-----------------------------------------------------------------------
// Func Name   : WriteTextMsg
// Description : Write the text type message into file.
// Parameter   : file: The file stream in which the message will be stored.
//               msgNode: The message node will be stored.
//               msgNum: The number of this message node.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStorer::WriteTextMsg(fstream& file, const MsgNode* msgNode)
{
    file << "\n    <message type=\"text\">\n";
    if (msgNode->from != NULL) {
        file << "        <from>" << msgNode->from << "</from>\n";
}
    if (msgNode->to != NULL) {
        file << "        <to>" << msgNode->to << "</to>\n";
}
    file << "        <src_ip>" << msgNode->srcIpv4 << "</src_ip>\n";
    file << "        <src_port>" << msgNode->srcPort << "</src_port>\n";
    file << "        <dest_ip>" << msgNode->destIpv4 << "</dest_ip>\n";
    file << "        <dest_port>" << msgNode->destPort << "</dest_port>\n";
    file << "        <time>" << msgNode->timeVal <<  "</time>\n";
    if (msgNode->text != NULL) {
        // Filter tags like "<...>".
        string filterTag(regex_replace(string(msgNode->text), boost::regex(FILTER_RULE), ""));
        // Replace symbol "<" to "&lt;".
        // Replace symbol ">" to "&gt;".
        file << "        <text>" << regex_replace(regex_replace(filterTag, boost::regex("&"), "&amp;"),
            boost::regex("<"), "&lt;") << "</text>\n";
}
    file << "    </message>\n";
}

void XmlStorer::WriteFileMsg(fstream& file, const MsgNode* msgNode)
{
    file << "\n    <message type=\"file\">\n";
    if (msgNode->from != NULL) {
        file << "        <from>" << msgNode->from << "</from>\n";
}
    if (msgNode->to != NULL) {
        file << "        <to>" << msgNode->to << "</to>\n";
}
    file << "        <src_ip>" << msgNode->srcIpv4 << "</src_ip>\n";
    file << "        <src_port>" << msgNode->srcPort << "</src_port>\n";
    file << "        <dest_ip>" << msgNode->destIpv4 << "</dest_ip>\n";
    file << "        <dest_port>" << msgNode->destPort << "</dest_port>\n";
    file << "        <time>" << msgNode->timeVal <<  "</time>\n";
    file << "        <file>" << msgNode->time <<  "</file>\n";
    if (msgNode->text != NULL) {
        file << "        <text>" << msgNode->text << "</text>\n";
        file << "    </message>\n";
}
}
*/
// End of file
