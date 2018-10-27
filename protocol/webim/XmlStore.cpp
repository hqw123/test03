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
// Module Name:     XmlStore.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class XmlStorer. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100622 tz Initial
//
//------------------------------------------------------------------------
#include "XmlStore.h"
#include "Public.h"
#include <iostream>
#include <assert.h>
#include <arpa/inet.h>
//#include "../clue/ProtocolID.h" //add by tz 2010-05-11
// The offside to position the file pointer before close root tag.
static const int ROOT_OFFSIDE = -10;
// Match rule for filter tags in some text.
#define FILTER_RULE "<[^>]*>"
//const char * SUBJECT_DECODE_RULE="=\\?(\\w).+?\\?(\\w)\\?(.+)\\?=";

//-----------------------------------------------------------------------
// Func Name   : XmlStore
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
XmlStore::XmlStore()
{
	
/*	filterRule_ = new boost::regex(FILTER_RULE);
	andRule_ = new boost::regex("&");
	littleRule_ = new boost::regex("<");*/
}

//-----------------------------------------------------------------------
// Func Name   : ~XmlStore
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
XmlStore::~XmlStore()
{
	//delete subjectDecodeRule_;
	/*delete filterRule_;
	delete andRule_;
	delete littleRule_;*/
}

//-----------------------------------------------------------------------
// Func Name   : DeclareXml
// Description : Initialize the XML file, and declare its version.
// Parameter   : fileName: The XML file you want to name
//               version: The XML version, such as 1.0.
//               encoding: The encoding type of XML, such as UTF-8.
// Return      : bool
//-----------------------------------------------------------------------
bool XmlStore::DeclareXml(const char* fileName, const char* tableName, const char* version, const char* encoding)
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
// Func Name   : InsertNode
// Description : Insert a message node to an existed XML file.
// Parameter   : msgNode: The target message node for storing.
// Return      : bool
//-----------------------------------------------------------------------
bool XmlStore::InsertNode(Node* node, fstream& file)
{
//cout << "begin_InsertNode://///////////" <<endl;
	//cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!"<<endl;
	bool insertOkay = false;
	//assert(node != NULL);
	if (node == NULL)
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
	WriteMsg(file, node);
	//cout<<"start writeMsg clear node"<<endl;
	ClearNode(node);
	//cout<<"start writeMsg del msgNode"<<endl;
	delete node;
    // Add the close root tag and message number, which have been covered.
	//file << "</table>";
    //file.close();
	insertOkay = true;
//cout << "end_InsertNode://///////" <<endl; 
	return insertOkay;
}

//-----------------------------------------------------------------------
// Func Name   : ClearNode
// Description : Free the members of message node.
// Parameter   : msgNode: The message node will be free.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStore::ClearNode(Node* node)
{
//cout << "begin_clearNode://////////"<< endl;

	if (node->fileName) {
		delete node->fileName;
		node->fileName = NULL;
	}

	if (node->from) {
		delete node->from;
		node->from = NULL;
	}

	if (node->to) {
		delete node->to;
		node->to = NULL;
	}

	if (node->text) {
		delete node->text;
		node->text = NULL;
	}
	
//cout<< "end_clearNode:///////" <<endl;	
}

//-----------------------------------------------------------------------
// Func Name   : WriteLogMsg
// Description : Write the login and logout types message into file.
// Parameter   : file: The file stream in which the message will be stored.
//               msgNode: The message node will be stored.
//               msgNum: The number of this message node.
// Return      : bool
//-----------------------------------------------------------------------
void XmlStore::WriteMsg(fstream& file, Node* node)
{
//cout << "begin_WriteMsg:////////////" <<endl;
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "  write xml start"<< endl;
	struct in_addr addr;
	file << "    <data>\n";
	file << "        <dev>" << node->device << "</dev>\n";
	file << "        <clueid>" << 0 << "</clueid>\n";
	
	addr.s_addr = node->srcIpv4;
	file << "        <src_ip>" << inet_ntoa(addr) << "</src_ip>\n";
	file << "        <src_port>" << node->srcPort << "</src_port>\n";
	addr.s_addr = node->destIpv4;
	file << "        <dest_ip>" << inet_ntoa(addr) << "</dest_ip>\n";
	file << "        <dest_port>" << node->destPort << "</dest_port>\n";
	file << "        <time>" << node->timeVal << "</time>\n";
	
	char srcMac[20];
	file << "        <mac>" <<  ParseMac(node->srcMac, srcMac) << "</mac>\n";
	switch (node->msgType) {
		case Login:
			file << "        <type>1</type>\n";
			break;
		case Logout:
			file << "        <type>2</type>\n";
			break;
		case Text:
			file << "        <type>3</type>\n";
			break;
		case Qun:
			file << "        <type>4</type>\n";
			break;
	}
	
	if (node->text != NULL) 
	{
		boost::regex filterRule_(FILTER_RULE);
		boost::regex andRule_("&");
		boost::regex littleRule_("<");
	
        // Filter tags like "<...>".
		string filterTag(regex_replace(string(node->text), filterRule_, ""));
        // Replace symbol "<" to "&lt;".
		file << "        <text>" << regex_replace(regex_replace(filterTag,andRule_, "&amp;"),
				littleRule_, "&lt;") << "</text>\n";
	} else {
		file << "        <text></text>\n";
	}
	if (node->from != NULL) {
		file << "        <from>" << node->from << "</from>\n";
	} else {
		file << "        <from></from>\n";
	}
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "        2"<< endl;
	if (node->to != NULL) {
		file << "        <to>" << node->to << "</to>\n";
	} else {
		file << "        <to></to>\n";
	}
    file << "        <protocolType>" <<  node->protocolType << "</protocolType>\n";
    file << "        <affixFlag>" <<  node->affixFlag << "</affixFlag>\n";
    file << "    </data>\n";
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "write xml end " << end
//cout << "end_WriteMsg://////////////" <<endl;
}


// End of file
