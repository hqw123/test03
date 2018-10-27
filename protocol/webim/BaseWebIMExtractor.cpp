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
// Module Name:     BaseWebIMExtractor.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class BaseWebIMExtractor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100622 tz Initial
// $d1= -------- 1.01 001 100622 tz Add the thread pool
//
//------------------------------------------------------------------------

#include <assert.h>
#include <iostream>
#include <sys/time.h>
#include <arpa/inet.h>
#include <boost/regex.hpp>

#include "BaseWebIMExtractor.h"
#include "Public.h"
//#include "Analyzer_log.h"

const int BUF_SIZE = 512;
//#define DATA_PATH "/home/LzData/moduleData"
//#define MOVE_PATH "/home/LzData"
#define FILTER_RULE "<[^>]*>"

//-----------------------------------------------------------------------
// Func Name   : BaseWebIMExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseWebIMExtractor::BaseWebIMExtractor()
{
    // Initialize the message buffer and thread pool.
    sessionProc2_ = NULL;
    msgNum_ = 0;
    devNum_ = GetDeviceNum();
    
    msgBuf2_ = new Buffer<Node*>(BUF_SIZE);
    sysClosed_ = false;
    //threadPool2_.size_controller().resize(1);
    //threadPool2_.schedule(boost::bind(&LoopStore, this));

}

//-----------------------------------------------------------------------
// Func Name   : ~BaseWebIMExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseWebIMExtractor::~BaseWebIMExtractor()
{
    //occi_->TerminateStmt(stmt_);
    
    //delete sessionMap_;
    delete msgBuf2_;
}

//-----------------------------------------------------------------------
// Func Name   : ~BaseWebIMExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::OnSysClosed()
{
    {
        boost::mutex::scoped_lock lock(sigMut2_);
        sysClosed_ = true;
    }
    //threadPool2_.wait();
    boost::mutex::scoped_lock lock(setMut2_);
  //  cout << typeid(*this).name() << " is closed." << endl;
  LOG_INFO("%s is closed.\n",typeid(*this).name());
}

bool BaseWebIMExtractor::IsSysClosed()
{
    bool isClosed;
    {
        boost::mutex::scoped_lock lock(sigMut2_); 
        isClosed = sysClosed_;
    }

    return sysClosed_;
}

//-----------------------------------------------------------------------
// Func Name   : PushNode
// Description : Push the message nodes into messge list in a session.
// Parameter   : fileName: The name of file you want to put the node in.
//               msgNode: Interested information in a network packet.
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::PushNode(Node* node)
{
//cout << "begin_PushNode:////////" <<endl;
    //assert(node != NULL);
    if (node == NULL)
		return;
	
    msgBuf2_->Push(node);
//cout << "end_pushNode://////////" <<endl;
}



//-----------------------------------------------------------------------
// Func Name   : LoopStore
// Description : Store the session into XML in loop. Thread function.
// Parameter   : obj: the object of this class for thread function.
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::LoopStore(void* obj)
{
    //assert(obj != NULL);
    if (obj == NULL)
		return;
	
    // Impress an object of BaseTextExtractor into this thread function.
	BaseWebIMExtractor* extractor = reinterpret_cast<BaseWebIMExtractor*>(obj);
    // Do loop.
    while (1) {
        if (extractor->IsSysClosed()) {
            break;
        }

        usleep(100);

        extractor->CheckBuf();
    }
}

//-----------------------------------------------------------------------
// Func Name   : CheckBuf
// Description : Get the session from the session buffer.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::CheckBuf()
{
    Node* node = msgBuf2_->Pop();
    if (node) {
        // Do something to the message node depending on each IM.
        ProcessSession(node);
        if (node) {
            // Store the data to CASE DB.
            //cout << "\nStart to get clue ...\n";
           
            //clueId = GetClueId(protoType_, msgNode->srcIpv4, msgNode->from);
            //cout << "Get clue finished ...\n";
		if (node->clueId) {
			//cout << "[" << tableName_ <<"]: Data for case! Clue ID is " << node->clueId << endl;
			LOG_INFO("[%s]: Data for case! Clue ID is %d\n",tableName_,node->clueId);
			//StoreMsg2DB(node, node->clueId);
		}	
         	   // Store the data into XML.
		if (msgNum_ == 0) 
		{
			xmlStore_.DeclareXml(dataFile_, tableName_, NULL, NULL);
			file_.open(dataFile_, ios::out | ios::ate | ios::in);
			if(!file_)
			{
				//cout<<" WEBIM WRITE XML open file error!"<<endl;
				LOG_ERROR(" WEBIM WRITE XML open file error!\n");
			}else{
			StoreMsg2Xml(node);
			++msgNum_;
			}
			
			  
		}

		else if (msgNum_ >=29) {
			StoreMsg2Xml(node);
			file_ << "</table>";
			file_.close();
			MoveDataFile();
			msgNum_ = 0;
		}	
		else
		{
			StoreMsg2Xml(node);
			++msgNum_;
		}
        }
    }
}

void BaseWebIMExtractor::MoveDataFile()
{
    //char srcPath[256];
    char destPath[256];
    time_t timeVal;
    time(&timeVal);
    //sprintf(srcPath, "%s/%s/%s\0", DATA_PATH, tableName_, tableName_);
    sprintf(destPath, "%s/spyData/%lu/%s_%lu.xml\0", LzDataPath, (timeVal/300)%12, tableName_, timeVal);
    rename(/*srcPath*/dataFile_, destPath);
}



//-----------------------------------------------------------------------
// Func Name   : RegSessionFunc
// Description : Register the session processor function.
// Parameter   : sessionProc the callback function to process the session.
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::RegSessionFunc(SessionProc sessionProc)
{
    sessionProc2_ = sessionProc;
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Execute the callback function.
// Parameter   : session: A talk session.
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::ProcessSession(Node*& node)
{
    if (sessionProc2_ != NULL) {
        sessionProc2_(node, this);
    }
    
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2Xml
// Description : Create XML file and store the messges into it.
// Parameter   : session: A session correspond to an XML file.
// Return      : void
//-----------------------------------------------------------------------
void BaseWebIMExtractor::StoreMsg2Xml(Node* node)
{
//cout << "begin_storeMsg2Xml://////////" <<endl;
    //assert(node != NULL);
    if (node == NULL)
		return;
	
	if(!file_)
	{
	//	cout<<"error!"<<endl;
		LOG_ERROR("error!\n");
	}
	
    xmlStore_.InsertNode(node, file_);
//cout << "end_storeMsg2xml://////////" << endl;
}
/*
void BaseWebIMExtractor::StoreMsg2DB(Node* node, u_int clueId)
{
//cout << "begin_StoreMsg2DB://////////" <<endl;
    struct in_addr addr;
    occi_->SetInt(stmt_, 1, devNum_);   
    occi_->SetInt(stmt_, 2, clueId);   
    addr.s_addr = node->srcIpv4;
    occi_->SetString(stmt_, 3, inet_ntoa(addr));  
    occi_->SetInt(stmt_, 4, node->srcPort);   
    addr.s_addr = node->destIpv4;
    occi_->SetString(stmt_, 5, inet_ntoa(addr));    
    occi_->SetInt(stmt_, 6, node->destPort);   
    occi_->SetTime(stmt_, 7, node->timeVal);    
    char srcMac[20];
    occi_->SetString(stmt_, 8, ParseMac(node->srcMac, srcMac));
	switch (node->msgType) {
		case Login:
			occi_->SetInt(stmt_, 9, 1);
			break;
		case Logout:
			occi_->SetInt(stmt_, 9, 2);
			break;
		case Text:
			occi_->SetInt(stmt_, 9, 3);
			break;
		case Qun:
			occi_->SetInt(stmt_, 9, 4);
			break;
	}
	if (node->text != NULL) {
		occi_->SetString(stmt_, 10, regex_replace(string(node->text), boost::regex(FILTER_RULE), "").c_str());
	} else {
		occi_->SetString(stmt_, 10, "");        
	}
	if (node->from != NULL) {
		occi_->SetString(stmt_, 11, node->from);       
	} else {
		occi_->SetString(stmt_, 11, "");        
	}
	if (node->to != NULL) {
		occi_->SetString(stmt_, 12, node->to);     
	} else {
		occi_->SetString(stmt_, 12, "");       
	}
	occi_->SetInt(stmt_, 13, node->protocolType);
    occi_->DoSql(stmt_);
//cout << "end_StoreMsg2DB://////////" <<endl;
}

void BaseWebIMExtractor::AddFilterPort(int port)
{
    boost::mutex::scoped_lock lock(setMut2_);
    portSet_.insert((u_short)port);
}

void BaseWebIMExtractor::SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing)
{
    isRunning_ = isRunning;
    attachSize_ = attachSize * 1024 * 1024; // Mega Bytes
    isDeepParsing_ = isDeepParsing;
}
*/

// End of file.
