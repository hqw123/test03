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
// Module Name:     BaseToolsExtractor.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class BaseToolsExtractor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 100507 tz Initial
// $d1= -------- 1.01 001 100507 tz Add the thread pool
//
//------------------------------------------------------------------------

#include <assert.h>
#include <iostream>
#include <sys/time.h>
#include <arpa/inet.h>
#include <boost/regex.hpp>

#include "BaseToolsExtractor.h"
#include "Public.h"
//#include "Analyzer_log.h"

const int BUF_SIZE = 512;
#define DATA_PATH "/home/spyData/moduleData"
#define MOVE_PATH "/home/spyData"
#define FILTER_RULE "<[^>]*>"

//-----------------------------------------------------------------------
// Func Name   : BaseTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseToolsExtractor::BaseToolsExtractor()
{
    // Initialize the message buffer and thread pool.
    sessionProc3_ = NULL;
    msgNum_ = 0;
    devNum_ = GetDeviceNum();
    
    msgBuf3_ = new Buffer<MsNode*>(BUF_SIZE);
    sysClosed_ = false;
    //threadPool3_.size_controller().resize(1);
    //threadPool3_.schedule(boost::bind(&LoopStore, this));

}

//-----------------------------------------------------------------------
// Func Name   : ~BaseToolsExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseToolsExtractor::~BaseToolsExtractor()
{
    //occi_->TerminateStmt(stmt_);
    
    //delete sessionMap_;
    delete msgBuf3_;
}

//-----------------------------------------------------------------------
// Func Name   : ~BaseTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void BaseToolsExtractor::OnSysClosed()
{
    {
        boost::mutex::scoped_lock lock(sigMut3_);
        sysClosed_ = true;
    }
    //threadPool3_.wait();
    boost::mutex::scoped_lock lock(setMut3_);
  //  cout << typeid(*this).name() << " is closed." << endl;
  LOG_INFO("%s is closed.\n",typeid(*this).name());
	
}

bool BaseToolsExtractor::IsSysClosed()
{
    bool isClosed;
    {
        boost::mutex::scoped_lock lock(sigMut3_); 
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
void BaseToolsExtractor::PushNode(MsNode* node)
{
    //assert(node != NULL);
	if (node == NULL)
		return;
	
    msgBuf3_->Push(node);
}

//-----------------------------------------------------------------------
// Func Name   : LoopStore
// Description : Store the session into XML in loop. Thread function.
// Parameter   : obj: the object of this class for thread function.
// Return      : void
//-----------------------------------------------------------------------
void BaseToolsExtractor::LoopStore(void* obj)
{
    //assert(obj != NULL);
    if (obj == NULL)
		return;
	
    // Impress an object of BaseTextExtractor into this thread function.
    BaseToolsExtractor* extractor = reinterpret_cast<BaseToolsExtractor*>(obj);
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
void BaseToolsExtractor::CheckBuf()
{
   


 MsNode* node = msgBuf3_->Pop();
    if (node) {
        // Do something to the message node depending on each IM.
        ProcessSession(node);
        if (node) {
            // Store the data to CASE DB.
            //cout << "\nStart to get clue ...\n";
           
            //clueId = GetClueId(protoType_, msgNode->srcIpv4, msgNode->from);
            //cout << "Get clue finished ...\n";
            if (node->clueId) {
               // cout << "[" << tableName_ <<"]: Data for case! Clue ID is " << node->clueId << endl;
				LOG_INFO("[%s]: Data for case! Clue ID is %d\n",tableName_,node->clueId);
                //StoreMsg2DB(node, node->clueId);
                //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Store to DB finished ...\n";
            }
            // Store the data into XML.

	    if (msgNum_ == 0) 
	    {
		   
		    xmlStor_.DeclareXml(dataFile_, tableName_, NULL, NULL);
		    file_.open(dataFile_, ios::out | ios::ate | ios::in);
		    if(!file_)
		    {
			    //cout<<"open error!"<<endl;
			    LOG_ERROR("open error!\n");
		    }
			else{
			StoreMsg2Xml(node);
                    	++msgNum_;
			
 		    }
			   
	    }
	    else if (msgNum_ >= 5) 
	    {
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

void BaseToolsExtractor::MoveDataFile()
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
void BaseToolsExtractor::RegSessionFunc(SessionProc sessionProc)
{
    sessionProc3_ = sessionProc;
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Execute the callback function.
// Parameter   : session: A talk session.
// Return      : void
//-----------------------------------------------------------------------
void BaseToolsExtractor::ProcessSession(MsNode*& node)
{
    if (sessionProc3_ != NULL) {
        sessionProc3_(node, this);
    }
    
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2Xml
// Description : Create XML file and store the messges into it.
// Parameter   : session: A session correspond to an XML file.
// Return      : void
//-----------------------------------------------------------------------
void BaseToolsExtractor::StoreMsg2Xml(MsNode* node)
{
    //assert(node != NULL);
    if (node == NULL)
		return;
	
	if(!file_)
	{
		//cout<<"error!"<<endl;
		LOG_ERROR("error!\n");
	}
	
    xmlStor_.InsertNode(node, file_);
	
}
/*
void BaseToolsExtractor::StoreMsg2DB(Node* node, u_int clueId)
{
    struct in_addr addr;
    occi_->SetInt(stmt_, 1, devNum_);   
    occi_->SetInt(stmt_, 2, clueId);   
	/*if(node->protocolType==PROTOCOL_ID_UNBOUNDED){
		addr.s_addr = node->destIpv4;
		occi_->SetString(stmt_, 3, inet_ntoa(addr));  
		occi_->SetInt(stmt_, 4, node->destPort);    
		addr.s_addr = node->srcIpv4;
		occi_->SetString(stmt_, 5, inet_ntoa(addr));    
		occi_->SetInt(stmt_, 6, node->srcPort);   
		occi_->SetTime(stmt_, 7, node->timeVal);    
		char srcMac[20];
		occi_->SetString(stmt_, 8, ParseMac(node->destMac, srcMac));    

		occi_->SetInt(stmt_, 9, node->protocolType);
	}else{*/
/*    addr.s_addr = node->srcIpv4;
    occi_->SetString(stmt_, 3, inet_ntoa(addr));  
    occi_->SetInt(stmt_, 4, node->srcPort);    
    addr.s_addr = node->destIpv4;
    occi_->SetString(stmt_, 5, inet_ntoa(addr));    
    occi_->SetInt(stmt_, 6, node->destPort);   
    occi_->SetTime(stmt_, 7, node->timeVal);    
    char srcMac[20];
    occi_->SetString(stmt_, 8, ParseMac(node->srcMac, srcMac));    

	occi_->SetInt(stmt_, 9, node->protocolType);
	//}    
    occi_->DoSql(stmt_);
}

void BaseToolsExtractor::AddFilterPort(int port)
{
    boost::mutex::scoped_lock lock(setMut2_);
    portSet_.insert((u_short)port);
}

void BaseToolsExtractor::SetStatu(bool isRunning, u_int attachSize, bool isDeepParsing)
{
    isRunning_ = isRunning;
    attachSize_ = attachSize * 1024 * 1024; // Mega Bytes
    isDeepParsing_ = isDeepParsing;
}
	*/

// End of file.
