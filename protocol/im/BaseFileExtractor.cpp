//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 RYing Information Security Techology CO., Ltd.
// This program belongs to RYing ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise RYing    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     BaseFileExtractor.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class BaseFileExtractor. 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081210 Zhao Junzhe Initial
// $d1= -------- 1.00 002 081212 Zhao Junzhe Add the thread pool
// $d2= -------- 1.00 003 090806 Zhao Junzhe Using the FileStream class to 
//                                           refine the FileSession
//
//------------------------------------------------------------------------

#include <assert.h>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>

#include "BaseFileExtractor.h"
#include "Public.h"
//#include "Analyzer_log.h"

FileSession::FileSession() : fileStream_(NULL)
{
}

FileSession::~FileSession()
{
//	cout << __FILE__ << ":" << __FUNCTION__ << endl;
    if (fileStream_) {
        delete fileStream_;
    }
}

const int BUF_SIZE = 256;
//#define DATA_PATH "/home/nodeData/moduleData"
#define MOVE_PATH "/home/spyData"

//-----------------------------------------------------------------------
// Func Name   : BaseFileExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseFileExtractor::BaseFileExtractor()
{
    // Initialize the session map, message buffer and thread pool.
    sessionProc_ = NULL;
    msgNum_ = 0;
    devNum_ = GetDeviceNum();

    //sessionMap_ = new SessionMap;
    msgBuf_ = new Buffer<MsgNode*>(BUF_SIZE);
    sysClosed_ = false;
    //threadPool_.size_controller().resize(1);
    //threadPool_.schedule(boost::bind(&LoopStore, this));
}

//-----------------------------------------------------------------------
// Func Name   : ~BaseFileExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseFileExtractor::~BaseFileExtractor()
{
//	cout << __FILE__ << ":" << __FUNCTION__ <<"del msgBuf_ "<< endl;
   // occi_->TerminateStmt(stmt_);
    //delete sessionMap_;
    delete msgBuf_;
//	cout << __FILE__ << ":" << __FUNCTION__ <<"del 11"<< endl;
}

//-----------------------------------------------------------------------
// Func Name   : ~BaseFileExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void BaseFileExtractor::OnSysClosed()
{
	//cout << __FILE__ << ":" << __FUNCTION__  << endl;
    {
        boost::mutex::scoped_lock lock(sigMut_);
        sysClosed_ = true;
    }
    //threadPool_.wait();
    //cout << typeid(*this).name() << " is closed." << endl;
    LOG_INFO("%s is closed.\n",typeid(*this).name());
}

bool BaseFileExtractor::IsSysClosed()
{
	
    bool isClosed;
    {
        boost::mutex::scoped_lock lock(sigMut_); 
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
void BaseFileExtractor::PushNode(MsgNode* msgNode)
{
    //assert(msgNode != NULL);
	if (msgNode == NULL)
		return;
	
    msgBuf_->Push(msgNode);
}

//-----------------------------------------------------------------------
// Func Name   : LoopStore
// Description : Store the session into XML in loop. Thread function.
// Parameter   : obj: the object of this class for thread function.
// Return      : void
//-----------------------------------------------------------------------
void BaseFileExtractor::LoopStore(void* obj)
{
    //assert(obj != NULL);
    if (obj == NULL)
		return;
    // Impress an object of BaseFileExtractor into this thread function.
    BaseFileExtractor* extractor = reinterpret_cast<BaseFileExtractor*>(obj);
    // Do loop.
    while (1) {
        {
            if (extractor->IsSysClosed()) {
				//cout<<"issysclosed"<<endl;
                break;
            }
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
void BaseFileExtractor::CheckBuf()
{
    MsgNode* msgNode = msgBuf_->Pop();
    if (msgNode) {
        // Do something to the message node depending on each IM.
        ProcessSession(msgNode);
        if (msgNode) {
			//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "msgNode != NULL" << endl;
            // Store the data to CASE DB.
            if (msgNode->clueId) {
               // cout << "[" << tableName_ <<"]: Data for case! Clue ID is " << msgNode->clueId << endl;
				LOG_INFO("[%s]: Data for case! Clue ID is %d\n",tableName_,msgNode->clueId);
                StoreMsg2DB(msgNode);
//                cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Store to DB finished ...\n";
            }
            // Store the session into XML.

   
	    if (msgNum_ == 0) 
	    {
	
		
               xmlStorer_.DeclareXml(dataFile_, tableName_, NULL, NULL);
               // file_.open(dataFile_, ios::out | ios::in);
               file_.open(dataFile_, ios::out | ios::ate | ios::in);
		if(!file_)
		    {
			    //cout<<"open error!"<<endl;
				LOG_ERROR("open error!\n");
		    }else{
			StoreMsg2Xml(msgNode);
                    	++msgNum_;
			
 		    }
            }
            else if (msgNum_ >= 5)
	    {
		StoreMsg2Xml(msgNode);
                    
		file_ << "</table>";
                file_.close();

		MoveDataFile();
                msgNum_ = 0;
            }
	    else 
	    {
		    StoreMsg2Xml(msgNode);
		    ++msgNum_;
	}
        }
    }
}

void BaseFileExtractor::MoveDataFile()
{
    char destPath[100];
    time_t timeVal;
    time(&timeVal);
    sprintf(destPath, "%s/spyData/%lu/%s_%lu.xml\0", LzDataPath, (timeVal/300)%12, tableName_, timeVal);
    rename(dataFile_, destPath);
}

//-----------------------------------------------------------------------
// Func Name   : RegSessionFunc
// Description : Register the session processor function.
// Parameter   : sessionProc the callback function to process the session.
// Return      : void
//-----------------------------------------------------------------------
void BaseFileExtractor::RegSessionFunc(SessionProc sessionProc)
{
    sessionProc_ = sessionProc;
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Execute the callback function.
// Parameter   : session: A talk session.
// Return      : void
//-----------------------------------------------------------------------
void BaseFileExtractor::ProcessSession(MsgNode*& msgNode)
{
    if (sessionProc_ != NULL) {
        sessionProc_(msgNode, this);
    }
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2Xml
// Description : Create XML file and store the messges into it.
// Parameter   : session: A session correspond to an XML file.
// Return      : void
//-----------------------------------------------------------------------
void BaseFileExtractor::StoreMsg2Xml(MsgNode* msgNode)
{
	 //assert(msgNode != NULL);
	 if (msgNode == NULL)
	 	return;
    // Store the messages into XML file.
    xmlStorer_.InsertMsgNode(msgNode, file_);
//	cout << __FILE__ << ":" << __FUNCTION__ <<"msgnode insert to xml sucess!"<< endl;
}

void BaseFileExtractor::SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing, u_int miniSize)
{
    isRunning_ = isRunning;
    attachSize_ = attachSize * 1024 * 1024; // Mega Bytes
    isDeepParsing_ = isDeepParsing;
	miniSize_ = miniSize * 1024 * 1024;
}

// End of file.
