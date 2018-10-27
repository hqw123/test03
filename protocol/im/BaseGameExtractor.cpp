
#include <assert.h>
#include <iostream>
#include <sys/time.h>
#include <arpa/inet.h>
#include <boost/regex.hpp>

#include "BaseGameExtractor.h"
#include "Public.h"
//#include "Analyzer_log.h"

const int BUF_SIZE = 512;
#define FILTER_RULE "<[^>]*>"

//-----------------------------------------------------------------------
// Func Name   : BaseGameExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseGameExtractor::BaseGameExtractor()
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
// Func Name   : ~BaseGameExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
BaseGameExtractor::~BaseGameExtractor()
{
#if 0  //zhangzm
    occi_->TerminateStmt(stmt_);
#endif
    
    //delete sessionMap_;
    delete msgBuf_;
}

//-----------------------------------------------------------------------
// Func Name   : ~BaseGameExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void BaseGameExtractor::OnSysClosed()
{
    {
        boost::mutex::scoped_lock lock(sigMut_);
        sysClosed_ = true;
    }
    //threadPool_.wait();
    boost::mutex::scoped_lock lock(setMut_);
   // cout << typeid(*this).name() << " is closed." << endl;
	LOG_INFO("%s is closed.\n",typeid(*this).name());
  
}

bool BaseGameExtractor::IsSysClosed()
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
void BaseGameExtractor::PushNode(MsgNode* msgNode)
{
    //assert(msgNode != NULL);
    if (msgNode == NULL)
		return;
	
    msgBuf_->Push(msgNode);
}


/*
void BaseGameExtractor::PushNode(const string& fileName, MsgNode* msgNode)
{
    // Find the corresponding session from message map.
    SessionMap::iterator it = sessionMap_->find(fileName);
    if (it == sessionMap_->end()) {
        // If no result, create a new session, and insert the message node into it.
        Session* session = new Session;
        session->fileName = new string(fileName);
        session->msgNum = 1;
        session->msgList = new MsgList;
        session->msgList->push_back(msgNode);
        sessionMap_->insert(SessionMap::value_type(fileName, session));
    } else {
        // Otherwise, insert the node directly.
        Session* session = it->second;
        session->msgList->push_back(msgNode);
        session->msgNum++;
        // Push the session into message buffer if the message number more than a predefined value.
        if (session->msgNum > MAX_MSG_NUM) {
            {
                // Multiple threads handle the buffer, so lock it.
                boost::mutex::scoped_lock lock(bufMut_);
                msgBuf_->push_back(session);
            }
            // Erase the session from session map after it being pushed into buffer.
            sessionMap_->erase(it);
        }
    }
}
*/

//-----------------------------------------------------------------------
// Func Name   : LoopStore
// Description : Store the session into XML in loop. Thread function.
// Parameter   : obj: the object of this class for thread function.
// Return      : void
//-----------------------------------------------------------------------
void BaseGameExtractor::LoopStore(void* obj)
{
    //assert(obj != NULL);
    if (obj == NULL)
		return;
    // Impress an object of BaseGameExtractor into this thread function.
    BaseGameExtractor* extractor = reinterpret_cast<BaseGameExtractor*>(obj);
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
void BaseGameExtractor::CheckBuf()
{
    MsgNode* msgNode = msgBuf_->Pop();
    if (msgNode) {
        // Do something to the message node depending on each IM.
        ProcessSession(msgNode);
        if (msgNode) {
            // Store the data to CASE DB.
            //cout << "\nStart to get clue ...\n";
           
            //clueId = GetClueId(protoType_, msgNode->srcIpv4, msgNode->from);
            //cout << "Get clue finished ...\n";
            if (msgNode->clueId) {
             //   cout << "[" << tableName_ <<"]: Data for case! Clue ID is " << msgNode->clueId << endl;
             	LOG_INFO("[%s]: Data for case! Clue ID is %d\n",tableName_,msgNode->clueId);
                StoreMsg2DB(msgNode, msgNode->clueId);
            }
            // Store the data into XML.
   
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
            else if (msgNum_ >= 9)
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

void BaseGameExtractor::MoveDataFile()
{
    //char srcPath[256];
    char destPath[256];
    time_t timeVal;
    time(&timeVal);
    sprintf(destPath, "%s/spyData/%lu/%s_%lu.xml\0", LzDataPath, (timeVal/300)%12, tableName_, timeVal);
    rename(/*srcPath*/dataFile_, destPath);
}

/*
void BaseGameExtractor::CheckBuf()
{
    Session* session = NULL;
    {
        // Lock the buffer.
        boost::mutex::scoped_lock lock(bufMut_);
        list<Session*>::iterator it = msgBuf_->begin();
        if (it != msgBuf_->end()) {
            session = *it;
            msgBuf_->erase(it);
        }
    }
    if (session) {
        // Do something to the session depending on each IM.
        ProcessSession(session);
        // Store the session into XML.
        if (session->msgNum > 0) {
            StoreMsg2Xml(session);
        }
        delete session->fileName;
        delete session;
    }
}
*/

//-----------------------------------------------------------------------
// Func Name   : RegSessionFunc
// Description : Register the session processor function.
// Parameter   : sessionProc the callback function to process the session.
// Return      : void
//-----------------------------------------------------------------------
void BaseGameExtractor::RegSessionFunc(SessionProc sessionProc)
{
    sessionProc_ = sessionProc;
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Execute the callback function.
// Parameter   : session: A talk session.
// Return      : void
//-----------------------------------------------------------------------
void BaseGameExtractor::ProcessSession(MsgNode*& msgNode)
{
    if (sessionProc_ != NULL) {
        sessionProc_(msgNode, this);
    }
    /*
    if (msgNode->text != NULL && *msgNode->text == '\0') {
        delete msgNode->text;
        msgNode->text = NULL;
    }
    if (msgNode->text == NULL && msgNode->msgType == Text) {
        if (msgNode->fileName != NULL) {
            delete msgNode->fileName;
        }
        if (msgNode->from != NULL) {
            delete msgNode->from;
        }
        if (msgNode->to != NULL) {
            delete msgNode->to;
        }
        if (msgNode->time != NULL) {
            delete msgNode->time;
        }
        delete msgNode;
        msgNode = NULL;
    }*/
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2Xml
// Description : Create XML file and store the messges into it.
// Parameter   : session: A session correspond to an XML file.
// Return      : void
//-----------------------------------------------------------------------
void BaseGameExtractor::StoreMsg2Xml(MsgNode* msgNode)
{
    //assert(msgNode != NULL);
	if (msgNode == NULL)
		return;
    // Check the file if exist.
    //ifstream file(msgNode->fileName);
    /*
    ifstream file(dataFile_);
    // If not exist, create it.
    if (file == NULL) {
        xmlStorer_.DeclareXml(dataFile_, tableName_, NULL, NULL);
    }
    file.close();*/
    // Store the messages into XML file.
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "start";
    xmlStorer_.InsertMsgNode(msgNode, file_);
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "end";
	
}

void BaseGameExtractor::StoreMsg2DB(MsgNode* msgNode, u_int clueId)
{   
    struct in_addr addr;

#if 0 //zhangzm POP solved
    occi_->SetInt(stmt_, 1, devNum_);   
    occi_->SetInt(stmt_, 2, clueId);   
    addr.s_addr = msgNode->srcIpv4;
    occi_->SetString(stmt_, 3, inet_ntoa(addr));  
    occi_->SetInt(stmt_, 4, msgNode->srcPort);    
    addr.s_addr = msgNode->destIpv4;
    occi_->SetString(stmt_, 5, inet_ntoa(addr));    
    occi_->SetInt(stmt_, 6, msgNode->destPort);   
    occi_->SetTime(stmt_, 7, msgNode->timeVal);    
    char srcMac[20];
    occi_->SetString(stmt_, 8, ParseMac(msgNode->srcMac, srcMac)); 
	if (msgNode->user != NULL) {   
    	occi_->SetString(stmt_, 9, msgNode->user);
	}else{
		occi_->SetString(stmt_, 9, "");	
	}
    if (msgNode->pass != NULL) {
        occi_->SetString(stmt_, 10, msgNode->pass);     
    } else {
        occi_->SetString(stmt_, 10, "");       
    }
    occi_->SetInt(stmt_, 11, msgNode->protocolType);    
    occi_->DoSql(stmt_);
#endif
}

void BaseGameExtractor::AddFilterPort(int port)
{
    boost::mutex::scoped_lock lock(setMut_);
    portSet_.insert((u_short)port);
}

void BaseGameExtractor::SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing)
{
    isRunning_ = isRunning;
    attachSize_ = attachSize * 1024 * 1024; // Mega Bytes
    isDeepParsing_ = isDeepParsing;
}


// End of file.
