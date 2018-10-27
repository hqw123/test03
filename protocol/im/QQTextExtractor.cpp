#include "QQTextExtractor.h"
#include "Public.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>
//#include <sys/time.h>

#define QQ_HEAD     0x02
#define QQ_END      0x03
#define QQ_LOGIN    0x22
#define QQ_LOGOUT   0x01
#define QQ_SEND     0x16
#define QQ_V09_SEND 0xcd
#define QQ_RECV     0x17
#define QQ_SERV     0x0001
#define MIN_PKT_LEN 12

#define QQ_COMMAND  4
#define QQ_VERSION  1
#define QQ_NUMBER   7
#define QQ_SEND_BODY 11
#define QQ_RECV_BODY 7
#define QQ_BUDDY    0x6003
#define QQ_BUDDY2   0x5103
#define QQ_BUDDY_TAG  0x0b
//#define QQ_BUDDY_TAG  0x1000
//TM2007beta1
#define TM_BUDDY 0x1803

#define QQ_QUN 0x0101
#define QQ_QUN_TAG 0x01000000

QQTextExtractor::QQTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",nodeDataPath,"/nodeData/moduleData/QQ");
    isRunning_ = true;
    isDeepParsing_ = false;
    protoType_ = PROTOCOL_QQ;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

    memcpy(tableName_, "QQ", 3);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
    ClearFilterPort();
}

QQTextExtractor::~QQTextExtractor()
{
}

bool QQTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isQQText = false;
	//assert(pktInfo != NULL);
	if (!isRunning_) {
		return false;
	}
	/*{
		boost::mutex::scoped_lock lock(setMut_);
		if (portSet_.find(pktInfo->srcPort) == portSet_.end() && portSet_.find(pktInfo->destPort) == portSet_.end()) {
		return false;
		}
	}*/
	pktInfo_ = pktInfo;
	u_short minLen;
	/*if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort)) {
		return false;
	}*/
	/*
	if (pktInfo_->ipid == QQ_SERV) {
		return false;
	}*/
	if (pktInfo_->pktType == TCP) {
		if (!pktInfo_->tcp->psh) {
			return false;
		}
		minLen = MIN_PKT_LEN + 2;
		offside_ = 2;
	} else {
		minLen = MIN_PKT_LEN;
		offside_ = 0;
	}
	if(//pktInfo_->bodyLen > minLen &&
	   *reinterpret_cast<const u_short*>(pktInfo_->body) == QQ_QUN && *reinterpret_cast<const u_int*>(pktInfo_->body + 4) == QQ_QUN_TAG){
		//cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ GroupNums!!!"<<endl;    
		isQQText = GetQunNum();
	}
    
	if ((pktInfo_->bodyLen > minLen) &&
            *reinterpret_cast<const u_short*>(pktInfo_->body) == TM_BUDDY && 
            *reinterpret_cast<const u_short*>(pktInfo_->body + 56) == QQ_BUDDY_TAG){   
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Buddies!!!"<<endl;    
		isQQText = MatchTM();
	}
	else if (((pktInfo_->bodyLen > minLen) &&
		 *reinterpret_cast<const u_short*>(pktInfo_->body) == QQ_BUDDY && 
		 *(pktInfo_->body + 56) == QQ_BUDDY_TAG)||((pktInfo_->bodyLen > minLen) &&
		 *reinterpret_cast<const u_short*>(pktInfo_->body) == QQ_BUDDY2 && 
		 *(pktInfo_->body + 56) == QQ_BUDDY_TAG)){   
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Buddies!!!"<<endl;    
		isQQText = MatchQQ();
	}
	if (pktInfo_->bodyLen > minLen &&
            *(pktInfo_->body + offside_) == QQ_HEAD &&
            *(pktInfo_->body + pktInfo_->bodyLen - 1) == QQ_END) {
		qqCommand_ = *reinterpret_cast<const u_char*>(pktInfo_->body + offside_ + QQ_COMMAND);
		//cout << "----------------QQ MSG--------------" << endl;
		switch (qqCommand_) {
			case QQ_SEND:
			case QQ_V09_SEND:
			case QQ_LOGOUT:
			case QQ_LOGIN:
				if (!ntohs(pktInfo_->ip->id)) {
					isQQText = true;
					break;
				}
				// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Text Data!!!"<<endl;
				PushMassage();
                
				isQQText = true;
				break;
			case QQ_RECV:
				if (ntohs(pktInfo_->ip->id)) {
					isQQText = true;
					break;
				}
				// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Text Data!!!"<<endl;
				PushMassage();
				
				isQQText = true;
				break;
		}
		if (isQQText && pktInfo_) {
			pktInfo_ = NULL;
		}
	}

	return isQQText;
}

bool QQTextExtractor::CheckPort(u_short port)
{
    switch (port) {
        case 80:
        case 443:
        case 8000:
	case 4000:
            return true;
    }
   /* if (port >= 6000 && port <= 6005) {
        return true;
    }*/
    if (port > 4000 && port < 4010) {
        return true;
    }
    return false;
}

bool QQTextExtractor::MatchQQ()
{
    bool matched = false;
   
    char strmac[20];
			memset(strmac,0,20);
			ParseMac(pktInfo_->srcMac,strmac);
			u_int clueId;

			clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4);

    if (!clueId) {
               matched = false;
    }else if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 58))<=0){
		matched = false;
	}
	else{
    char* user = new char[12]; 
    sprintf(user, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 58)));
  
    
    //for(int i=64;i<=pktInfo_->bodyLen-40;i+=4){
    for(int i=64;i<=pktInfo_->bodyLen-4;i+=4){
	if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + i))<=0)
	{
		matched=false;
	}else{
    char* buddy =new char[12];
    sprintf(buddy, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + i)));

#if 0  //zhangzm VW_RELATION_TABLE
    const char* sql="insert into VW_RELATION_TABLE (relationid, account, type, friendsnum, capturetime, isgroup) values (relationid.nextval, :v1, :v2, :v3, :v4, :v5)";
        oracle::occi::Statement* stmt2_;
        stmt2_= occi_->CreateStmt();
        occi_->SetSql(stmt2_, sql);
        occi_->SetString(stmt2_, 1, user);
        occi_->SetInt(stmt2_, 2, PROTOCOL_ID_QQ);
        occi_->SetString(stmt2_, 3, buddy);
        time_t timeVal;
        time(&timeVal);
        occi_->SetTime(stmt2_, 4, timeVal);
       	occi_->SetInt(stmt2_, 5, 0);
        cout << "[QQ]: Data for case!Get the buddies! "<< buddy << endl;
        occi_->DoSql(stmt2_);
              
        occi_->TerminateStmt(stmt2_);
#endif
		
        delete buddy;                                          
        matched = true;
	}
      } 
    delete user;
    }
    return matched;
}
bool QQTextExtractor::MatchTM()
{
    bool matched = false;
   
    char strmac[20];
			memset(strmac,0,20);
			ParseMac(pktInfo_->srcMac,strmac);
			u_int clueId;

			clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4);

    if (!clueId) {
               matched = false;
    }else if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + pktInfo_->bodyLen - 4))<=0){
		matched = false;
	}
	else{
    char* user = new char[12]; 
    sprintf(user, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + pktInfo_->bodyLen - 4)));
  
    
    for(int i=60;i<=pktInfo_->bodyLen-8;i+=4){
	if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + i))<=0)
	{
		matched=false;
	}else{
    char* buddy =new char[12];
    sprintf(buddy, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + i)));

#if 0  //zhangzm VW_RELATION_TABLE
    const char* sql="insert into VW_RELATION_TABLE (relationid, account, type, friendsnum, capturetime, isgroup) values (relationid.nextval, :v1, :v2, :v3, :v4, :v5)";
        oracle::occi::Statement* stmt2_;
        stmt2_= occi_->CreateStmt();
        occi_->SetSql(stmt2_, sql);
        occi_->SetString(stmt2_, 1, user);
        occi_->SetInt(stmt2_, 2, PROTOCOL_ID_QQ);
        occi_->SetString(stmt2_, 3, buddy);
        time_t timeVal;
        time(&timeVal);
        occi_->SetTime(stmt2_, 4, timeVal);
       	occi_->SetInt(stmt2_, 5, 0);
        cout << "[QQ]: Data for case!Get the buddies! "<< buddy << endl;
        occi_->DoSql(stmt2_);
              
        occi_->TerminateStmt(stmt2_);
#endif
        delete buddy;                                          
        matched = true;
	}
      } 
    delete user;
    }
    return matched;
}


bool QQTextExtractor::GetQunNum()
{
    bool matched = false;
   
    char strmac[20];
			memset(strmac,0,20);
			ParseMac(pktInfo_->srcMac,strmac);
			u_int clueId;

			clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4);

    if (!clueId) {
               matched = false;
    }else{
    char* user = new char[12]; 
    sprintf(user, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 56)));
  
    
    for(int i=61;i<pktInfo_->bodyLen;i+=4){

	u_int sendNum = ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + i));
	int qunNum;
	if(sendNum>2100000000){
	qunNum=sendNum-2080000000;
	}else if(sendNum<2000000000){
	qunNum=sendNum-202000000;
	}else{
	qunNum=sendNum-1943000000;
	}
	//cout<<"groupNum: "<<qunNum<<endl;
    char* groupNum =new char[12];
    sprintf(groupNum, "%d\0", qunNum);

#if 0  //zhangzm VW_RELATION_TABLE
    const char* sql="insert into VW_RELATION_TABLE (relationid, account, type, friendsnum, capturetime, isgroup) values (relationid.nextval, :v1, :v2, :v3, :v4, :v5)";
        oracle::occi::Statement* stmt2_;
        stmt2_= occi_->CreateStmt();
        occi_->SetSql(stmt2_, sql);
        occi_->SetString(stmt2_, 1, user);
        occi_->SetInt(stmt2_, 2, PROTOCOL_ID_QQ);
        occi_->SetString(stmt2_, 3, groupNum);
        time_t timeVal;
        time(&timeVal);
        occi_->SetTime(stmt2_, 4, timeVal);
        occi_->SetInt(stmt2_, 5, 1);
        cout << "[QQ]: Data for case!Get the groupNum! "<< groupNum << endl;
        occi_->DoSql(stmt2_);
              
        occi_->TerminateStmt(stmt2_);
#endif
        delete groupNum;                                          
        matched = true;
      } 
    delete user;
    }
    return matched;
}
/*void QQTextExtractor::PushMassage()
{
    // Create and push message node for source address.
    MsgNode* srcNode;
    u_int clueId;
    switch (qqCommand_) {
        case QQ_LOGIN: {
            srcNode = new MsgNode;
            memset(srcNode, 0, sizeof(MsgNode));
            srcNode->msgType = Login;
            srcNode->to = NULL;
            char* from = new char[12]; // The max length of long number
            sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));
            srcNode->from = from;
            clueId = GetClueId(protoType_, pktInfo_->srcIpv4, srcNode->from);
            srcNode->text = NULL;
            break;
        }
        case QQ_LOGOUT: {
            srcNode = new MsgNode;
            memset(srcNode, 0, sizeof(MsgNode));
            srcNode->msgType = Logout;
            srcNode->to = NULL;
            char* from = new char[12]; // The max length of long number
            sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));
            srcNode->from = from;
            clueId = GetClueId(protoType_, pktInfo_->srcIpv4);
            srcNode->text = NULL;
            break;
        }
        case QQ_SEND:
        case QQ_V09_SEND: {
            char* from = new char[12]; // The max length of long number
            sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));
            clueId = GetClueId(protoType_, pktInfo_->srcIpv4, from);
            if (!clueId) {
                delete from;
                return;
            }
            srcNode = new MsgNode;
            memset(srcNode, 0, sizeof(MsgNode));
            srcNode->msgType = Text;
            srcNode->to = NULL;
            srcNode->from = from;
            /*
            char* text = new char[pktInfo_->bodyLen];
            memcpy(text, pktInfo_->body + offside_ + QQ_SEND_BODY, pktInfo_->bodyLen - QQ_SEND_BODY - offside_ - 1);
            text[pktInfo_->bodyLen - QQ_SEND_BODY - offside_ - 1] = 0;
            srcNode->text = text;*/
 /*           srcNode->text = NULL;
            break;
        }
        case QQ_RECV: {
            clueId = GetClueId(protoType_, pktInfo_->destIpv4);
            if (!clueId) {
                return;
            }
            srcNode = new MsgNode;
            memset(srcNode, 0, sizeof(MsgNode));
            srcNode->msgType = Text;
            srcNode->to = NULL;
            srcNode->from = NULL;
            /*char* text = new char[pktInfo_->bodyLen];
            memcpy(text, pktInfo_->body + offside_ + QQ_RECV_BODY, pktInfo_->bodyLen - QQ_RECV_BODY - offside_ - 1);
            text[pktInfo_->bodyLen - QQ_RECV_BODY - offside_ - 1] = 0;
            srcNode->text = text;*/
 /*           srcNode->text = NULL;
            break;
        }
    }
    srcNode->time = NULL;
    time(&srcNode->timeVal);
    // Copy basic data to message node
    memcpy(srcNode, pktInfo_, COPY_BYTES);
    srcNode->fileName = NULL;
    srcNode->clueId = clueId;
	srcNode->user=NULL;
	srcNode->pass=NULL;
	srcNode->subject=NULL;
	srcNode->affixFlag=0;
	srcNode->cc=NULL;
    PushNode(srcNode);
    pktInfo_ = NULL;
}*/

void QQTextExtractor::PushMassage()
{  

	MsgNode* srcNode;
	u_int clueId;
	switch (qqCommand_) {
		case QQ_LOGIN: {
			if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER))>0){
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Login;
				srcNode->to = NULL;
				char* from = new char[12]; // The max length of long number
				sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));
				srcNode->from = from;
				char strmac[20];
				memset(strmac,0,20);
				ParseMac(pktInfo_->srcMac,strmac);
				clueId = GetClueId(protoType_, strmac,pktInfo_->srcIpv4, srcNode->from);
				srcNode->text = NULL;
				srcNode->time = NULL;
				time(&srcNode->timeVal);
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->user=NULL;
				srcNode->pass=NULL;
				srcNode->subject=NULL;
				srcNode->affixFlag=0;
				srcNode->cc=NULL;
				srcNode->path=NULL;
				PushNode(srcNode);
			//            cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
				pktInfo_ = NULL;
			}
			break;
		}
		case QQ_LOGOUT: {
			if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER))>0){
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Logout;
				srcNode->to = NULL;
				char* from = new char[12]; // The max length of long number
				sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));
				srcNode->from = from;
				char strmac[20];
				memset(strmac,0,20);
				ParseMac(pktInfo_->srcMac,strmac);
				clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4);
				srcNode->text = NULL;
				srcNode->time = NULL;
				time(&srcNode->timeVal);
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->user=NULL;
				srcNode->pass=NULL;
				srcNode->subject=NULL;
				srcNode->affixFlag=0;
				srcNode->cc=NULL;
				srcNode->path=NULL;
				PushNode(srcNode);
			//            cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
				pktInfo_ = NULL;
            
            
			}
			break;
		}
		case QQ_SEND:
		case QQ_V09_SEND: {
			if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort)) {
				return ;
			}
			if(ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER))>0){
				char* from = new char[12]; // The max length of long number
				sprintf(from, "%d\0", ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + offside_ + QQ_NUMBER)));

				char strmac[20];
				memset(strmac,0,20);
				ParseMac(pktInfo_->srcMac,strmac);
				clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4, from);
				if (!clueId) {
					delete from;
					return;
				}else{
           

            
					devNum_ = GetDeviceNum();
					u_int devnum = devNum_;
					
					u_short srcport = pktInfo_->srcPort;
					u_short destport = pktInfo_->destPort;
					/*  addr.s_addr = pktInfo_->srcIpv4;
					char* srcip;
					strcpy(srcip,inet_ntoa(addr));
					
					
					
					addr.s_addr = pktInfo_->destIpv4;
					char* destip;
					strcpy(destip,inet_ntoa(addr));*/
                                               
					char srcMac[20];
					memset(srcMac,0,20);
					ParseMac(pktInfo_->srcMac,srcMac);
            
					time_t timeVal;
					time(&timeVal);
					/*tm* timeStruct = localtime(&timeVal);          
					char cptime[100];
					sprintf(cptime,"%d-%d-%d %2d:%2d:%2d",timeStruct->tm_year + 1900,timeStruct->tm_mon + 1,timeStruct->tm_mday,timeStruct->tm_hour,timeStruct->tm_min,(timeStruct->tm_sec == 60) ? 0 : timeStruct->tm_sec);*/
#if 0 //zhangzm QQ
					const char* sql = "insert into QQ (qqid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, content, qqnum, peerqqnum, datafile) values (qqid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12, :v13)";
					const char* sql1 = "update QQ t set capturetime=:v1 where t.clientip=:v2 and t.optype=3 and t.status=1 and t.capturetime=(select max(capturetime) from QQ where clientip=:v2 and optype=3 and status=1)";
					const char* sql2 = "select qqid from QQ t where t.optype=3 and t.status=1 and t.clientip=:v1 and t.capturetime=(select max(capturetime) from QQ m where m.clientip=:v1 and m.optype=3 and m.status=1)";
					oracle::occi::Statement* stmt2_;
					oracle::occi::Statement* stmt3_;
					struct in_addr addr;
					stmt2_= occi_->CreateStmt();                      
					occi_->SetSql(stmt2_, sql2);           
					addr.s_addr = pktInfo_->srcIpv4; 
					occi_->SetString(stmt2_, 1, inet_ntoa(addr));
					u_int ret=occi_->DoSqlRetInt(stmt2_);
					occi_->TerminateStmt(stmt2_);
					stmt3_= occi_->CreateStmt();
					if(ret!=0)
					{                       
						occi_->SetSql(stmt3_, sql1);             
						occi_->SetTime(stmt3_, 1, timeVal);
						addr.s_addr = pktInfo_->srcIpv4; 
						occi_->SetString(stmt3_, 2, inet_ntoa(addr));
						cout << "[QQ]: Update online(send) data for case!Clue ID is "<< clueId << endl;            
						occi_->DoSql(stmt3_);            
					}
					else
					{                        
						occi_->SetSql(stmt3_, sql);            
						occi_->SetInt(stmt3_, 1, devnum);   
						occi_->SetInt(stmt3_, 2, clueId);
						addr.s_addr = pktInfo_->srcIpv4;   
						occi_->SetString(stmt3_, 3, inet_ntoa(addr));  
						occi_->SetInt(stmt3_, 4, srcport);
						addr.s_addr = pktInfo_->destIpv4;
						occi_->SetString(stmt3_, 5, inet_ntoa(addr));
						occi_->SetInt(stmt3_, 6, destport);
						occi_->SetTime(stmt3_, 7, timeVal);
						occi_->SetString(stmt3_, 8, srcMac);
						occi_->SetInt(stmt3_, 9, 3);
						occi_->SetString(stmt3_, 10, ""); 
						if (from != NULL) {
							occi_->SetString(stmt3_, 11, from);       
						} else {
							occi_->SetString(stmt3_, 11, ""); 
						}
						occi_->SetString(stmt3_, 12, "");
						occi_->SetString(stmt3_, 13, "");
						cout << "[QQ]: Data for case!Clue ID is "<< clueId << endl;

//						AddObjectId (clueId,srcMac);

// #ifndef VPDNLZ
// 						AddObjectId (clueId,srcMac);
// 
// #endif
						occi_->DoSql(stmt3_);
					}            
            
					occi_->TerminateStmt(stmt3_);
#endif
				}
			}
			break;
		}
		case QQ_RECV: {
			if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort)) {
				return ;
			}
			char strmac[20];
			memset(strmac,0,20);
			ParseMac(pktInfo_->destMac,strmac);
			clueId = GetClueId(protoType_, strmac, pktInfo_->destIpv4);
			if (!clueId) {
				return;
			}else{
				devNum_ = GetDeviceNum();
				u_int devnum = devNum_;
				
				u_short srcport = pktInfo_->srcPort;
				u_short destport = pktInfo_->destPort;

                                               
				char srcMac[20];
				memset(srcMac,0,20);
				ParseMac(pktInfo_->srcMac,srcMac);
				
				time_t timeVal;
				time(&timeVal);

#if 0  //zhangzm QQ
				const char* sql = "insert into QQ (qqid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, content, qqnum, peerqqnum, datafile) values (qqid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12, :v13)";
				const char* sql1 = "update QQ t set capturetime=:v1 where t.serverip=:v2 and t.optype=3 and t.status=1 and t.capturetime=(select max(capturetime) from QQ where serverip=:v2 and optype=3 and status=1)";
				const char* sql2 = "select qqid from QQ t where t.optype=3 and t.status=1 and t.serverip=:v1 and t.capturetime=(select max(capturetime) from QQ m where m.serverip=:v1 and m.optype=3 and m.status=1)";
				oracle::occi::Statement* stmt2_;
				oracle::occi::Statement* stmt3_;
				struct in_addr addr;
				stmt2_= occi_->CreateStmt();                      
				occi_->SetSql(stmt2_, sql2);           
				addr.s_addr = pktInfo_->destIpv4; 
				occi_->SetString(stmt2_, 1, inet_ntoa(addr));
				u_int ret=occi_->DoSqlRetInt(stmt2_);
				occi_->TerminateStmt(stmt2_);
				stmt3_= occi_->CreateStmt();
				if(ret!=0)
				{                       
					occi_->SetSql(stmt3_, sql1);             
					occi_->SetTime(stmt3_, 1, timeVal);
					addr.s_addr = pktInfo_->destIpv4; 
					occi_->SetString(stmt3_, 2, inet_ntoa(addr));
					cout << "[QQ]: Update online(receive) data for case!Clue ID is "<< clueId << endl;            
					occi_->DoSql(stmt3_);            
				}
				else
				{                        
					occi_->SetSql(stmt3_, sql);            
					occi_->SetInt(stmt3_, 1, devnum);   
					occi_->SetInt(stmt3_, 2, clueId);
					addr.s_addr = pktInfo_->srcIpv4;   
					occi_->SetString(stmt3_, 3, inet_ntoa(addr));  
					occi_->SetInt(stmt3_, 4, srcport);
					addr.s_addr = pktInfo_->destIpv4;
					occi_->SetString(stmt3_, 5, inet_ntoa(addr));
					occi_->SetInt(stmt3_, 6, destport);
					occi_->SetTime(stmt3_, 7, timeVal);
					occi_->SetString(stmt3_, 8, srcMac);
					occi_->SetInt(stmt3_, 9, 3);
					occi_->SetString(stmt3_, 10, ""); 
					
					occi_->SetString(stmt3_, 11, ""); 
					
					occi_->SetString(stmt3_, 12, "");
					occi_->SetString(stmt3_, 13, "");
					cout << "[QQ]: Data for case!Clue ID is "<< clueId << endl;

//					AddObjectId (clueId,srcMac);

// #ifndef VPDNLZ
// 					AddObjectId (clueId,srcMac);
// 
// #endif
					occi_->DoSql(stmt3_);
				}            
            
				occi_->TerminateStmt(stmt3_);
#endif
			}
		}
		break;
       
	}
    
}


void QQTextExtractor::StoreMsg2Text(const string& from, const string& to, const string& text)
{
    stringstream srcFileName;
    srcFileName << DIRECTORY << "/" << pktInfo_->srcIpv4 << ":" << pktInfo_->srcPort;
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
}


void QQTextExtractor::ClearFilterPort()
{
    boost::mutex::scoped_lock lock(setMut_);
    portSet_.clear();
    portSet_.insert(8000);
    portSet_.insert(80);
    portSet_.insert(443);
    portSet_.insert(4000);
}
