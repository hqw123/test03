
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "QQMsgExtractor.h"
#include "Public.h"
#include "util.h"
#include "md5.h"
#include "qqcrypt.h"
#include "clue_c.h"
#include "db_data.h"

// Boost正则表达式库
#include <boost/xpressive/xpressive_dynamic.hpp>

//#include <mysql.h>
//#include <sys/time.h>

#define QQ_HEAD     0x02
#define QQ_END      0x03
// #define QQ_V08_RL   0x62
// #define QQ_RL       0x91
#define QQ_LOGIN    0x2200
#define QQ_LOGOUT   0x0100
#define QQ_SEND     0x1600
#define QQ_V09_SEND 0xcd00
#define QQ_V08_SENDLS 0xe100
#define QQ_V10_SENDLS 0xe200
#define QQ_RECV     0x1700
#define QQ_V10_RECV 0xce00
#define QQ_PWDCHECK 0xdd00
#define QQ_LOGCHECK 0xe500
#define QQ_LOGINFO  0x3000

#define QQ_V12B3_PCHK 0x2608
#define QQ_V12B3_LINF 0x2808
// #define QQ_SERV     0x0001
#define MIN_PKT_LEN 12

#define QQ_COMMAND  3
#define QQ_VERSION  1
#define QQ_NUMBER   7
#define QQ_SEND_BODY 11
#define QQ_RECV_BODY 7

#define QQ_BUDDY    0x6003
#define QQ_BUDDY2   0x5103
#define QQ_BUDDY_TAG  0x0b
//QQ2011
#define QQ_BUDDY3	0x4303
#define TAG 0x6400
//#define QQ_BUDDY_TAG  0x1000
//TM2007beta1
#define TM_BUDDY 0x1803

#define QQ_QUN 0x0101
#define QQ_QUN_TAG 0x01000000

#define QQ_2012TAG 0x592f	//QQ2012正式版 2012-08-30
#define QQ_2012TAG2 0x1930	//QQ2012正式版(QQProtect3.0) 2012-10-30
#define QQ_2012TAG3 0x1330	//QQ2012正式版 2012-10-25
#define QQ_2013TAG 0x3730	//QQ2013Beta1 2012-11-29
#define QQ_2013TAG2 0x0331	//QQ2013Beta2 2013-01-08

#define PORT_BITS          16
QQDecrypt qqDecrypt;

QQMsgExtractor::QQMsgExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/QQ");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protocolType_ = PROTOCOL_QQ;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	memcpy(tableName_, "QQ", 3);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
	ClearFilterPort();
}

QQMsgExtractor::~QQMsgExtractor()
{
	//keyMap.clear();
}

bool QQMsgExtractor::get_qqcommunication()
{
    if(pktInfo_->bodyLen == 0 || strncmp(pktInfo_->body, "POST /cgi-bin/qqshow_user_props_info HTTP", 41))
        return false;

    // 编译正则表达式
    boost::xpressive::cregex reg1 = boost::xpressive::cregex::compile("uin=(.*?)[& ;\r\n]");
    boost::xpressive::cregex reg2 = boost::xpressive::cregex::compile("senduin=(.*?)[& ;\r\n]");
    boost::xpressive::cmatch what1, what2;
    char* sender = NULL, *recver = NULL;

    if(boost::xpressive::regex_search(pktInfo_->body, what1, reg1))
    {
        int len = what1[1].length();
        if(len > 0)
        {
            sender = new char[len + 1];
            memcpy(sender, what1[1].first, len);
            sender[len] = '\0';
        }
    }
    else
    {
        return false;
    }

    if(boost::xpressive::regex_search(pktInfo_->body, what2, reg2))
    {
        int len = what2[1].length();
        if(len > 0)
        {
            recver = new char[len + 1];
            memcpy(recver, what2[1].first, len);
            recver[len] = '\0';
        }
    }
    else
    {
        if(sender)
        {
            delete[] sender;
            sender = NULL;
        }
        
        return false;
    }

    char strmac[20] = {0};
	
	ParseMac(pktInfo_->srcMac, strmac);

	MsgNode *srcNode = new MsgNode;
	memset(srcNode, 0, sizeof(MsgNode));

	srcNode->msgType = Text;
	srcNode->to = recver;
	srcNode->from = sender;

	srcNode->text = NULL;
	srcNode->groupSign = 0;
	srcNode->groupNum = NULL;
	srcNode->time = NULL;
	srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	srcNode->clueId = get_clue_id(strmac, inet_ntoa(addr));
    srcNode->destIpv4 = pktInfo_->destIpv4;
    srcNode->srcIpv4 = pktInfo_->srcIpv4;
    srcNode->srcPort = pktInfo_->srcPort;
    srcNode->destPort = pktInfo_->destPort;
    memcpy(srcNode->srcMac, pktInfo_->srcMac, 6);
    memcpy(srcNode->destMac, pktInfo_->destMac, 6);
	srcNode->fileName = NULL;
	srcNode->protocolType = 501;
	srcNode->user = NULL;
	srcNode->pass = NULL;
	srcNode->subject = NULL;
	srcNode->affixFlag = 0;
	srcNode->cc = NULL;
	srcNode->path = NULL;
	StoreMsg2DB(srcNode);
    
    return true;
}

bool QQMsgExtractor::IsImText(PacketInfo * pktInfo)
{
	bool isQQText = false;
	//assert(pktInfo != NULL);
	if (!isRunning_)
	{
		return false;
	}

	pktInfo_ = pktInfo;
	u_short minLen;

	if (pktInfo_->pktType == TCP)
	{
		minLen = MIN_PKT_LEN + 2;
		offside_ = 2;
        isQQText = get_qqcommunication();
		if (isQQText)
			return isQQText;
	}
	else
	{
		minLen = MIN_PKT_LEN;
		offside_ = 0;
	}

#if 0  //closed by zhangzm
	if (			//pktInfo_->bodyLen > minLen &&
		   *reinterpret_cast < const u_short * >(pktInfo_->body) == QQ_QUN && *reinterpret_cast < const u_int * >(pktInfo_->body + 4) == QQ_QUN_TAG)
	{
		//cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ GroupNums!!!"<<endl;    
		isQQText = GetQunNum();
	}

	if ((pktInfo_->bodyLen > minLen) && *reinterpret_cast < const u_short * >(pktInfo_->body) == TM_BUDDY && *(pktInfo_->body + 56) == QQ_BUDDY_TAG)
	{
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Buddies!!!"<<endl;    
		isQQText = MatchTM();
	}
	else if ((pktInfo_->bodyLen > minLen) && (*reinterpret_cast < const u_short * >(pktInfo_->body) == QQ_BUDDY || *reinterpret_cast < const u_short * >(pktInfo_->body) == QQ_BUDDY2) && *(pktInfo_->body + 56) == QQ_BUDDY_TAG)
	{
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Buddies!!!"<<endl;    
		isQQText = MatchQQ();
	}
	else if ((pktInfo_->bodyLen > 60) && *reinterpret_cast < const u_short * >(pktInfo_->body + offside_) == QQ_BUDDY3)
	{
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ Buddies!!!"<<endl;    
		isQQText = MatchQQ2011();
	}
#endif
	if (pktInfo_->bodyLen > minLen && *(pktInfo_->body + offside_) == QQ_HEAD && *(pktInfo_->body + pktInfo_->bodyLen - 1) == QQ_END)
	{
		qqCommand_ = *reinterpret_cast < const u_short *>(pktInfo_->body + offside_ + QQ_COMMAND);

		//cout << "----------------QQ MSG--------------" << endl;

		switch (qqCommand_)
		{
			//case QQ_V08_RL:
			//case QQ_RL:
/*
		case QQ_SEND:
		case QQ_V09_SEND:
		case QQ_V08_SENDLS:
		case QQ_V10_SENDLS:*/
		case QQ_LOGOUT:
		case QQ_LOGIN:
//                                                                              if (!ntohs(pktInfo_->ip->id)) {
//                                      //cout<<"IP-id : "<<ntohs(pktInfo_->ip->id)<<endl;
//                                                                              isQQText = true;
//                                                                              break;
//                                                                              }

			PushMassage();
			isQQText = true;
			break;
/*
		case QQ_LOGCHECK:
		case QQ_LOGINFO:
		case QQ_RECV:
		case QQ_V10_RECV:
		case QQ_V12B3_LINF:*/
//                                                                              if (ntohs(pktInfo_->ip->id)) {
//                                                                              isQQText = true;
//                                                                              break;
//                                                                              }
/*
			PushMassage();

			isQQText = true;
			break;

		case QQ_PWDCHECK:
		case QQ_V12B3_PCHK:

			PushMassage();

			isQQText = true;
			break;*/
		}


		if (isQQText && pktInfo_)
		{
			pktInfo_ = NULL;
		}
	}

	return isQQText;
}

bool QQMsgExtractor::CheckPort(u_short port)
{
	switch (port)
	{
	case 80:
	case 443:
	case 8000:
	case 4000:
		return true;
	}
	/* if (port >= 6000 && port <= 6005) {
	   return true;
	   } */
	if (port > 4000 && port < 4010)
	{
		return true;
	}
	return false;
}

bool QQMsgExtractor::MatchQQ2011()
{
	bool matched = false;
	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
	u_int clueId = 0;
#ifdef VPDNLZ
	char pppoe[60] = {0};
	clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	//if (!clueId)
	//{
	//	return matched;
	//}
	uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
	map < uint64_t, char *>::iterator it;
	it = myMap.find(key);
	//int usr;
	//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + 58));
	if (it != myMap.end())
	{
		for (int i = 60; i <= pktInfo_->bodyLen - 4; i += 4)
		{
			if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)) == 0)
			{
				matched = false;
			}
			else
			{
				char *buddy = new char[12];
				sprintf(buddy, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)));
				//cout<<"QQ: "<<it->second<<"       "<<"buddy: "<<buddy<<endl;

				//char tmp[256];
#if 0  //zhangzm relation_list
				string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
				sql += " values(";
				sql += "\'";
				sql += it->second;
				sql += "\',";
				u_int type = 501;
				sprintf(tmp, "%lu", type);	//TYPE
				sql += tmp;
				sql += ",\'";
				sql += buddy;
				sql += "\',";
				sql += "now()";	//capturetime record currenttime
				sql += ",";
				u_int isgroup = 0;
				sprintf(tmp, "%lu", isgroup);
				sql.append(tmp);
				sql += ",";
				sprintf(tmp, "%lu", clueId);
				sql.append(tmp);
				sql += ")";
				sqlConn_->Insert(&sql);

//				AddObjectId (clueId,strmac);
#endif
				//cout << "[QQFriendsNum] Data insert into DB!" << endl;
				LOG_DEBUG("[QQFriendsNum] Data insert into DB!\n");
// #ifndef VPDNLZ
// 				AddObjectId(clueId, strmac);
// #endif
				delete buddy;

				matched = true;
			}
		}
		if (*reinterpret_cast < const u_short * >(pktInfo_->body + 58) != TAG)
		{
			//cout<<"last buddy pkt!"<<endl;
			myMap.erase(key);
		}
	}
	else
	{
		if (*(pktInfo_->body + 7) == 0x01)
		{
			if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 60)) == 0)
			{
				matched = false;
			}
			else
			{
				char *user = new char[12];
				sprintf(user, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 60)));
				//cout<<"user: "<<user<<endl;
				myMap.insert(map < uint64_t, char *>::value_type(key, user));
				//for(int i=64;i<=pktInfo_->bodyLen-40;i+=4){
				for (int i = 64; i <= pktInfo_->bodyLen - 4; i += 4)
				{
					if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)) == 0)
					{
						matched = false;
					}
					else
					{
						char *buddy = new char[12];
						sprintf(buddy, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)));
						//cout<<"USER: "<<user<<"       "<<"buddy: "<<buddy<<endl;

						//char tmp[256];
#if 0  //zhangzm relation_list
						string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
						sql += " values(";
						sql += "\'";
						sql += user;
						sql += "\',";
						u_int type = 501;
						sprintf(tmp, "%lu", type);	//TYPE
						sql += tmp;
						sql += ",\'";
						sql += buddy;
						sql += "\',";
						sql += "now()";	//capturetime record currenttime
						sql += ",";
						u_int isgroup = 0;
						sprintf(tmp, "%lu", isgroup);
						sql.append(tmp);
						sql += ",";
						sprintf(tmp, "%lu", clueId);
						sql.append(tmp);
						sql += ")";
						sqlConn_->Insert(&sql);
#endif
						//cout << "[QQFriendsNum] Data insert into DB!" << endl;
						LOG_INFO("[QQFriendsNum] Data insert into DB!\n");
						delete buddy;
						matched = true;
					}
				}

				//delete user;
				if (*reinterpret_cast < const u_short * >(pktInfo_->body + 58) != TAG)
				{
					//cout<<"last buddy pkt!"<<endl;
					delete user;
					myMap.erase(key);
				}
			}
		}
	}
	return matched;
}

bool QQMsgExtractor::MatchQQ()
{
	bool matched = false;

	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
	u_int clueId = 0;
#ifdef VPDNLZ
	char pppoe[60] = {0};
	clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	//if (!clueId)
	//{
	//	return matched;
	//}
	//int usr;
	//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + 58));
	if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 58)) == 0)
	{
		matched = false;
	}
	else
	{
		char *user = new char[12];
		sprintf(user, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 58)));

		//for(int i=64;i<=pktInfo_->bodyLen-40;i+=4){
		for (int i = 64; i <= pktInfo_->bodyLen - 4; i += 4)
		{
			if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)) == 0)
			{
				matched = false;
			}
			else
			{
				char *buddy = new char[12];
				sprintf(buddy, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)));

				//char tmp[256];
#if 0  //zhangzm relation_list
				string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
				sql += " values(";
				sql += "\'";
				sql += user;
				sql += "\',";
				u_int type = 501;
				sprintf(tmp, "%lu", type);	//TYPE
				sql += tmp;
				sql += ",\'";
				sql += buddy;
				sql += "\',";
				sql += "now()";	//capturetime record currenttime
				sql += ",";
				u_int isgroup = 0;
				sprintf(tmp, "%lu", isgroup);
				sql.append(tmp);
				sql += ",";
				sprintf(tmp, "%lu", clueId);
				sql.append(tmp);
				sql += ")";
				sqlConn_->Insert(&sql);
#endif
				//cout << "[QQFriendsNum] Data insert into DB!" << endl;
				LOG_DEBUG("[QQFriendsNum] Data insert into DB!\n");
				delete buddy;
				matched = true;
			}
		}
		delete user;
	}
	return matched;
}

bool QQMsgExtractor::MatchTM()
{
	bool matched = false;

	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
	u_int clueId = 0;
#ifdef VPDNLZ
	char pppoe[60] = {0};
	clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	//if (!clueId)
	//{
	//	return matched;
	//}
	//int usr;
	//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + pktInfo_->bodyLen - 4));
	if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + pktInfo_->bodyLen - 4)) == 0)
	{
		matched = false;
	}
	else
	{
		char *user = new char[12];
		sprintf(user, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + pktInfo_->bodyLen - 4)));


		for (int i = 60; i <= pktInfo_->bodyLen - 8; i += 4)
		{
			if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)) == 0)
			{
				matched = false;
			}
			else
			{
				char *buddy = new char[12];
				sprintf(buddy, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i)));

				//char tmp[256];
#if 0  //zhangzm relation_list
				string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
				sql += " values(";
				sql += "\'";
				sql += user;
				sql += "\',";
				u_int type = 501;
				sprintf(tmp, "%lu", type);	//TYPE
				sql += tmp;
				sql += ",\'";
				sql += buddy;
				sql += "\',";
				sql += "now()";	//capturetime record currenttime
				sql += ",";
				u_int isgroup = 0;
				sprintf(tmp, "%lu", isgroup);
				sql.append(tmp);
				sql += ",";
				sprintf(tmp, "%lu", clueId);
				sql.append(tmp);
				sql += ")";
				sqlConn_->Insert(&sql);
#endif
				//cout << "[QQFriendsNum] Data insert into DB!" << endl;
				LOG_DEBUG("[QQFriendsNum] Data insert into DB!\n");
				delete buddy;
				matched = true;
			}
		}
		delete user;
	}
	return matched;
}

bool QQMsgExtractor::GetQunNum()
{
	bool matched = false;

	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
	u_int clueId = 0;
#ifdef VPDNLZ
	char pppoe[60] = {0};
	clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	//if (!clueId)
	//{
	//	return matched;
	//}
	//int usr;
	//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + 56));
	if (ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 56)) == 0)
	{
		matched = false;
	}
	else
	{

		char *user = new char[12];
		sprintf(user, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 56)));


		for (int i = 61; i < pktInfo_->bodyLen; i += 4)
		{

			u_int sendNum = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + i));
			int qunNum;
			if (sendNum > 4000000000)
			{
				qunNum = sendNum - 3890000000;
			}
			else if (4000000000 > sendNum && sendNum > 2100000000)
			{
				qunNum = sendNum - 2080000000;
			}
			else if (sendNum < 2000000000)
			{
				qunNum = sendNum - 202000000;
			}
			else
			{
				qunNum = sendNum - 1943000000;
			}
			//cout<<"groupNum: "<<qunNum<<endl;
			if (qunNum <= 0)
			{
				matched = false;
			}
			else
			{
				char *groupNum = new char[12];
				sprintf(groupNum, "%d\0", qunNum);
				//char tmp[256];
#if 0  //zhangzm relation_list
				string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
				sql += " values(";
				sql += "\'";
				sql += user;
				sql += "\',";
				u_int type = 501;
				sprintf(tmp, "%lu", type);	//TYPE
				sql += tmp;
				sql += ",\'";
				sql += groupNum;
				sql += "\',";
				sql += "now()";	//capturetime record currenttime
				sql += ",";
				u_int isgroup = 1;
				sprintf(tmp, "%lu", isgroup);
				sql.append(tmp);
				sql += ",";
				sprintf(tmp, "%lu", clueId);
				sql.append(tmp);
				sql += ")";
				sqlConn_->Insert(&sql);

//				AddObjectId (clueId,strmac);
#endif
				//cout << "[QQGroupNum] Data insert into DB!" << endl;
				LOG_DEBUG("[QQGroupNum] Data insert into DB!\n");
// #ifndef VPDNLZ
// 				AddObjectId(clueId, strmac);
// #endif
				delete groupNum;

				matched = true;
			}
		}
		delete user;
	}
	return matched;
}


void QQMsgExtractor::PushMassage()
{
	MsgNode *srcNode = NULL;
	uint64_t keys = pktInfo_->srcIpv4;
	keys = keys << PORT_BITS;
	keys += pktInfo_->srcPort;
	uint64_t keyd = pktInfo_->destIpv4;
	keyd = keyd << PORT_BITS;
	keyd += pktInfo_->destPort;
	map < uint64_t, QQkey >::iterator it;
	it = keyMap.find(keys);
	map < uint64_t, QQkey >::iterator ite;
	ite = keyMap.find(keyd);
	int clueId = 0;
	//u_int usr;
	switch (qqCommand_)
	{
	case QQ_LOGIN:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		{
			char *user = new char[12];
			sprintf(user, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + 7)));

			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);

			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));

			srcNode->msgType = Login;
			srcNode->to = NULL;
			srcNode->from = user;

			srcNode->text = NULL;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
			if (clueId == 0)
				clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);
			pktInfo_ = NULL;
		}
		/*if(!clueId)
		   {
		   delete user;
		   break;
		   }
		   if(it != keyMap.end())
		   {
		   break;
		   } */
		/*const char* sql = "select pwd from QQPWD t where t.qqnum=:v1";
		   oracle::occi::Statement* stmtd;
		   stmtd=occi_->CreateStmt();
		   occi_->SetSql(stmtd, sql);
		   occi_->SetString(stmtd, 1,user);

		   char* retd=(char*)occi_->DoSqlRetString(stmtd);
		   occi_->TerminateStmt(stmtd);
		   cout<<"password is : "<<retd<<endl;
		   if(!retd)
		   {
		   break;
		   } */
		//QQkey qqkey;
		//strcpy(qqkey.qqnum,user);
		//qqkey.qqnum=user;
		//qqkey.pwd=retd;
		//keyMap.insert(map<uint64_t,QQkey>::value_type(keys,qqkey));


		//}
		break;

	case QQ_PWDCHECK:
		//cout<<"PWDCHECK!!!"<<endl;            
		if (it != keyMap.end())
		{
			//cout<<"aaaaaaaaaaaaaaaaaa"<<endl;
			break;
		}
		else if (ite != keyMap.end())
		{
			//s->c
			//cout<<"1111111111111"<<endl;  

			int slen = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *scrypt = new unsigned char[slen + 1];
			memset(scrypt, 0, slen + 1);
			memcpy(scrypt, pktInfo_->body + offside_ + 14, slen);
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(scrypt, slen, ite->second.key2);
			plainLen = qqDecrypt.getPlainlen(scrypt, slen, ite->second.key2);
			if (!plain)
			{
				cout << "Decrypt failed! 3" << endl;
				break;
			}

			unsigned char *Key3_1 = new unsigned char[17];
			memset(Key3_1, 0, 17);
			//memcpy(Key3_1,plain+plainLen-36,16);  
			memcpy(Key3_1, plain + plainLen - 38, 16);
			unsigned char *Key3_2 = new unsigned char[17];
			memset(Key3_2, 0, 17);
			//memcpy(Key3_2,plain+plainLen-18,16);
			memcpy(Key3_2, plain + plainLen - 20, 16);
			ite->second.key3_1 = Key3_1;
			ite->second.key3_2 = Key3_2;
			pktInfo_ = NULL;
		}
		else
		{
			//c->s
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));
			/*
			   char strmac[20];
			   memset(strmac,0,20);
			   ParseMac(pktInfo_->srcMac,strmac);
			   //cout<<"Type: "<<501<<" QQNum: "<<qqNum<<" MAC: "<<strmac<<" SRCPORT: "<<pktInfo_->srcPort<<" DESTPORT: "<<pktInfo_->destPort<<endl;
			   clueId = GetObjectId(strmac);
			   //cout<<"ClueId: "<<clueId<<endl;
			   if(!clueId)
			   {
			   cout<<"get the clueid failed!"<<endl;
			   delete qqNum;
			   break;
			   } */
			//cout << "QQ login!Then get the password..." << endl;
			LOG_INFO("QQ login!Then get the password...\n");
			string s;

			break;
#if 0  //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			
			ResultSet* result = NULL;
			string sql = "select qq_pwd from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				//cout << "get the password successful!" << endl;
				LOG_INFO("get the password successful!\n");
				sqlConn_->closeResult(result);
			}
			else
			{
				//cout << "get the password failed!" << endl;
				LOG_ERROR("get the password failed!\n");
				break;
			}
#endif			
#if 0  //zhangzm
			string sql = "select qq_pwd from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				s = row[0];
				//cout<<"password: "<<s<<endl;
				cout << "get the password successful!" << endl;

			}
			else
			{
				cout << "get the password failed!" << endl;
				mysql_free_result(rets);
				break;
			}
			mysql_free_result(rets);
#endif

			unsigned char *key = new unsigned char[17];
			memset(key, 0, 17);
			memcpy(key, pktInfo_->body + offside_ + 22, 16);
			int len = pktInfo_->bodyLen - offside_ - 22 - 16 - 1;
			unsigned char *crypt = new unsigned char[len + 1];
			memset(crypt, 0, len + 1);
			memcpy(crypt, pktInfo_->body + offside_ + 22 + 16, len);
			//first decrypt
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(crypt, len, key);
			plainLen = qqDecrypt.getPlainlen(crypt, len, key);
			if (!plain)
			{
				//cout << "Decrypt failed! 1" << endl;
				LOG_ERROR("Decrypt failed! 1\n");
				break;
			}

			//second decrypt
			int lenth = 120;
			unsigned char *recrypt = new unsigned char[lenth + 1];
			memset(recrypt, 0, lenth + 1);

			memcpy(recrypt, plain + 82, lenth);
			MD5 md5;
			md5.reset();
			string pwd = s;
			md5.update(pwd);

			u_char *s1 = new u_char[4];
			const string s2 = "00 00 00 00";
			//size_t size_str = hexStringToBytes(s2, s1);
			u_char *sp = new u_char[25];
			memset(sp, 0, 25);
			memcpy(sp, md5.digest(), 16);
			memcpy(sp + 16, s1, 4);
			memcpy(sp + 20, pktInfo_->body + 7 + offside_, 4);
			//cout<<bytesToHexString(s,24)<<endl;

			char *str = new char[25];
			memset(str, 0, 25);
			memcpy(str, sp, 24);

			md5.reset();
			md5.update(str, 24);


			unsigned char *pwdkey = new unsigned char[17];
			memset(pwdkey, 0, 17);
			for (int j = 0; j < 16; j++)
			{
				pwdkey[j] = md5.digest()[j];
			}
			unsigned char *replain;
			int replainLen;
			QQDecrypt qDecrypt;
			replain = qDecrypt.qqdecrypt(recrypt, lenth, pwdkey);
			replainLen = qDecrypt.getPlainlen(recrypt, lenth, pwdkey);
			if (!replain)
			{
				// cout << "Decrypt failed! 2" << endl;
				// LOG_ERROR("Decrypt failed! 2\n");
				break;
			}
			unsigned char *Key1 = new unsigned char[17];
			memset(Key1, 0, 17);
			memcpy(Key1, replain + replainLen - 32, 16);
			unsigned char *Key2 = new unsigned char[17];
			memset(Key2, 0, 17);
			memcpy(Key2, replain + replainLen - 16, 16);

			QQkey qqkey;
			strcpy(qqkey.qqnum, qqNum);
			//qqkey.qqnum = qqNum;
			qqkey.key1 = Key1;
			qqkey.key2 = Key2;
			keyMap.insert(map < uint64_t, QQkey >::value_type(keys, qqkey));
			//cout<<"!!!!!!!!!!!!!!"<<endl;
			pktInfo_ = NULL;
		}

		break;

	case QQ_V12B3_PCHK:
		//cout<<"PWDCHECK!!!"<<endl;            
		if (it != keyMap.end())
		{
			//cout<<"aaaaaaaaaaaaaaaaaa"<<endl;
			break;
		}
		else if (ite != keyMap.end())
		{
			//s->c
			//cout<<"1111111111111"<<endl;  

			int slen = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *scrypt = new unsigned char[slen + 1];
			memset(scrypt, 0, slen + 1);
			memcpy(scrypt, pktInfo_->body + offside_ + 14, slen);
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(scrypt, slen, ite->second.key2);
			plainLen = qqDecrypt.getPlainlen(scrypt, slen, ite->second.key2);
			if (!plain)
			{
				//cout << "Decrypt failed! 3(new)" << endl;
				LOG_ERROR("Decrypt failed! 3(new)\n");
				break;
			}

			unsigned char *Key4 = new unsigned char[32];
			memset(Key4, 0, 32);
//                              if(*reinterpret_cast<const u_short*>(pktInfo_->body + 1 + offside_) == QQ_2013TAG2)
//                              {
//                                      memcpy(Key4,plain+263,16);
//                              }
//                              else{
//                                      memcpy(Key4,plain+235,16);
//                              }
			char cmpstr[3] = "\x00\x02";
			if (!strncmp((const char *) plain + 261, cmpstr, 2))
			{
				memcpy(Key4, plain + 263, 16);
			}
			else if (!strncmp((const char *) plain + 169, cmpstr, 2))
			{
				memcpy(Key4, plain + 171, 16);
			}
			else if (!strncmp((const char *) plain + 233, cmpstr, 2))
			{
				memcpy(Key4, plain + 235, 16);
			}
			else
			{
				//cout << "new data style" << endl;
				LOG_INFO("new data style\n");
				break;
			}
			char *keepkey = new char[32];
			memset(keepkey, 0, 32);
			keepkey = chang((char *) Key4);
			//changed by tz at 20111019
			//ite->second.key4=Key4;
#if 0   //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sqlu = "update qq_pwd set session_key=\'";
			//sqlu+=(char*)Key4;
			sqlu += keepkey;
			sqlu += "\', session_num=\'";


			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sqlu += key;
			sqlu += "\' where qq_num=\'";
			sqlu += ite->second.qqnum;
			sqlu += "\'";
		
			sqlConn_->SetSql(sqlu.c_str());
			sqlConn_->DoSql();
			delete key;
#endif
			//cout << "Update keepkey(new)!" << endl;
			LOG_INFO("Update keepkey(new)!\n");
			delete keepkey;
			pktInfo_ = NULL;
		}
		else
		{
			//c->s
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));
			/*
			   char strmac[20];
			   memset(strmac,0,20);
			   ParseMac(pktInfo_->srcMac,strmac);
			   //cout<<"Type: "<<501<<" QQNum: "<<qqNum<<" MAC: "<<strmac<<" SRCPORT: "<<pktInfo_->srcPort<<" DESTPORT: "<<pktInfo_->destPort<<endl;
			   clueId = GetObjectId(strmac);
			   //cout<<"ClueId: "<<clueId<<endl;
			   if(!clueId)
			   {
			   cout<<"get the clueid failed!"<<endl;
			   delete qqNum;
			   break;
			   } */
			cout << "QQ login!Then get the password..." << endl;
			string s;

			break;
#if 0  //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			ResultSet* result = NULL;
			string sql = "select qq_pwd from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				cout << "get the password successful!" << endl;
				sqlConn_->closeResult(result);
			}
			else
			{
				cout << "get the password failed!" << endl;
				break;
			}	
#endif
#if 0  //zhangzm
			string sql = "select qq_pwd from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				s = row[0];
				//cout<<"password: "<<s<<endl;
				cout << "get the password successful!" << endl;

			}
			else
			{
				cout << "get the password failed!" << endl;
				mysql_free_result(rets);
				break;
			}
			mysql_free_result(rets);
#endif


			unsigned char *key = new unsigned char[17];
			memset(key, 0, 17);
			int len;
			unsigned char *crypt;
//                              if(*reinterpret_cast<const u_short*>(pktInfo_->body + 1 + offside_) == QQ_2012TAG || *reinterpret_cast<const u_short*>(pktInfo_->body + 1 + offside_) == QQ_2012TAG2 || *reinterpret_cast<const u_short*>(pktInfo_->body + 1 + offside_) == QQ_2012TAG3 || *reinterpret_cast<const u_short*>(pktInfo_->body + 1 + offside_) == QQ_2013TAG)
//                              {
			memcpy(key, pktInfo_->body + offside_ + 26, 16);
			len = pktInfo_->bodyLen - offside_ - 26 - 16 - 1;
			crypt = new unsigned char[len + 1];
			memset(crypt, 0, len + 1);
			memcpy(crypt, pktInfo_->body + offside_ + 26 + 16, len);
//                              }
//                              else{
//                                      memcpy(key,pktInfo_->body + offside_ + 22,16);
//                                      len=pktInfo_->bodyLen - offside_ - 22 - 16 -1;
//                                      crypt=new unsigned char[len+1];
//                                      memset(crypt,0,len+1);
//                                      memcpy(crypt,pktInfo_->body + offside_ + 22 + 16,len);
//                              }

			//first decrypt
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(crypt, len, key);
			plainLen = qqDecrypt.getPlainlen(crypt, len, key);
			if (!plain)
			{
				memset(key, 0, 17);
				memcpy(key, pktInfo_->body + offside_ + 22, 16);
				len = pktInfo_->bodyLen - offside_ - 22 - 16 - 1;
				crypt = new unsigned char[len + 1];
				memset(crypt, 0, len + 1);
				memcpy(crypt, pktInfo_->body + offside_ + 22 + 16, len);

				plain = qqDecrypt.qqdecrypt(crypt, len, key);
				plainLen = qqDecrypt.getPlainlen(crypt, len, key);
				if (!plain)
				{
					//cout << "Decrypt failed! 1(new)" << endl;
					LOG_ERROR("Decrypt failed! 1(new)\n");
					break;
				}
			}

			//second decrypt
			int lenth = 120;
			unsigned char *recrypt = new unsigned char[lenth + 1];
			memset(recrypt, 0, lenth + 1);

			memcpy(recrypt, plain + 74, lenth);
			MD5 md5;
			md5.reset();
			string pwd = s;
			md5.update(pwd);

			u_char *s1 = new u_char[4];
			const string s2 = "00 00 00 00";
			//size_t size_str = hexStringToBytes(s2, s1);
			u_char *sp = new u_char[25];
			memset(sp, 0, 25);
			memcpy(sp, md5.digest(), 16);
			memcpy(sp + 16, s1, 4);
			memcpy(sp + 20, pktInfo_->body + 7 + offside_, 4);
			//cout<<bytesToHexString(s,24)<<endl;

			char *str = new char[25];
			memset(str, 0, 25);
			memcpy(str, sp, 24);

			md5.reset();
			md5.update(str, 24);


			unsigned char *pwdkey = new unsigned char[17];
			memset(pwdkey, 0, 17);
			for (int j = 0; j < 16; j++)
			{
				pwdkey[j] = md5.digest()[j];
			}
			unsigned char *replain;
			int replainLen;
			QQDecrypt qDecrypt;
			replain = qDecrypt.qqdecrypt(recrypt, lenth, pwdkey);
			replainLen = qDecrypt.getPlainlen(recrypt, lenth, pwdkey);
			if (!replain)
			{
				cout << "Decrypt failed! 2(new)" << endl;
				break;
			}
//                              unsigned char* Key1=new unsigned char[17];
//                              memset(Key1,0,17);
//                              memcpy(Key1,replain+replainLen-32,16);  
			unsigned char *Key2 = new unsigned char[17];
			memset(Key2, 0, 17);
			memcpy(Key2, replain + replainLen - 16, 16);

			QQkey qqkey;
			strcpy(qqkey.qqnum, qqNum);
			//qqkey.qqnum = qqNum;
//                              qqkey.key1 = Key1;
			qqkey.key2 = Key2;
			keyMap.insert(map < uint64_t, QQkey >::value_type(keys, qqkey));
			//cout<<"!!!!!!!!!!!!!!"<<endl;
			pktInfo_ = NULL;
		}

		break;
	case QQ_LOGCHECK:
		//cout<<"LOGINCHECK!!!"<<endl;
		if (ite != keyMap.end())
		{
			//s->c          
			//cout<<"22222222222222"<<endl;

			int slen = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *scrypt = new unsigned char[slen + 1];
			memset(scrypt, 0, slen + 1);
			memcpy(scrypt, pktInfo_->body + offside_ + 14, slen);
			unsigned char *plain;
			plain = qqDecrypt.qqdecrypt(scrypt, slen, ite->second.key3_2);

			if (!plain)
			{
				//cout << "Decrypt failed! 4" << endl;
				LOG_ERROR("Decrypt failed! 4\n");
				break;
			}

			//unsigned char* Key4=new unsigned char[17];
			//memset(Key4,0,17);
			unsigned char *Key4 = new unsigned char[32];
			memset(Key4, 0, 32);
			memcpy(Key4, plain + 4, 16);
			char *keepkey = new char[32];
			memset(keepkey, 0, 32);
			keepkey = chang((char *) Key4);
			//changed by tz at 20111019
			//ite->second.key4=Key4;
#if 0  //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sqlu = "update qq_pwd set session_key=\'";
			//sqlu+=(char*)Key4;
			sqlu += keepkey;
			sqlu += "\', session_num=\'";

			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sqlu += key;
			sqlu += "\' where qq_num=\'";
			sqlu += ite->second.qqnum;
			sqlu += "\'";
			//cout<<"SQLU : "<<sqlu<<endl;
			//sqlConn_->Insert(&sqlu);   //MYSQL

			sqlConn_->SetSql(sqlu.c_str());
			sqlConn_->DoSql();
			delete key;
#endif			
			cout << "Update keepkey!" << endl;
			delete keepkey;
			pktInfo_ = NULL;

		}
		break;

	case QQ_LOGINFO:
		//cout<<"LOGININFO"<<endl;
		{

			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
//                      string sql = "select qqnum from qqpwd where keynum=\'";
//                      sql+=key;
//                      sql+="\'";
//                      MYSQL_RES * rets;
//                      rets = sqlConn_->Select(&sql);
//                      string s;
//                      MYSQL_ROW row;
//                      if((row = mysql_fetch_row(rets))){
//                              s=row[0];
//                              mysql_free_result(rets);

			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			string s1;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql1 = "select session_key from qq_pwd where session_num=\'";

			sql1 += key;
			sql1 += "\' and qq_num=\'";
			sql1 += qqNum;
			sql1 += "\'";

			sqlConn_->SetSql(sql1.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s1 = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm			
			string sql1 = "select session_key from qq_pwd where session_num=\'";

			sql1 += key;
			sql1 += "\' and qq_num=\'";
			sql1 += qqNum;
			sql1 += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets1;
			rets1 = sqlConn_->Select(&sql1);
			string s1;
			MYSQL_ROW row1;
			if ((row1 = mysql_fetch_row(rets1)))
			{
				s1 = row1[0];
				mysql_free_result(rets1);
			}
			else
			{
				mysql_free_result(rets1);
				break;
			}
#endif

			int slen = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *scrypt = new unsigned char[slen + 1];
			memset(scrypt, 0, slen + 1);
			memcpy(scrypt, pktInfo_->body + offside_ + 14, slen);
			//plain=qqDecrypt.qqdecrypt(scrypt, slen, ite->second.key4);
			unsigned char *plain;
			plain = qqDecrypt.qqdecrypt(scrypt, slen, (u_char *) s1.c_str());
			if (!plain)
			{
				//cout << "Decrypt failed! 5" << endl;
				LOG_ERROR("Decrypt failed! 5\n");
				break;
			}

			unsigned char *msgKey = new unsigned char[17];
			memset(msgKey, 0, 17);
			memcpy(msgKey, plain + 1, 16);
#if 0  //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sqlu = "update qq_pwd set msg_key=\'";
			sqlu += (char *) msgKey;

			sqlu += "\' where qq_num=\'";
			sqlu += qqNum;
			sqlu += "\'";
			//cout<<"SQLU : "<<sqlu<<endl;
			//sqlConn_->Insert(&sqlu);   //MYSQL

			sqlConn_->SetSql(sqlu.c_str());
			sqlConn_->DoSql();
#endif
			//cout << "[QQ]: Update msgkey of QQ!" << endl;
			LOG_INFO("[QQ]: Update msgkey of QQ!\n");
			keyMap.erase(keyd);
			delete qqNum;
			pktInfo_ = NULL;
			delete key;

		}
		break;
	case QQ_V12B3_LINF:
		{
			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			string s1;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql1 = "select session_key from qq_pwd where session_num=\'";

			sql1 += key;
			sql1 += "\' and qq_num=\'";
			sql1 += qqNum;
			sql1 += "\'";

			sqlConn_->SetSql(sql1.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s1 = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm			
			string sql1 = "select session_key from qq_pwd where session_num=\'";

			sql1 += key;
			sql1 += "\' and qq_num=\'";
			sql1 += qqNum;
			sql1 += "\'";
			MYSQL_RES *rets1;
			rets1 = sqlConn_->Select(&sql1);
			string s1;
			MYSQL_ROW row1;
			if ((row1 = mysql_fetch_row(rets1)))
			{
				s1 = row1[0];
				mysql_free_result(rets1);
			}
			else
			{
				mysql_free_result(rets1);
				break;
			}
#endif

			int slen = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *scrypt = new unsigned char[slen + 1];
			memset(scrypt, 0, slen + 1);
			memcpy(scrypt, pktInfo_->body + offside_ + 14, slen);
			//plain=qqDecrypt.qqdecrypt(scrypt, slen, ite->second.key4);
			unsigned char *plain;
			plain = qqDecrypt.qqdecrypt(scrypt, slen, (u_char *) s1.c_str());
			if (!plain)
			{
				cout << "Decrypt failed! 4(new)" << endl;
				break;
			}

			unsigned char *msgKey = new unsigned char[17];
			memset(msgKey, 0, 17);
			memcpy(msgKey, plain + 25, 16);

			//ite->second.msgkey=msgKey;
			//string sqls = "select msgkey from qqpwd where qqnum=\'";

			//sqls+=ite->second.qqnum;
			//sqls+="\'";
			//cout<<"SQLS : "<<sqls<<endl;
			//MYSQL_RES * rets;
			//rets = sqlConn_->Select(&sqls);
			//MYSQL_ROW row;
			//if((row = mysql_fetch_row(rets))){
#if 0  //zhangzm
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sqlu = "update qq_pwd set msg_key=\'";
			sqlu += (char *) msgKey;

			sqlu += "\' where qq_num=\'";
			sqlu += qqNum;
			sqlu += "\'";
			//cout<<"SQLU : "<<sqlu<<endl;
			//sqlConn_->Insert(&sqlu);   //MYSQL

			sqlConn_->SetSql(sqlu.c_str());
			sqlConn_->DoSql();
#endif
			cout << "[QQ]: Update msgkey of QQ(new)!" << endl;
			keyMap.erase(keyd);
			delete qqNum;
			//}
			//mysql_free_result(rets);
			//cout<<"key: "<<ite->second.msgkey<<endl;
			pktInfo_ = NULL;

//                      }else{
//                              mysql_free_result(rets);
//                              //break;
//                      }
			delete key;

		}
		break;

	case QQ_SEND:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + offside_ + QQ_NUMBER));
		//if(usr<=0){break;}
		//if(it != keyMap.end()){
		{
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));
			//cout<<qqNum<<endl;

			int len = pktInfo_->bodyLen - offside_ - 11 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 11, len);

			string s;
#if 0 //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);
				break;
			}
#endif
			unsigned char *plain;
			int plainLen;
//                      QQDecrypt qqDecrypt;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			//plain=qqDecrypt.qqdecrypt(msgCrypt, len, it->second.msgkey);
			//plainLen=qqDecrypt.getPlainlen(msgCrypt, len, it->second.msgkey);
			if (!plain)
			{
				break;
			}
			if (plainLen <= 53)
			{
				break;
			}
			int textLen = ntohs(*(u_short *) (plain + 51));
			unsigned char *text = new unsigned char[textLen + 1];
			memset(text, 0, textLen + 1);
			memcpy(text, plain + 53, textLen);
			/*unsigned char* text =new unsigned char[plainLen-53-14+1];
			   memset(text,0,plainLen-53-14+1);
			   memcpy(text,plain+53,plainLen-53-14); */

			//cout<<"The message is : "<<text<<endl;

			char *from = new char[12];
			sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
			//cout<<"From: "<<from<<endl;

			char *to = new char[12];
			sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
			//cout<<"To: "<<to<<endl;

			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);

			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));

			srcNode->msgType = Text;
			srcNode->to = to;

			srcNode->from = from;

			srcNode->text = (char *) text;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);

		}
		break;

	case QQ_V09_SEND:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + offside_ + QQ_NUMBER));
		//if(usr<=0){cout<<"QQNumber: "<<usr<<endl;break;}
		//if(it != keyMap.end()){
		{
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			string s;
/*			ResultSet* result = NULL;
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
			{
				break;
			}*/

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);
				//                                      
				break;
			}
#endif

			int len = pktInfo_->bodyLen - offside_ - 22 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 22, len);
			//cout<<it->second.msgkey<<endl;
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			//plain=qqDecrypt.qqdecrypt(msgCrypt, len, it->second.msgkey);
			//plainLen=qqDecrypt.getPlainlen(msgCrypt, len, it->second.msgkey);
			if (!plain)
			{
				break;
			}

			if (plainLen <= 105)
			{
				break;
			}
			if (plain[0] == plain[22])
			{
				//char* str=new char[3];
				//memset(str,0,3);
				//memcpy(str,plain+103,2);
				//cout<<plainLen<<endl;
				//str[0]+=48;
				//str[1]+=48;
				//str[2]='\0';
				//cout<<":"<<plain+102<<endl;
				//cout<<":"<<plain+103<<endl;
				//int textLen=str_to_num(str,2);
				int fontLen = ntohs(*(u_short *) (plain + 89));
				int textLen = ntohs(*(u_short *) (plain + 91 + fontLen + 6));
				//cout<<"Len: "<<textLen<<endl;
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 91 + fontLen + 8, textLen);
				/*int textLen=ntohs(*(u_short*)(plain+103));
				   //cout<<"Len: "<<textLen<<endl;
				   unsigned char* text =new unsigned char[textLen+1];
				   memset(text,0,textLen+1);
				   memcpy(text,plain+105,textLen); */
				/*unsigned char* text =new unsigned char[plainLen-105+1];
				   memset(text,0,plainLen-105+1);
				   memcpy(text,plain+105,plainLen-105); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->srcMac, strmac);

				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->srcIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 0;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
				break;
			}
			//cout<<plainLen<<endl;
			/*unsigned char* text =new unsigned char[plainLen-110+1];
			   memset(text,0,plainLen-110+1);
			   memcpy(text,plain+110,plainLen-110); */
			//char* str=new char[3];
			//memset(str,0,3);
			//memcpy(str,plain+108,2);
			//cout<<plainLen<<endl;
			//cout<<":"<<plain+107<<endl;
			//cout<<":"<<plain+108<<endl;
			/*str[0]+=48;
			   str[1]+=48;
			   str[2]='\0';
			   int textLen=str_to_num(str,2); */
			//changed by tz at 20110923 for the font
			int fontLen = ntohs(*(u_short *) (plain + 94));
			int textLen = ntohs(*(u_short *) (plain + 96 + fontLen + 6));
			//cout<<"Len: "<<textLen<<endl;
			unsigned char *text = new unsigned char[textLen + 1];
			memset(text, 0, textLen + 1);
			memcpy(text, plain + 96 + fontLen + 8, textLen);
			/*int textLen=ntohs(*(u_short*)(plain+108));
			   //cout<<"Len: "<<textLen<<endl;
			   unsigned char* text =new unsigned char[textLen+1];
			   memset(text,0,textLen+1);
			   memcpy(text,plain+110,textLen); */
			/*unsigned char* text =new unsigned char[plainLen-110+1];
			   memset(text,0,plainLen-110+1);
			   memcpy(text,plain+110,plainLen-110); */
			//cout<<"The message is : "<<text<<endl;

			char *from = new char[12];
			sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
			//cout<<"From: "<<from<<endl;

			char *to = new char[12];
			sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
			//cout<<"To: "<<to<<endl;       
			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);

			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));
			srcNode->msgType = Text;
			srcNode->to = to;
			srcNode->from = from;
			srcNode->text = (char *) text;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);
		}
		break;

	case QQ_V08_SENDLS:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + offside_ + QQ_NUMBER));
		//if(usr<=0){break;}
		//if(it != keyMap.end())
		{
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			int len = pktInfo_->bodyLen - offside_ - 11 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 11, len);

			string s;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);

				break;
			}
#endif
			unsigned char *plain;
			int plainLen;
//                              QQDecrypt qqDecrypt;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			if (!plain)
			{
				break;
			}
			if (plainLen <= 150)
			{
				break;
			}
			int textLen = ntohs(*(u_short *) (plain + 148));
			unsigned char *text = new unsigned char[textLen + 1];
			memset(text, 0, textLen + 1);
			memcpy(text, plain + 150, textLen);
			/*unsigned char* text =new unsigned char[plainLen-150-14+1];
			   memset(text,0,plainLen-150-14+1);
			   memcpy(text,plain+150,plainLen-150-14); */
			//cout<<"The message is : "<<text<<endl;

			char *from = new char[12];
			sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
			//cout<<"From: "<<from<<endl;

			char *to = new char[12];
			sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
			//cout<<"To: "<<to<<endl;
			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);
			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));
			srcNode->msgType = Text;
			srcNode->to = to;
			srcNode->from = from;
			srcNode->text = (char *) text;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);

		}
		break;

	case QQ_V10_SENDLS:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + offside_ + QQ_NUMBER));
		//if(usr<=0){break;}
		//if(it != keyMap.end())
		{
			char *qqNum = new char[12];
			sprintf(qqNum, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			string s;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where qq_num=\'";
			sql += qqNum;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);

				break;
			}
#endif

			int len = pktInfo_->bodyLen - offside_ - 22 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 22, len);
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			if (!plain)
			{
				break;
			}
			if (plainLen <= 190)
			{
				break;
			}
			//cout<<plainLen<<endl;
			int fontLen = ntohs(*(u_short *) (plain + 174));
			int textLen = ntohs(*(u_short *) (plain + 176 + fontLen + 6));
			unsigned char *text = new unsigned char[textLen + 1];
			memset(text, 0, textLen + 1);
			memcpy(text, plain + 176 + fontLen + 8, textLen);
			/*int textLen=ntohs(*(u_short*)(plain+188));
			   unsigned char* text =new unsigned char[textLen+1];
			   memset(text,0,textLen+1);
			   memcpy(text,plain+190,textLen); */
			//cout<<"The message is : "<<text<<endl;

			char *from = new char[12];
			sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
			//cout<<"From: "<<from<<endl;

			char *to = new char[12];
			sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
			//cout<<"To: "<<to<<endl;       
			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);
			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));
			srcNode->msgType = Text;
			srcNode->to = to;
			srcNode->from = from;
			srcNode->text = (char *) text;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);
		}
		break;

	case QQ_RECV:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}

		//if(ite != keyMap.end())
		{
			int len = pktInfo_->bodyLen - offside_ - 7 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 7, len);

			string s;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql = "select msg_key from qq_pwd where session_num=\'";
			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sql += key;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			delete key;
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where session_num=\'";
			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sql += key;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			delete key;
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);

				break;
			}
#endif
			unsigned char *plain;
			int plainLen;
//                              QQDecrypt qqDecrypt;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			if (!plain)	//2010
			{
				len = pktInfo_->bodyLen - offside_ - 14 - 1;
				memcpy(msgCrypt, pktInfo_->body + offside_ + 14, len);
				plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
				plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
				if (!plain)
				{
					break;
				}
				

				u_int sendNum = ntohl(*reinterpret_cast < const u_int * >(plain));
				//cout<<"sendNum: "<<sendNum<<endl;
				int qunNum;
				if (sendNum > 4000000000)
				{
					qunNum = sendNum - 3890000000;
				}
				else if (4000000000 > sendNum && sendNum > 2100000000)
				{
					qunNum = sendNum - 2080000000;
				}
				else if (sendNum < 2000000000)
				{
					qunNum = sendNum - 202000000;
				}
				else
				{
					qunNum = sendNum - 1943000000;
				}
				if (qunNum < 0)
				{
					break;
				}

				u_int cmpNum = ntohl(*reinterpret_cast < const u_int * >(plain+42));
				if(cmpNum == (u_int)qunNum){
					int tlen = *(plain + 100);
				//cout<<"len: "<<tlen<<endl;    
				if (plainLen <= 109 + tlen)
				{
					break;
				}
				//cout<<plainLen<<endl;
				int textLen = ntohs(*(u_short *) (plain + 107 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 109 + tlen, textLen);
				//cout<<"The message is : "<<text<<endl;

				if (plain[4] == plain[47])
				{
					char *from = new char[12];
					sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"From: "<<from<<endl;

					char *to = new char[18];
					sprintf(to, "group-%d\0", qunNum);
					//cout<<"To: "<<to<<endl;       

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					memcpy(srcNode, pktInfo_, COPY_BYTES);
					srcNode->srcIpv4 = pktInfo_->destIpv4;
					srcNode->srcPort = pktInfo_->destPort;
					srcNode->destIpv4 = pktInfo_->srcIpv4;
					srcNode->destPort = pktInfo_->srcPort;
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
				else
				{
					char *sender = new char[12];
					sprintf(sender, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 47)));
					char *from = new char[30];
					sprintf(from, "group-%d-%s\0", qunNum, sender);
					//cout<<"From: "<<from<<endl;

					char *to = new char[12];
					sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"To: "<<to<<endl;

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
				break;
				}
	
				int tlen = *(plain + 82);
				//cout<<"len: "<<tlen<<endl;    
				if (plainLen <= 91 + tlen)
				{
					break;
				}
				//cout<<plainLen<<endl;
				int textLen = ntohs(*(u_short *) (plain + 89 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 91 + tlen, textLen);
				//cout<<"The message is : "<<text<<endl;

				if (plain[4] == plain[29])
				{
					char *from = new char[12];
					sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"From: "<<from<<endl;

					char *to = new char[18];
					sprintf(to, "group-%d\0", qunNum);
					//cout<<"To: "<<to<<endl;       

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					memcpy(srcNode, pktInfo_, COPY_BYTES);
					srcNode->srcIpv4 = pktInfo_->destIpv4;
					srcNode->srcPort = pktInfo_->destPort;
					srcNode->destIpv4 = pktInfo_->srcIpv4;
					srcNode->destPort = pktInfo_->srcPort;
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
				else
				{
					char *sender = new char[12];
					sprintf(sender, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 29)));
					char *from = new char[30];
					sprintf(from, "group-%d-%s\0", qunNum, sender);
					//cout<<"From: "<<from<<endl;

					char *to = new char[12];
					sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"To: "<<to<<endl;

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
				break;
			}

			if (plainLen <= 73)
			{
				break;
			}
			if (plain[0] == plain[22])
			{	//2008
				int textLen = ntohs(*(u_short *) (plain + 71));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 73, textLen);
				/*unsigned char* text =new unsigned char[plainLen-73-14+1];
				   memset(text,0,plainLen-73-14+1);
				   memcpy(text,plain+73,plainLen-73-14); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}
			else if (plain[0] == plain[140])
			{	//2008ls
				if (plainLen <= 183)
				{
					break;
				}
				int textLen = ntohs(*(u_short *) (plain + 181));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 183, textLen);
				/*unsigned char* text =new unsigned char[plainLen-183-21+1];
				   memset(text,0,plainLen-183-21+1);
				   memcpy(text,plain+183,plainLen-183-21); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}
			else
			{	//2009
				int tlen = *(plain + 82);
				//cout<<"len: "<<tlen<<endl;
				if (plainLen <= 91 + tlen)
				{
					break;
				}
				int textLen = ntohs(*(u_short *) (plain + 89 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 91 + tlen, textLen);
				//cout<<"The message is : "<<text<<endl;

				u_int sendNum = ntohl(*reinterpret_cast < const u_int * >(plain));
				//cout<<"sendNum: "<<sendNum<<endl;     

				int qunNum;
				if (sendNum > 2100000000)
				{
					qunNum = sendNum - 2080000000;
				}
				else if (sendNum < 2000000000)
				{
					qunNum = sendNum - 202000000;
				}
				else
				{
					qunNum = sendNum - 1943000000;
				}
				if (qunNum < 0)
				{
					break;
				}
				if (plain[4] == plain[29])
				{
					char *from = new char[12];
					sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"From: "<<from<<endl;

					char *to = new char[18];
					sprintf(to, "group-%d\0", qunNum);
					//cout<<"To: "<<to<<endl;       

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					srcNode->srcIpv4 = pktInfo_->destIpv4;
					srcNode->srcPort = pktInfo_->destPort;
					srcNode->destIpv4 = pktInfo_->srcIpv4;
					srcNode->destPort = pktInfo_->srcPort;
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif

					//memcpy(srcNode, pktInfo_, COPY_BYTES);
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
				else
				{
					char *sender = new char[12];
					sprintf(sender, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 29)));
					char *from = new char[30];
					sprintf(from, "group-%d-%s\0", qunNum, sender);
					//cout<<"From: "<<from<<endl;

					char *to = new char[12];
					sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
					//cout<<"To: "<<to<<endl;

					char strmac[20];
					memset(strmac, 0, 20);
					ParseMac(pktInfo_->destMac, strmac);
					srcNode = new MsgNode;
					memset(srcNode, 0, sizeof(MsgNode));
					srcNode->msgType = Text;
					srcNode->to = to;
					srcNode->from = from;
					srcNode->text = (char *) text;
					srcNode->groupSign = 1;
					char *groupnum = new char[12];
					sprintf(groupnum, "%d\0", qunNum);
					srcNode->groupNum = groupnum;
					srcNode->time = NULL;
					//time(&srcNode->timeVal);
					srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
					// Copy basic data to message node
					memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
					clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
					if (clueId == 0)
						clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
					//clueId = GetObjectId(strmac);
					struct in_addr addr;
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
					srcNode->fileName = NULL;
					srcNode->clueId = clueId;
					srcNode->protocolType = 501;
					srcNode->user = NULL;
					srcNode->pass = NULL;
					srcNode->subject = NULL;
					srcNode->affixFlag = 9000;
					srcNode->cc = NULL;
					srcNode->path = NULL;
					StoreMsg2DB(srcNode);
				}
			}

		}
		break;

	case QQ_V10_RECV:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//if(ite != keyMap.end())
		{
			string s;
#if 0  //zhangzm
			ResultSet* result = NULL;
			sqlConn_ = m_db_conn->get_sqlConn_special();
			string sql = "select msg_key from qq_pwd where session_num=\'";
			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sql += key;
			sql += "\'";

			sqlConn_->SetSql(sql.c_str());
			delete key;
			result = sqlConn_->DoSqlResult();
			if (result->next())
			{
				s = result->getString(1);
				sqlConn_->closeResult(result);
			}
			else
#endif
			{
				break;
			}

#if 0  //zhangzm
			string sql = "select msg_key from qq_pwd where session_num=\'";
			char *key = new char[20];
			sprintf(key, "%d\0", (int) keyd);
			sql += key;
			sql += "\'";
			//cout<<"SQL : "<<sql<<endl;
			MYSQL_RES *rets;
			rets = sqlConn_->Select(&sql);
			delete key;
			string s;
			MYSQL_ROW row;
			if ((row = mysql_fetch_row(rets)))
			{
				if (row[0] == NULL)
				{
					s = "";
				}
				else
				{
					s = row[0];
				}
				mysql_free_result(rets);
			}
			else
			{
				//cout<<"get the msgkey failed!"<<endl;
				mysql_free_result(rets);
				break;
			}
#endif

			int len = pktInfo_->bodyLen - offside_ - 14 - 1;
			unsigned char *msgCrypt = new unsigned char[len + 1];
			memset(msgCrypt, 0, len + 1);
			memcpy(msgCrypt, pktInfo_->body + offside_ + 14, len);
			unsigned char *plain;
			int plainLen;
			plain = qqDecrypt.qqdecrypt(msgCrypt, len, (u_char *) s.c_str());
			plainLen = qqDecrypt.getPlainlen(msgCrypt, len, (u_char *) s.c_str());
			if (!plain)
			{
				//cout<<"Decrypt msg failed"<<endl;
				break;
			}
			if (plainLen <= 130)
			{
				break;
			}
			//cout<<plainLen<<endl;
			if (plain[0] == plain[47])
			{
				int tlen = *(plain + 115);
				//cout<<tlen<<endl;
				/*unsigned char* text =new unsigned char[plainLen-130+1];
				   memset(text,0,plainLen-130+1);
				   memcpy(text,plain+130,plainLen-130); */
				int textLen = ntohs(*(u_short *) (plain + 122 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 124 + tlen, textLen);
				/*int textLen=ntohl(*reinterpret_cast<const u_short*>(plain+128));
				   unsigned char* text =new unsigned char[textLen+1];
				   memset(text,0,textLen+1);
				   memcpy(text,plain+130,textLen); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;       
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}
			else if (plain[0] == plain[53])
			{
				int tlen = *(plain + 121);
				//cout<<tlen<<endl;
				/*unsigned char* text =new unsigned char[plainLen-130+1];
				   memset(text,0,plainLen-130+1);
				   memcpy(text,plain+130,plainLen-130); */
				int textLen = ntohs(*(u_short *) (plain + 128 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 130 + tlen, textLen);
				/*int textLen=ntohl(*reinterpret_cast<const u_short*>(plain+128));
				   unsigned char* text =new unsigned char[textLen+1];
				   memset(text,0,textLen+1);
				   memcpy(text,plain+130,textLen); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;       
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}
			else if (plain[0] == plain[61])//QQ2013Beta3
			{
				int tlen = *(plain + 129);
				//cout<<tlen<<endl;
				/*unsigned char* text =new unsigned char[plainLen-130+1];
				   memset(text,0,plainLen-130+1);
				   memcpy(text,plain+130,plainLen-130); */
				int textLen = ntohs(*(u_short *) (plain + 136 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 138 + tlen, textLen);
				/*int textLen=ntohl(*reinterpret_cast<const u_short*>(plain+128));
				   unsigned char* text =new unsigned char[textLen+1];
				   memset(text,0,textLen+1);
				   memcpy(text,plain+130,textLen); */
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;       
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				// Copy basic data to message node
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}
			else
			{
				int tlen = *(plain + 220);
				//cout<<tlen<<endl;
				if (plainLen <= 229 + tlen)
				{
					break;
				}
				/*int textLen=ntohl(*reinterpret_cast<const u_short*>(plain+238));
				   cout<<"Len: "<<textLen<<endl;
				   unsigned char* text =new unsigned char[textLen+1];
				   memset(text,0,textLen+1);
				   memcpy(text,plain+240,textLen); */

				/*unsigned char* text =new unsigned char[plainLen-240+1];
				   memset(text,0,plainLen-240+1);
				   memcpy(text,plain+240,plainLen-240); */
				int textLen = ntohs(*(u_short *) (plain + 227 + tlen));
				unsigned char *text = new unsigned char[textLen + 1];
				memset(text, 0, textLen + 1);
				memcpy(text, plain + 229 + tlen, textLen);
				//cout<<"The message is : "<<text<<endl;

				char *from = new char[12];
				sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain)));
				//cout<<"From: "<<from<<endl;

				char *to = new char[12];
				sprintf(to, "%u\0", ntohl(*reinterpret_cast < const u_int * >(plain + 4)));
				//cout<<"To: "<<to<<endl;       
				char strmac[20];
				memset(strmac, 0, 20);
				ParseMac(pktInfo_->destMac, strmac);
				srcNode = new MsgNode;
				memset(srcNode, 0, sizeof(MsgNode));
				srcNode->msgType = Text;
				srcNode->to = to;
				srcNode->from = from;
				srcNode->text = (char *) text;
				srcNode->groupSign = 0;
				srcNode->groupNum = NULL;
				srcNode->time = NULL;
				//time(&srcNode->timeVal);
				srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
				// Copy basic data to message node
				memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
				clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
				if (clueId == 0)
					clueId = GetObjectId2(srcNode->destIpv4, srcNode->pppoe);
#else
				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
				srcNode->fileName = NULL;
				srcNode->clueId = clueId;
				srcNode->protocolType = 501;
				srcNode->user = NULL;
				srcNode->pass = NULL;
				srcNode->subject = NULL;
				srcNode->affixFlag = 9000;
				srcNode->cc = NULL;
				srcNode->path = NULL;
				StoreMsg2DB(srcNode);
			}

		}
		break;

	case QQ_LOGOUT:
		if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
		{
			break;
		}
		//usr=ntohl(*reinterpret_cast<const int*>(pktInfo_->body + offside_ + QQ_NUMBER));
		//if(usr<=0){break;}
		if (pktInfo_->bodyLen == (44 + offside_) || pktInfo_->bodyLen == (63 + offside_))
		{

			srcNode = new MsgNode;
			memset(srcNode, 0, sizeof(MsgNode));
			srcNode->msgType = Logout;
			srcNode->to = NULL;
			char *from = new char[12];	// The max length of long number
			sprintf(from, "%u\0", ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + offside_ + QQ_NUMBER)));

			srcNode->from = from;
			char strmac[20];
			memset(strmac, 0, 20);
			ParseMac(pktInfo_->srcMac, strmac);
			srcNode->text = NULL;
			srcNode->groupSign = 0;
			srcNode->groupNum = NULL;
			srcNode->time = NULL;
			//time(&srcNode->timeVal);
			srcNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
			// Copy basic data to message node
			memcpy(srcNode, pktInfo_, COPY_BYTES);
#ifdef VPDNLZ
			clueId = GetObjectId2(srcNode->srcIpv4, srcNode->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			srcNode->fileName = NULL;
			srcNode->clueId = clueId;
			srcNode->protocolType = 501;
			srcNode->user = NULL;
			srcNode->pass = NULL;
			srcNode->subject = NULL;
			srcNode->affixFlag = 0;
			srcNode->cc = NULL;
			srcNode->path = NULL;
			StoreMsg2DB(srcNode);
//                              if(it != keyMap.end()){
//                                      cout<<"44444444444"<<endl;
//                                      keyMap.erase(keys);
//                              }
			pktInfo_ = NULL;

		}
		break;

	}
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void QQMsgExtractor::StoreMsg2DB(MsgNode * msgNode)
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

/*int QQMsgExtractor::str_to_num(char* size,int len)
{
	cout<<": "<<size[0]<<endl;
	cout<<": "<<size[1]<<endl;
	int res=0,i=len-1;
	while(i>=0)
{
	int num;
	if(size[i]=='\0'){num=0;}
	else 
	if(!(size[i]>='0'&&size[i]<='9'))
{
	num=size[i]-'a'+10;
}
	else{
	num=size[i]-'0';
}
	int j=len-1,temp=1;
	while(j>i)
{
	temp*=16;
	j--;
}	
	temp*=num;
	res+=temp;
	i--;
}
	return res;
}*/


void QQMsgExtractor::ClearFilterPort()
{
	boost::mutex::scoped_lock lock(setMut_);
	portSet_.clear();
	portSet_.insert(8000);
	portSet_.insert(80);
	portSet_.insert(443);
	portSet_.insert(4000);
}

char *QQMsgExtractor::chang(char *str)
{
	char newstr[32];
	int pos = 0;
	for (int i = 0; str[i] != '\0'; i++)
	{
		if (str[i] == '\'')
		{
			newstr[i + pos] = '\'';
			newstr[i + 1 + pos] = str[i];
			pos++;
		}
		else
		{
			newstr[i + pos] = str[i];
		}
	}
	strcpy(str, newstr);
	return str;
}


//end of file
