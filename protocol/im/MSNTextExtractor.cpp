
#include <map>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "MSNTextExtractor.h"
#include "Public.h"
#include "clue_c.h"

#define MIN_MSN_LEN 4
#define PORT_BITS          16
#define LIST1	       "^FQY\\s\\d\\s\\d+\r\n"
#define LIST2	       "^ADL\\s\\d\\s\\d+\r\n"
#define LOGIN_RULE     "^USR\\s4\\sOK\\s(.+?)\\s\\d\\s\\d\r\n$"
#define LOGOUT_RULE    "^OUT\\s\r\n$"
#define RECVER_RULE    "CAL\\s\\d+\\s([^\\s]+?@.+?)\r\n"
#define SENDMSG_RULE   "MSG\\s\\d+\\sN\\s\\d+\r\n.*?\r\nContent-Type:\\stext/plain;\\scharset=UTF-8\r\n.*?\r\n\r\n(.+?)(MSG\\s\\d+\\sU\\s\\d+\r\n)?"
#define RECVMSG_RULE   "^MSG\\s(.+?)\\s.+?\\s\\d+\r\n.*?\r\nContent-Type:\\stext/plain;\\scharset=UTF-8\r\n.*?\r\n\r\n(.+)$"
#define SENDLXMSG_RULE "^UUM\\s\\d+\\s(.+?)\\s.*?\r\n.*?\r\nContent-Type:\\stext/plain;\\scharset=UTF-8\r\n.*?\r\n.*?\r\n\r\n(.+)$"
#define LIST_RULE "^ADL\\s6\\s\\d+\r\n<ml\\sl=.\\d.>((<d\\sn=.(.*?).>(<c\\sn=.(.*?).\\s.*?/>)+</d>)+)</ml>$"
#define GROUP_RULE "^NFY\\sPUT\\s\\d+\r\n.*?\r\nTo:\\s\\d+:(.+?);.*?\r\nFrom:\\s.*?\r\n\r\n.*?\r\n.*?\r\n\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n\r\n<circle>.+?<MFN>(.+?)</MFN>.+?</circle>$"

static int LLLL = 0;
static int FLAG = 0;
static char flag[10] = { 0 };
static char flag2[10] = { 0 };
static char flag3[10] = { 0 };
static char DataStr[2500] = { 0 };

MSNTextExtractor::MSNTextExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/MSN");
	isRunning_ = true;
	isDeepParsing_ = false;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	loginRule_ = new boost::regex(LOGIN_RULE);
	logoutRule_ = new boost::regex(LOGOUT_RULE);
	recverRule_ = new boost::regex(RECVER_RULE);
	sendMsgRule_ = new boost::regex(SENDMSG_RULE);
	recvMsgRule_ = new boost::regex(RECVMSG_RULE);
	sendlxMsgRule_ = new boost::regex(SENDLXMSG_RULE);
	listRule_ = new boost::regex(LIST_RULE);
	groupRule_ = new boost::regex(GROUP_RULE);
	boost::regex * list1_ = new boost::regex(LIST1);
	boost::regex * list2_ = new boost::regex(LIST2);
	
	memcpy(tableName_, "MSN", 4);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
	ClearFilterPort();
}

MSNTextExtractor::~MSNTextExtractor()
{
	delete loginRule_;
	delete logoutRule_;
	delete recverRule_;
	delete sendMsgRule_;
	delete recvMsgRule_;
	delete sendlxMsgRule_;
	delete listRule_;
	delete groupRule_;
}



bool MSNTextExtractor::IsImText(PacketInfo * pktInfo)
{
	//assert(pktInfo != NULL);
	bool isMSNText = false;

	if (!isRunning_)
	{
		//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Not Running!" << endl;
		return false;
	}

#ifdef MULTI_PORT   //close by zhangzm	
	{
		boost::mutex::scoped_lock lock(setMut_);
		if (portSet_.find(pktInfo->srcPort) == portSet_.end() && portSet_.find(pktInfo->destPort) == portSet_.end())
		{
			//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Not linstening port!" << endl;
			return false;
		}
	}
	pktInfo_ = pktInfo;
	if (pktInfo_->bodyLen <= MIN_MSN_LEN)
	{
		//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Less lenth!" << endl;
		return false;
	}
	if (!CheckPort(pktInfo_->srcPort) && !CheckPort(pktInfo_->destPort))
	{
		//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Not linstening port2!" << endl;
		return false;
	}
#else
	if (pktInfo->srcPort != 1863 && pktInfo->destPort != 1863)
		return false;

	if (pktInfo->bodyLen <= MIN_MSN_LEN)
		return false;

	pktInfo_ = pktInfo;
#endif


	boost::cmatch matchedStr;
	const char *first = pktInfo_->body;
	const char *last = pktInfo_->body + pktInfo_->bodyLen;
	//boost::regex * list1_;
	//boost::regex * list2_;
	//list1_ = new boost::regex(LIST1);
	//list2_ = new boost::regex(LIST2);

	if (boost::regex_search(first, last, matchedStr, *list2_))
	{
		FLAG = 1;
	}
	if (FLAG)
	{
		//cout<<"FLAG: "<<FLAG<<endl;
		if (!strncmp(first, flag3, 9))
		{
			return false;
		}
		else if (strstr(first, "</d></ml>") != NULL)
		{
			strncpy(DataStr + LLLL, first, pktInfo_->bodyLen);
			first = DataStr;
			last = DataStr + strlen(DataStr);
			FLAG = 0;
			LLLL = 0;
			//      cout<<"DATALEN: "<<strlen(DataStr)<<endl;
			//      cout<<"DATA: "<<DataStr<<endl;
		}
		else
		{
			strncpy(DataStr + LLLL, first, pktInfo_->bodyLen);
			strncpy(flag3, first, 9);
			LLLL += pktInfo_->bodyLen;
			return false;

		}
	}

	if (boost::regex_search(first, last, matchedStr, *groupRule_))
	{
		//cout<<"Get groupNum!!!"<<endl;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
		u_int clueId = 0;
#ifdef VPDNLZ
		char pppoe[60] = {0};
		clueId = GetObjectId2(pktInfo_->destIpv4, pppoe);
		if (clueId == 0)
			return false;
#else
		//clueId = GetObjectId(strmac);
		//if(!clueId){return false;}
		struct in_addr addr;
		addr.s_addr = pktInfo->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));

#endif
		int len = matchedStr[1].length();
		char *str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *user = str;
		//cout<<user<<endl;
		len = matchedStr[2].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char *groupNum = str;
		//cout<<groupNum<<endl;

		char tmp[256] = {0};

#if 0  //zhangzm relation_list
		string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
		sql += " values(";
		sql += "\'";
		sql += user;
		sql += "\',";
		u_int type = 502;
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
// #ifndef VPDNLZ
// 		AddObjectId(clueId, strmac);
// #endif
#endif
		//cout << "[MSNGroupNum] Data insert into DB!" << endl;
		LOG_INFO("[MSNGroupNum] Data insert into DB!\n");
		delete user;
		delete groupNum;
		isMSNText = true;
	}

	uint64_t key = pktInfo_->srcIpv4;
	key = key << PORT_BITS;
	key += pktInfo_->srcPort;
	uint64_t key2 = pktInfo_->destIpv4;
	key2 = key2 << PORT_BITS;
	key2 += pktInfo_->destPort;
	map < uint64_t, Chat >::iterator it;
	it = keyMap.find(key);

	map < uint64_t, Chat >::iterator ite;
	ite = keyMap.find(key2);
	if (ite != keyMap.end())
	{
		if (boost::regex_search(first, last, matchedStr, *recvMsgRule_))
		{
			//cout<<"Get recvMsg!!!"<<endl;
			int len = matchedStr[2].length();
			char *str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char *text = str;
			//cout<<"The recvMsg is: "<<text<<endl;

			len = matchedStr[1].length();
			str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);
			char *from = str;

			//cout<<from<<endl;
			string t = ite->second.sender;
			char *to = new char[t.size() + 1];
			to[t.size()] = 0;
			memcpy(to, &t[0], t.size());
			//cout<<to<<endl;


			MsgNode *node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);

			node->text = text;
			node->from = from;
			node->to = to;
			node->msgType = Text;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo->pkt->ts.tv_sec;
			int clueId = 0;

			//node->protocolType = PROTOCOL_ID_WEBMSN;
			char strmac[20] = {0};
			ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->destIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 502;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			node->affixFlag = 9000;
			node->cc = NULL;
			node->path = NULL;
			node->groupSign = 0;
			node->groupNum = NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			isMSNText = true;
		}
	}
	else if (it != keyMap.end())
	{
		if (boost::regex_search(first, last, matchedStr, *recverRule_))
		{
			//cout<<"Get recver!!!"<<endl;
			int len = matchedStr[1].length();
			char *str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);
			string recver = str;
			//cout<<"The recver is: "<<recver<<endl;

			it->second.recver = recver;

			isMSNText = true;
		}
		else if (boost::regex_search(first, last, matchedStr, *sendMsgRule_))
		{
			char* str = new char[pktInfo_->bodyLen + 1];
			str[pktInfo_->bodyLen] = 0;
			memcpy(str, pktInfo_->body, pktInfo_->bodyLen);

			boost::cmatch matchedStrr;
			for(;boost::regex_search(str, matchedStrr, *sendMsgRule_);)
			{
				str = str + matchedStr[0].length();
				
			//cout<<"Get sendMsg!!!"<<endl;
			if (!strncmp(first, flag, 9))
				return 0;
			strncpy(flag, first, 9);
			int len = matchedStrr[1].length();
			char *strr = new char[len + 1];
			strr[len] = 0;
			memcpy(strr, matchedStrr[1].first, len);
			char *text = strr;
			//cout<<"The sendMsg is: "<<text<<endl;
			string f = it->second.sender;
			string t = it->second.recver;
			char *from = new char[f.size() + 1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());
			//cout<<from<<endl;
			char *to = new char[t.size() + 1];
			to[t.size()] = 0;
			memcpy(to, &t[0], t.size());
			//cout<<to<<endl;
			MsgNode *node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			node->text = text;
			node->from = from;
			node->to = to;
			node->msgType = Text;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo->pkt->ts.tv_sec;
			int clueId = 0;

			//node->protocolType = PROTOCOL_ID_WEBMSN;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 502;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			node->affixFlag = 0;
			node->cc = NULL;
			node->path = NULL;
			node->groupSign = 0;
			node->groupNum = NULL;
			StoreMsg2DB(node);

			}
			pktInfo_ = NULL;
			isMSNText = true;
		}
		else if (boost::regex_search(first, last, matchedStr, *logoutRule_))
		{
			//cout<<"MSNlogout!!!"<<endl;
			string f = it->second.sender;
			char *from = new char[f.size() + 1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());
			//cout<<"Logout ID: "<<from<<endl;
			MsgNode *node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);

			node->text = NULL;
			node->from = from;
			node->to = NULL;
			node->msgType = Logout;
			node->time = NULL;
			time(&node->timeVal);
			int clueId = 0;

			//node->protocolType = PROTOCOL_ID_WEBMSN;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 502;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			node->affixFlag = 0;
			node->cc = NULL;
			node->path = NULL;
			node->groupSign = 0;
			node->groupNum = NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			keyMap.erase(key);
			isMSNText = true;
		}
		else if (boost::regex_match(first, last, matchedStr, *listRule_))
		{
			//cout<<matchedStr[0]<<endl;
			//if(boost::regex_search(first, last, matchedStr, *listRule2_)){
			//cout<<"MSN Friends List!"<<endl;
			//cout<<matchedStr[1]<<endl;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			u_int clueId = 0;
#ifdef VPDNLZ
			char pppoe[60];
			clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			//if(clueId==0){return false;}
			int leng = matchedStr[1].length();
			char *str2 = new char[leng + 1];
			str2[leng] = 0;
			memcpy(str2, matchedStr[1].first, leng);
			char *data = str2;
			string f = it->second.sender;

			char *from = new char[f.size() + 1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());
			//cout<<"user is : "<<from<<endl;
			//GetBuddy(data);
			int num = 0;
			char *i, *j, str[256], res[64][256];
			i = strstr(data, "n=\"");
			while (i)
			{
				i += 3;
				j = strstr(i, "\"");
				int len = j - i;
				if (*(i - 5) == 'd')
				{
					memset(str, 0, 256);
					memcpy(str, i, len);
					//cout<<str<<endl;
					str[len] = '\0';
				}
				else if (*(i - 5) == 'c')
				{
					memset(res[num], 0, 256);
					memcpy(res[num], i, len);
					//cout<<res[num]<<endl;
					res[num][len] = '\0';
					memcpy(res[num] + len, "@", 1);
					memcpy(res[num] + len + 1, str, strlen(str));
					//strcat(res[num], "@");
					//strcat(res[num], str);
					//cout<<res[num]<<endl;
					char tmp[256];
#if 0  //zhangzm relation_list
					string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
					sql += " values(";
					sql += "\'";
					sql += from;
					sql += "\',";
					u_int type = 502;
					sprintf(tmp, "%lu", type);	//TYPE
					sql += tmp;
					sql += ",\'";
					sql += res[num];
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

//					AddObjectId (clueId,strmac);


// #ifndef VPDNLZ
// 					AddObjectId(clueId, strmac);
// #endif
#endif
					//cout << "[MSNFriendsNum] Data insert into DB!" << endl;
					LOG_INFO("[MSNFriendsNum] Data insert into DB!\n");
					num++;
				}
				i = strstr(i, "n=\"");
			}
			isMSNText = true;
			memset(DataStr, 0, 2500);
			//}
		}
		else if (boost::regex_search(first, last, matchedStr, *sendlxMsgRule_))
		{
			//cout<<"Get sendlxMsg!!!"<<endl;
			if (!strncmp(first, flag2, 9))
				return 0;
			strncpy(flag2, first, 9);
			int len = matchedStr[2].length();
			char *str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char *text = str;
			//cout<<"The sendlxMsg is: "<<text<<endl;
			string f = it->second.sender;

			char *from = new char[f.size() + 1];
			from[f.size()] = 0;
			memcpy(from, &f[0], f.size());
			//cout<<from<<endl;
			len = matchedStr[1].length();
			str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);
			char *to = str;
			//cout<<to<<endl;

			MsgNode *node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);

			node->text = text;
			node->from = from;
			node->to = to;
			node->msgType = Text;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo->pkt->ts.tv_sec;
			int clueId = 0;

			//node->protocolType = PROTOCOL_ID_WEBMSN;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 502;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			node->affixFlag = 0;
			node->cc = NULL;
			node->path = NULL;
			node->groupSign = 0;
			node->groupNum = NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			isMSNText = true;
		}
	}
	else
	{
		if (boost::regex_search(first, last, matchedStr, *loginRule_))
		{
			//cout<<"MSNlogin!!!"<<endl;

			int len = matchedStr[1].length();
			char *str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);
			string sender = str;
			char *from = str;
			//cout<<from<<endl;
			uint64_t key = pktInfo_->destIpv4;
			key = key << PORT_BITS;
			key += pktInfo_->destPort;
			Chat chat;
			chat.sender = sender;
			keyMap.insert(pair < uint64_t, Chat > (key, chat));
			MsgNode *node = new MsgNode;
			memset(node, 0, sizeof(MsgNode));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			node->srcIpv4 = pktInfo_->destIpv4;
			node->srcPort = pktInfo_->destPort;
			node->destIpv4 = pktInfo_->srcIpv4;
			node->destPort = pktInfo_->srcPort;

			node->text = NULL;
			node->from = from;
			node->to = NULL;
			node->msgType = Login;
			node->time = NULL;
			//time(&node->timeVal);
			node->timeVal = (time_t)pktInfo->pkt->ts.tv_sec;
			int clueId = 0;

			//node->protocolType = PROTOCOL_ID_WEBMSN;
			char strmac[20] = {0};
			ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
			clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo->destIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			//cout<<"Clue ID is : "<<clueId<<endl;
			node->clueId = clueId;
			node->fileName = NULL;
			node->protocolType = 502;
			node->user = NULL;
			node->pass = NULL;
			node->subject = NULL;
			node->affixFlag = 9000;	//sign for msn login
			node->cc = NULL;
			node->path = NULL;
			node->groupSign = 0;
			node->groupNum = NULL;
			StoreMsg2DB(node);
			pktInfo_ = NULL;
			isMSNText = true;
		}
		else if (boost::regex_search(first, last, matchedStr, *recverRule_))
		{
			//cout<<"Get sender!!!"<<endl;
			int len = matchedStr[1].length();
			char *str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[1].first, len);
			string sender = str;
			//cout<<"The sender is: "<<sender<<endl;
			uint64_t key = pktInfo_->srcIpv4;
			key = key << PORT_BITS;
			key += pktInfo_->srcPort;
			Chat chat;
			chat.sender = sender;
			keyMap.insert(pair < uint64_t, Chat > (key, chat));

			isMSNText = true;
		}
	}
	return isMSNText;
}

bool MSNTextExtractor::CheckPort(u_short port)
{
	switch (port)
	{
		// case 80:
	case 1863:
		return true;
	}

	return false;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void MSNTextExtractor::StoreMsg2DB(MsgNode * msgNode)
{
#if 0 //zhangzm
	if (msgNode->clueId == 0)
	{
		sqlConn_ = m_db_conn->get_sqlConn_flood();
	}
	else
	{
		sqlConn_ = m_db_conn->get_sqlConn_special();
	}

	struct in_addr addr;
	char tmp[256] = {0};
	char srcMac[20] = {0};

	string sql = "insert into IMINFO(id,clueid,readed,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,num,peernum,type,deleted) ";
	sql += "values(SEQ_IMINFO_ID.nextval,:clueid,:readed,:clientip,:clientmac,:clientport,:serverip,:serverport,:capturetime,:optype,:content,:num,:peernum,:type,:deleted)";

	sqlConn_->SetSql(sql.c_str());
	sqlConn_->SetInt(1, msgNode->clueId);
	sqlConn_->SetInt(2, 0);
	addr.s_addr = msgNode->srcIpv4;
	sqlConn_->SetString(3, inet_ntoa(addr));
	if (msgNode->affixFlag == 9000)
	{
		ParseMac(msgNode->destMac, srcMac);
	}
	else
	{
		ParseMac(msgNode->srcMac, srcMac);
	}
	sqlConn_->SetString(4, srcMac);
	sprintf(tmp, "%d", msgNode->srcPort);
	sqlConn_->SetString(5, tmp);
	addr.s_addr = msgNode->destIpv4;
	sqlConn_->SetString(6, inet_ntoa(addr));
	sprintf(tmp, "%d", msgNode->destPort);
	sqlConn_->SetString(7, tmp);
	sqlConn_->SetTime(8,msgNode->timeVal);
	sqlConn_->SetInt(9, msgNode->msgType);
	if (msgNode->text != NULL)
	{
		
		sqlConn_->SetString(10, msgNode->text);
	}
	else
	{
		sqlConn_->SetString(10, "");
	}
	if (msgNode->from != NULL)
	{
		
	sqlConn_->SetString(11, msgNode->from);
	}
	else
	{
		sqlConn_->SetString(11, "");
	}
	if (msgNode->to != NULL)
	{
		sqlConn_->SetString(12, msgNode->to);
	}
	else
	{
		sqlConn_->SetString(12, "");
	}
	
	sqlConn_->SetInt(13, msgNode->protocolType);  //502
	sqlConn_->SetInt(14, 0);
	sqlConn_->DoSql();
#endif
	xmlStorer_.ClearNode(msgNode);

	//cout << "[MSN] Data insert into DB!" << endl;\
	LOG_INFO("[MSN] Data insert into DB!\n");
}

void MSNTextExtractor::ClearFilterPort()
{
	boost::mutex::scoped_lock lock(setMut_);
	portSet_.clear();
	portSet_.insert(1863);
}

