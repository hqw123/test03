
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "FetionTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"
//#include "Analyzer_log.h"

// Regular expression rules.
#define SEND_RULE "^M\\sfetion.com.cn\\sSIP-C/(2|4).0\r\nF:\\s(\\w+?)\r\n.*?(\\s(sip|tel):(\\w+)(@fetion.com.cn)?.*?)?\r\n\r\n(.+)"
#define RECV_RULE "^M(\\s)(\\w+?)\\sSIP-C/(2|4).0\r\n.*?\\s(sip|tel):(\\w+)(@fetion.com.cn)?.*?\r\n\r\n(.+)"

// Positions in matched list.
#define SRC_POS        2
#define DEST_POS       5
#define TEXT           7
#define V10QUN_RULE "^<events>.*?<group\\suri=.*sip:PG(\\d+)@fetion.com.cn.*?\\sgroup-attributes-version=.*/></group></event></events>$"
#define V10LIST_RULE "^<events>.*?<p\\sv=.*sid=.(\\d+).*/>.*</events>$"
#define V10USER_RULE "^BN\\s(\\w+)\\sSIP-C/4.0$"
#define V10PHONE_RULE "^<events>.*m=.(\\d+).*</events>$"

#define BUDDIES        1
// #define LOGIN_RULE "^F:\\s(\\w+?)$"
#define LOGIN_RULE "^POST\\s/nav/getsystemconfig.aspx\\?NewType=2&loginId=.*?<config><user\\smobile-no=\"(\\d+)\"\\s/>.*?</config>$"

#define LOGOUT_RULE "^POST\\s/fpc/fpcdata/receive\\sHTTP/1.1"

#define USER           1
#define TAG            0x204d       //"M "
// #define LOGIN_TAG      0x2052
#define LOGIN_TAG      0x54534f50   //"POST"
#define L_TAG          0x4c         //"L"
#define V10L_TAG       0x4e43       //"CN"
#define V10_TAG          0x4e42     //"BN"
#define V08_TAG        0x2d504953

#define FILTER_RULE "<[^>]*>"
#define MIN_PKT_LEN    64

//-----------------------------------------------------------------------
// Func Name   : FetionTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
FetionTextExtractor::FetionTextExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/Fetion");

	// Create a directory to store the Fetion message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	sendRule_ = new boost::regex(SEND_RULE);
	recvRule_ = new boost::regex(RECV_RULE);
	loginRule_ = new boost::regex(LOGIN_RULE);
	logoutRule_ = new boost::regex(LOGOUT_RULE);
	v10listRule_ = new boost::regex(V10LIST_RULE);
	v10qunRule_ = new boost::regex(V10QUN_RULE);
	v10userRule_ = new boost::regex(V10USER_RULE);
	v10phoneRule_ = new boost::regex(V10PHONE_RULE);
	memcpy(tableName_, "FETION", 7);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

//-----------------------------------------------------------------------
// Func Name   : ~FetionTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
FetionTextExtractor::~FetionTextExtractor()
{
	delete sendRule_;
	delete recvRule_;
	delete loginRule_;
	delete logoutRule_;
	delete v10listRule_;
	delete v10qunRule_;
	delete v10userRule_;
	delete v10phoneRule_;
}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool FetionTextExtractor::IsImText(PacketInfo * pktInfo)
{
	bool isFetionText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;

	if (pktInfo_->bodyLen <= MIN_PKT_LEN)
		return isFetionText;

	// Filter the port and packet lenth at the first.
	if (*reinterpret_cast < const u_short * >(pktInfo_->body) == TAG)
	{
//		cout << __FILE__ << ":" << __FUNCTION__ << ": " << "FETION MSG!!!" << endl;
		isFetionText = MatchFetion();
	}
	else if (*reinterpret_cast < const unsigned int * >(pktInfo_->body) == LOGIN_TAG)
	{
//		cout << __FILE__ << ":" << __FUNCTION__ << ": " << "FETION 2015 Login!!!" << endl;
		isFetionText = MatchFetion();
	}
	else if (*reinterpret_cast < const u_short * >(pktInfo_->body) == V10_TAG)
	{
//		cout << __FILE__ << ":" << __FUNCTION__ << ": " << "FETION 2010 Buddies!!!" << endl;
		isFetionText = MatchFetion();
	}
	
	return isFetionText;
}

//-----------------------------------------------------------------------
// Func Name   : MatchFetion
// Description : The function matches the packet if is belong to Fetion.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool FetionTextExtractor::MatchFetion()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char *first = pktInfo_->body;
	const char *last = pktInfo_->body + pktInfo_->bodyLen;

	// Match the sent message.
	if (boost::regex_match(first, last, matchedStr, *sendRule_))
	{
		// Push the node to message list.
		StoreMsg2DB(CreateMsgNode(matchedStr, SRC_POS, DEST_POS, pktInfo_->srcIpv4, pktInfo_->srcPort));
//		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushNode sendRule_ over!!!" << endl;
		matched = true;
	}
	else if (boost::regex_match(first, last, matchedStr, *recvRule_))
	{
		StoreMsg2DB(CreateMsgNode(matchedStr, DEST_POS, SRC_POS, pktInfo_->destIpv4, pktInfo_->destPort));
//		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushNode recvRule_ over!!!" << endl;
		matched = true;
	}
	else if (boost::regex_search(first, last, matchedStr, *loginRule_))
	{
		StoreMsg2DB(CreateLoginNode(matchedStr, USER, pktInfo_->srcIpv4, pktInfo_->srcPort));
//		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushNode loginRule_ over!!!" << endl;
		matched = true;
	}
	else if (boost::regex_search(first, last, matchedStr, *logoutRule_))
	{
		StoreMsg2DB(CreateLogoutNode(matchedStr, pktInfo_->srcIpv4, pktInfo_->srcPort));
//		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushNode loginRule_ over!!!" << endl;
		matched = true;
	}
	else if (boost::regex_search(first, last, matchedStr, *v10listRule_))
	{
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
		unsigned int clueId = 0;
#ifdef VPDNLZ
		char pppoe[60] = {0};
		clueId = GetObjectId2(pktInfo_->destIpv4, pppoe);
		if (clueId == 0)
		{
			return false;
		}
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));

		//if(clueId==0){return false;}
#endif
		int len = matchedStr[1].length();
		char *str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *buddy = str;

		boost::regex_search(first, last, matchedStr, *v10userRule_);
		len = matchedStr[1].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *user = str;

		boost::regex_search(first, last, matchedStr, *v10phoneRule_);
		len = matchedStr[1].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *phoneNum = str;

#if 0  //zhangzm	relation_list
		string sqls = "select account from relation_list where protocol_type=504 and is_group=0 and friends_account=\'";
		sqls += buddy;
		sqls += "\'";
//		cout << "SQLS : " << sqls << endl;
		MYSQL_RES *rets;
		rets = sqlConn_->Select(&sqls);
		MYSQL_ROW row;
		if ((row = mysql_fetch_row(rets)))
		{
			string sqlu = "update relation_list set phone_num=\'";
			sqlu += phoneNum;
			sqlu += "\' where protocol_type=504 and is_group=0 and friends_account=\'";
			sqlu += buddy;
			sqlu += "\'";
//			cout << "SQLU : " << sqlu << endl;
			sqlConn_->Insert(&sqlu);
			cout << "[FETIONFriendsNum]: Update phoneNum of Fetion friend!" << endl;
		}
		else
		{
			char tmp[256];
			string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, phone_num, is_group,object_id)";
			sql += " values(";
			sql += "\'";
			sql += user;
			sql += "\',";
			unsigned int type = 504;
			sprintf(tmp, "%lu", type);	//TYPE
			sql += tmp;
			sql += ",\'";
			sql += buddy;
			sql += "\',";
			sql += "now()";	//capturetime record currenttime
			sql += ",\'";
			sql += phoneNum;
			sql += "\',";
			unsigned int isgroup = 0;
			sprintf(tmp, "%lu", isgroup);
			sql.append(tmp);
			sql += ",";
			sprintf(tmp, "%lu", clueId);
			sql.append(tmp);
			sql += ")";
			sqlConn_->Insert(&sql);

// #ifndef VPDNLZ
// 			AddObjectId(clueId, strmac);
// #endif
			cout << "[FETIONFriendsNum] Data insert into DB!" << endl;

		}
		mysql_free_result(rets);
#endif
		delete buddy;
		delete user;
		delete phoneNum;
		matched = true;

	}
	else if (boost::regex_search(first, last, matchedStr, *v10qunRule_))
	{
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
		unsigned int clueId = 0;

#ifdef VPDNLZ
		char pppoe[60];
		clueId = GetObjectId2(pktInfo_->destIpv4, pppoe);
		if (clueId == 0)
		{
			return false;
		}
#else
		//clueId = GetObjectId(strmac);
		//if(clueId==0){return false;}
		
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		int len = matchedStr[1].length();
		char *str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *groupNum = str;

		boost::regex_search(first, last, matchedStr, *v10userRule_);
		len = matchedStr[1].length();
		str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char *user = str;

		char tmp[256];
#if 0  //zhangzm	relation_list
		string sql = "insert into relation_list(account, protocol_type, friends_account, capture_time, is_group,object_id)";
		sql += " values(";
		sql += "\'";
		sql += user;
		sql += "\',";
		unsigned int type = 504;
		sprintf(tmp, "%lu", type);	//TYPE
		sql += tmp;
		sql += ",\'";
		sql += groupNum;
		sql += "\',";
		sql += "now()";	//capturetime record currenttime
		sql += ",";

		unsigned int isgroup = 1;
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
		//cout << "[FETIONGroupNum] Data insert into DB!" << endl;
		LOG_INFO("[FETIONGroupNum] Data insert into DB!\n");
		delete groupNum;
		delete user;
		matched = true;

	}
	return matched;
}

MsgNode *FetionTextExtractor::CreateMsgNode(boost::cmatch & matchedStr, u_short from, u_short to, unsigned int ip, u_short port)
{
	int clueId = 0;

	// Create the message node.
	MsgNode *node = new MsgNode;
	memset(node, 0, sizeof(MsgNode));
	node->msgType = Text;

	// Get the sender.
	int len = matchedStr[from].length();
	char *str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[from].first, len);
	node->from = str;

	// Get the text.
	len = matchedStr[TEXT].length();
	str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[TEXT].first, len);
	node->text = str;

	// Get the receiver.
	len = matchedStr[to].length();
	str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[to].first, len);
	node->to = str;

	// Get the current time.
	node->time = NULL;
	//time(&node->timeVal);
	node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;

	// Copy basic data to message node
	memcpy(node, pktInfo_, COPY_BYTES);
	node->affixFlag = 0;
	if (ip != pktInfo_->srcIpv4)
	{
		node->srcPort = pktInfo_->destPort;
		node->destPort = pktInfo_->srcPort;
		node->srcIpv4 = pktInfo_->destIpv4;
		node->destIpv4 = pktInfo_->srcIpv4;
		node->affixFlag = 9000;
	}

	struct in_addr addr;
	char strmac[20] = {0};
	if (node->affixFlag == 9000)
	{
		ParseMac(pktInfo_->destMac, strmac);
		addr.s_addr = pktInfo_->destIpv4;
	}
	else
	{
		ParseMac(pktInfo_->srcMac, strmac);
		addr.s_addr = pktInfo_->srcIpv4;
	}
#ifdef VPDNLZ
	clueId = GetObjectId2(node->srcIpv4, node->pppoe);
#else
	//clueId = GetObjectId(strmac);
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	node->clueId = clueId;
	node->fileName = NULL;
	node->protocolType = 504;
	node->user = NULL;
	node->pass = NULL;
	node->subject = NULL;
	node->cc = NULL;
	node->path = NULL;
	node->groupSign = 0;
	node->groupNum = NULL;
	pktInfo_ = NULL;
	return node;
}

MsgNode *FetionTextExtractor::CreateLoginNode(boost::cmatch & matchedStr, u_short from, unsigned int ip, u_short port)
{
	int clueId = 0;

	// Create the message node.
	MsgNode *loginNode = new MsgNode;
	memset(loginNode, 0, sizeof(MsgNode));
	loginNode->msgType = Login;

	// Get the sender.
	int len = matchedStr[from].length();
	char *str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[from].first, len);
	loginNode->from = str;
	loginNode->to = NULL;
	loginNode->text = NULL;

	// Get the current time.
	loginNode->time = NULL;
	//time(&loginNode->timeVal);
	loginNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	// Copy basic data to message node
	memcpy(loginNode, pktInfo_, COPY_BYTES);

	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);

#ifdef VPDNLZ
	clueId = GetObjectId2(loginNode->srcIpv4, loginNode->pppoe);
#else
	//clueId = GetObjectId(strmac);

	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	loginNode->clueId = clueId;
	loginNode->fileName = NULL;
	loginNode->protocolType = 504;
	loginNode->user = NULL;
	loginNode->pass = NULL;
	loginNode->subject = NULL;
	loginNode->affixFlag = 0;
	loginNode->cc = NULL;
	loginNode->path = NULL;
	loginNode->groupSign = 0;
	loginNode->groupNum = NULL;
	pktInfo_ = NULL;

	return loginNode;
}
MsgNode *FetionTextExtractor::CreateLogoutNode(boost::cmatch & matchedStr, unsigned int ip, u_short port)
{
	int clueId = 0;

	// Create the message node.
	MsgNode *loginNode = new MsgNode;
	memset(loginNode, 0, sizeof(MsgNode));
	loginNode->msgType = Logout;

	// Get the sender.

	loginNode->from = NULL;
	loginNode->to = NULL;
	loginNode->text = NULL;

	// Get the current time.
	loginNode->time = NULL;
	//time(&loginNode->timeVal);
	loginNode->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
	// Copy basic data to message node
	memcpy(loginNode, pktInfo_, COPY_BYTES);

	char strmac[20];
	memset(strmac, 0, 20);
	ParseMac(pktInfo_->srcMac, strmac);

#ifdef VPDNLZ
	clueId = GetObjectId2(loginNode->srcIpv4, loginNode->pppoe);
#else
	//clueId = GetObjectId(strmac);
	
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
	loginNode->clueId = clueId;
	loginNode->fileName = NULL;
	loginNode->protocolType = 504;
	loginNode->user = NULL;
	loginNode->pass = NULL;
	loginNode->subject = NULL;
	loginNode->affixFlag = 0;
	loginNode->cc = NULL;
	loginNode->path = NULL;
	loginNode->groupSign = 0;
	loginNode->groupNum = NULL;
	pktInfo_ = NULL;

	return loginNode;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void FetionTextExtractor::StoreMsg2DB(MsgNode * msgNode)
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
		strncpy(tmp_data.content, regex_replace(string(msgNode->text), boost::regex(FILTER_RULE), "").c_str(), 499);
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

