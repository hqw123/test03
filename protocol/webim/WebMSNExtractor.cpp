
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "WebMSNExtractor.h"
#include "Public.h"
#include "clue_c.h"

#define LOGIN_RULE "^ADL\\s\\d+\\sOK\r\nNFY\\sPUT\\s\\d+\r\nRouting:\\s1.0\r\nTo:\\s1:(.*?)\r\nFrom.+$"
#define LOGOUT_RULE "^NFY\\sDEL\\s\\d+\r\nRouting:\\s1.0\r\nTo:\\s1:(.*?)\r\nFrom.+$"
#define SENDMSG_RULE "SDG\\s\\d+\\s\\d+\r\nRouting:\\s1.0\r\nTo:\\s1:(.*?)\r\nFrom:\\s1:(.*?);.*?\r\n\r\n.*?\r\n\r\n.+?\r\n.+?\r\n.+?\r\n.+?\r\n.+?\r\n\r\n(.+)"
#define RECVMSG_RULE "SDG\\s0\\s\\d+\r\nRouting:\\s1.0\r\nTo:\\s1:(.*?)\r\nFrom:\\s1:(.*?);.*?\r\n\r\n.*?\r\n\r\n.+?\r\n.+?\r\n.+?\r\n.+?\r\n.+?\r\n.+?\r\n\r\n(.+)"

WebMSNExtractor::WebMSNExtractor()
{   
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBIM/WebMSN");
	isRunning_ = true;
	isDeepParsing_ = false;
	//protoType_ = PROTOCOL_WEBPAGECHAT;
    // Create a directory to store the webim message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	//loginRule_ = new boost::regex(LOGIN_RULE);
	//logoutRule_ = new boost::regex(LOGOUT_RULE);

	//sendMsgRule_ = new boost::regex(SENDMSG_RULE);
	//recvMsgRule_ = new boost::regex(RECVMSG_RULE);
	memcpy(tableName_, "WEBIM", 6);
	
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

WebMSNExtractor::~WebMSNExtractor()
{
	//delete loginRule_;
	//delete logoutRule_;
	//delete sendMsgRule_;
	//delete recvMsgRule_;
}

bool WebMSNExtractor::IsWebIMText(PacketInfo* pktInfo)
{
	bool iswebMSNText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	
	boost::regex loginRule_(LOGIN_RULE);
	boost::regex logoutRule_(LOGOUT_RULE);
	boost::regex sendMsgRule_(SENDMSG_RULE);
	boost::regex recvMsgRule_(RECVMSG_RULE);
  	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(boost::regex_search(first, last, matchedStr, loginRule_)){
	//cout<<"WebMSNlogin!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
		//cout<<"Login ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
	
		node->srcIpv4=pktInfo_->destIpv4;
		node->srcPort=pktInfo_->destPort;
		node->destIpv4=pktInfo_->srcIpv4;
		node->destPort=pktInfo_->srcPort;
		
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 602;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 9000;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
		iswebMSNText = true;
	}
	else if(boost::regex_search(first, last, matchedStr, logoutRule_)){
	//cout<<"WebMSNlogout!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
		//cout<<"Logout ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
	
		node->srcIpv4=pktInfo_->destIpv4;
		node->srcPort=pktInfo_->destPort;
		node->destIpv4=pktInfo_->srcIpv4;
		node->destPort=pktInfo_->srcPort;
		
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Logout;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId = 0;
		
		node->protocolType = 602;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 9000;
		StoreMsg2DB(node);
		pktInfo_ = NULL;
		iswebMSNText = true;
	}
	else if(boost::regex_search(first, last, matchedStr, recvMsgRule_)){
		//cout<<"Get recvMsg!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* to=str;
		//cout<<to<<endl;

		len = matchedStr[2].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char* from =str;
		//cout<<from<<endl;

		len = matchedStr[3].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[3].first, len);
		char* text=str;
		//cout<<"The recvMsg is: "<<text<<endl;
	
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=text;
		node->from=from;
		node->to=to;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 602;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 9000;
		StoreMsg2DB(node);
		pktInfo_ = NULL;	
		iswebMSNText = true;
		
	}
	else if(boost::regex_search(first, last, matchedStr, sendMsgRule_)){
		//cout<<"Get sendMsg!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* to=str;
		//cout<<to<<endl;

		len = matchedStr[2].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char* from =str;
		//cout<<from<<endl;

		len = matchedStr[3].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[3].first, len);
		char* text=str;
		//cout<<"The sendMsg is: "<<text<<endl;
		
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=text;
		node->from=from;
		node->to=to;
		node->msgType=Text;
		node->time = NULL;
		//time(&node->timeVal);
		node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
		u_int clueId=0;
		
		node->protocolType = 602;
		char strmac[20] = {0};
		ParseMac(pktInfo_->srcMac, strmac);
#ifdef VPDNLZ
		clueId = GetObjectId2(node->srcIpv4,node->pppoe);
#else
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag = 0;
		StoreMsg2DB(node);
		pktInfo_ = NULL;	
		iswebMSNText = true;
		
	}
	return iswebMSNText;
}

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebMSNExtractor::StoreMsg2DB(Node* msgNode)
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
	if(msgNode->affixFlag == 9000)
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
	sprintf(tmp, "%d",  msgNode->destPort);
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
	
	sqlConn_->SetInt(13, msgNode->protocolType);  //602
	sqlConn_->SetInt(14, 0);
	sqlConn_->DoSql();
#endif
	xmlStore_.ClearNode(msgNode);
}

/*
#define DIRECTORY      "/home/LzData/moduleData/WEBIM/WebMSN"
#define LOGIN_RULE	"UUX\\s12\\s0\r\nUBX\\s(.*?)\\s1\\s\\d+\r\n"
#define LOGOUT_RULE   	"OUT\\s\\d+\r\n"
#define PORT_BITS          16
#define SENDER_RULE "CAL\\s2\\s([^\\s]+?@.+?)\r\n"
#define RECVER_RULE "CAL\\s3\\s([^\\s]+?@.+?)\r\n"
//#define RECVER_RULE "CAL\\s3\\sRINGING\\s\\d+\r\nJOI\\s(.*?);"
//#define SENDER_RULE   "MSG\\s\\d+\\sU\\s\\d+\r\n.*?\r\nContent-Type:\\stext/x-msmsgscontrol\r\nTypingUser:\\s(.*?)\r\n\r\n"
//#define RECVER_RULE "MSG\\s.*?@.*?\\s.*?\\s\\d+\r\n.*?\r\nContent-Type:\\stext/x-msmsgscontrol\r\nTypingUser:\\s(.*?)\r\n\r\n"
#define SENDMSG_RULE "MSG\\s\\d+\\sN\\s\\d+\r\n.*?\r\nContent-Type:\\stext/plain;\\scharset=UTF-8\r\n.*?\r\n\r\n(.+)"
#define RECVMSG_RULE "HTTP/1.1\\s200\\sOK\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n\r\nMSG\\s(.+?)\\s.+?\\s\\d+\r\n.*?\r\nContent-Type:\\stext/plain;\\scharset=UTF-8\r\n.*?\r\n\r\n(.+)"
//POST\\s/gateway/gateway.dll?SessionId=.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n.*?\r\n\r\n
WebMSNExtractor::WebMSNExtractor(Occi* occi)
{   
	isRunning_ = true;
	isDeepParsing_ = false;
	protoType_ = PROTOCOL_WEBPAGECHAT;
    // Create a directory to store the webim message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	occi_ = occi;
	const char* sql="insert into WEBIM (webimid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, content, webimnum, peerwebimnum, type) values (webimid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12, :v13)";
	stmt_ = occi_->CreateStmt();
	occi_->SetSql(stmt_, sql);
	loginRule_ = new boost::regex(LOGIN_RULE);
	logoutRule_ = new boost::regex(LOGOUT_RULE);
	senderRule_ = new boost::regex(SENDER_RULE);
	recverRule_ = new boost::regex(RECVER_RULE);
	sendMsgRule_ = new boost::regex(SENDMSG_RULE);
	recvMsgRule_ = new boost::regex(RECVMSG_RULE);
	memcpy(tableName_, "WEBIM", 6);
	
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
	
}

WebMSNExtractor::~WebMSNExtractor()
{
	delete loginRule_;
	delete logoutRule_;
	delete senderRule_;
	delete recverRule_;
	delete sendMsgRule_;
	delete recvMsgRule_;
}

bool WebMSNExtractor::IsWebIMText(PacketInfo* pktInfo)
{
	bool iswebMSNText = false;
	assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
  	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(boost::regex_search(first, last, matchedStr, *loginRule_)){
		//cout<<"WebMSNlogin!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
		//cout<<"Login ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
	
		node->srcIpv4=pktInfo_->destIpv4;
		node->srcPort=pktInfo_->destPort;
		node->destIpv4=pktInfo_->srcIpv4;
		node->destPort=pktInfo_->srcPort;
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->destMac,strmac);
		clueId = GetClueId(protoType_, strmac, pktInfo_->destIpv4,node->from);
		node->clueId = clueId;
		node->fileName = NULL;
		PushNode(node);
		pktInfo_ = NULL;
		iswebMSNText = true;
	}else{
	uint64_t key = pktInfo_->srcIpv4;
		key = key << PORT_BITS;
		key += pktInfo_->srcPort;
	uint64_t key2 = pktInfo_->destIpv4;
		key2 = key2 << PORT_BITS;
		key2 += pktInfo_->destPort;
	map<uint64_t,Chat>::iterator it;
	it = keyMap.find(key);

        map<uint64_t,Chat>::iterator ite;
	ite = keyMap.find(key2);

	if(it != keyMap.end()){
		if(boost::regex_search(first, last, matchedStr, *recverRule_)){
		//cout<<"Get recver!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		string recver=str;
		cout<<"The recver is: "<<recver<<endl;
		/*uint64_t key = pktInfo_->srcIpv4;
		key = key << PORT_BITS;
		key += pktInfo_->srcPort;*/
	/*	it->second.recver=recver;
		
		iswebMSNText = true;
	}
	else if(boost::regex_search(first, last, matchedStr, *sendMsgRule_)){
		//cout<<"Get sendMsg!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* text=str;
		//cout<<"The sendMsg is: "<<text<<endl;
		string f=it->second.sender;
		string t=it->second.recver;
		char* from = new char[f.size()+1];
		from[f.size()] = 0;
		memcpy(from,&f[0],f.size());
		//cout<<from<<endl;
		char* to = new char[t.size()+1];
		to[t.size()] = 0;
		memcpy(to,&t[0],t.size());
		//cout<<to<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=text;
		node->from=from;
		node->to=to;
		node->msgType=Text;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->srcMac,strmac);
		clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4,node->from);
		node->clueId = clueId;
		node->fileName = NULL;
		PushNode(node);
		pktInfo_ = NULL;	
		iswebMSNText = true;
		
	}else if(boost::regex_search(first, last, matchedStr, *logoutRule_)){
		//cout<<"WebMSNlogout!!!"<<endl;
		string f=it->second.sender;
		char* from = new char[f.size()+1];
		from[f.size()] = 0;
		memcpy(from,&f[0],f.size());
		//cout<<"Logout ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Logout;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->srcMac,strmac);
		clueId = GetClueId(protoType_, strmac, pktInfo_->srcIpv4,node->from);
		node->clueId = clueId;
		node->fileName = NULL;
		PushNode(node);
		pktInfo_ = NULL;
		keyMap.clear();
		iswebMSNText = true;	
	}
	}
	else if(ite != keyMap.end()){
	if(boost::regex_search(first, last, matchedStr, *recvMsgRule_)){
		//cout<<"Get recvMsg!!!"<<endl;
		int len = matchedStr[2].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char* text=str;
		//cout<<"The recvMsg is: "<<text<<endl;
		string f=ite->second.recver;
		string t=ite->second.sender;
		char* from = new char[f.size()+1];
		from[f.size()] = 0;
		memcpy(from,&f[0],f.size());
		//cout<<from<<endl;
		char* to = new char[t.size()+1];
		to[t.size()] = 0;
		memcpy(to,&t[0],t.size());
		//cout<<to<<endl;
		
		
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=text;
		node->from=from;
		node->to=to;
		node->msgType=Text;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->destMac,strmac);
		clueId = GetClueId(protoType_, strmac, pktInfo_->destIpv4,node->to);
		node->clueId = clueId;
		node->fileName = NULL;
		PushNode(node);
		pktInfo_ = NULL;
		iswebMSNText = true;
	}
	}else{
	
	if(boost::regex_search(first, last, matchedStr, *senderRule_)){
		//cout<<"Get sender!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		string sender=str;
		//cout<<"The sender is: "<<sender<<endl;
		uint64_t key = pktInfo_->srcIpv4;
		key = key << PORT_BITS;
		key += pktInfo_->srcPort;
		Chat chat;
		chat.sender=sender;
		keyMap.insert(pair<uint64_t,Chat>(key,chat));
			
		iswebMSNText = true;
	}
	
	}
	}
    return iswebMSNText;
}*/



// End of file






/*/*
#include <map>

#define DIRECTORY "/home/LzData/moduleData/WEBIM/WebMSN"
//#define LOGIN_RULE "^HTTP[.\r\n]*?OnPresenceChanged\".*?\"id\":\"(.*?)\".*"
//#define LOGIN_RULE "OnPresenceChanged\".*?\"id\":\"(.*?)\""
#define LOGIN_RULE	"UUX\\s12\\s0\r\nUBX\\s(.*?)\\s1\\s\\d+\r\n"
#define TELNAME_RULE "CAL (\\d) (.*?)\r\n"
#define POST_CONTENT_RULE "MSG.*?\r\n.*?\r\nContent-Type:\\stext/plain;.*?\r\n.*?\r\n\r\n.+"
#define RECIVE_CONTENT_RULE "MSG\\s.*?\r\nMIME.*?\r\nContent-Type:\\stext/plain;.*?\r\n.*?\r\n\r\n(.*)"
map<string,WebMsnContNode*> msnmap;

WebMSNExtractor::WebMSNExtractor(Occi *occi)
{
         isRunning_ = true;
         isDeepParsing_ = false;
         protoType_ = PROTOCOL_WEBPAGECHAT;
         mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
         occi_ = occi;
         const char* sql="insert into WEBIM (webimid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, content, webimnum, peerwebimnum, type) values (webimid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12, :v13)";
         stmt_ = occi_->CreateStmt();
	 occi_->SetSql(stmt_, sql);
         loginRule_ = new boost::regex(LOGIN_RULE);
         telnameRule_ = new boost::regex(TELNAME_RULE);
         contentRule_ = new boost::regex(POST_CONTENT_RULE);
	 recivContentRule_ = new boost::regex(RECIVE_CONTENT_RULE);
	 memcpy(tableName_, "WEBIM", 6);
	
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}
WebMSNExtractor::~WebMSNExtractor()
{
        delete loginRule_;
        delete telnameRule_;
	delete contentRule_;
	delete recivContentRule_;
}

bool WebMSNExtractor::IsWebIMText(PacketInfo* pktInfo)
{	
	bool iswebMSNText = false;
        assert(pktInfo !=NULL);
	pktInfo_ = pktInfo;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	if(boost::regex_search(first, last, matchedStr, *loginRule_)){
		//cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!webMSNlogin!!!"<<endl;
		int len = matchedStr[1].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* from=str;
		//cout<<"Login ID: "<<from<<endl;
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		node->text=NULL;
		node->from=from;
		node->to=NULL;
		node->msgType=Login;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = PROTOCOL_ID_WEBMSN;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->destMac,strmac);
		clueId = GetClueId(protoType_, strmac, pktInfo_->destIpv4,node->from);
		node->clueId = clueId;
		node->fileName = NULL;
		PushNode(node);
		pktInfo_ = NULL;
		iswebMSNText = true;
	}else{
      WebMsnPacketType webpacketType;
      Type_judge(pktInfo_,webpacketType);
      switch(webpacketType)
     {
       /*case Signin:  Signin_analyse(pktInfo);
                     iswebMSNText = true;
                     break;*/
/*/*       case Session: Session_analyse(pktInfo_);
                     iswebMSNText = true;
                     break;
	   default:      iswebMSNText = false; break;
     } 
	}
     return iswebMSNText;
} 
void WebMSNExtractor::Type_judge(PacketInfo* pktInfo,WebMsnPacketType & pktType)
{
      char strnode_post[100]={0};
      sprintf(strnode_post,"%lu%lu%u%u",pktInfo->srcIpv4,pktInfo->destIpv4,pktInfo->srcPort,pktInfo->destPort);
      char strnode_ok[100]={0};
      sprintf(strnode_ok,"%lu%lu%u%u",pktInfo->destIpv4,pktInfo->srcIpv4,pktInfo->destPort,pktInfo->srcPort);
      map<string,WebMsnContNode*>::iterator iter_p;
      iter_p = msnmap.find(strnode_post);
      map<string,WebMsnContNode*>::iterator iter_ok;
      iter_ok = msnmap.find(strnode_ok);
   
   /*if(!strncmp(pktInfo->body,"POST /actions/signin/ HTTP/1.1\r\n",22)&&strstr(pktInfo->body,"Referer: http://messenger.services.live.com/xmlProxy.htm?"))
   {
       pktType = Signin;
   }
   else */
/*/*   if(!strncmp(pktInfo->body,"POST /gateway/gateway.dll?SessionID=",36))
   {
       pktType = Session;
   } 
   else
   if( iter_p != msnmap.end()) 
   {
         pktType = iter_p->second->packetType;
   } 
   else
   if( iter_ok != msnmap.end())
   {
       pktType = iter_ok->second->packetType;
   }
   else
   {
      pktType = NotWebMsn;
   }
}
/*
void WebMSNExtractor::Signin_analyse(PacketInfo* pktInfo)
{
       pktInfo_ = pktInfo;
       unsigned int seq=ntohl(pktInfo_->tcp->seq);
       int off_seq;
       int range=0;

      char strnode_ok[100]={0};
      sprintf(strnode_ok,"%lu%lu%u%u",pktInfo_->destIpv4,pktInfo_->srcIpv4,pktInfo_->destPort,pktInfo_->srcPort);
      map<string,WebMsnContNode*>::iterator iter_ok;
      iter_ok = msnmap.find(strnode_ok);
   if(!strncmp(pktInfo_->body,"POST /actions/signin/ HTTP/1.1\r\n",22)&&strstr(pktInfo_->body,"Referer: http://messenger.services.live.com/xmlProxy.htm?"))
   {
        WebMsnContNode * loginnode;
         loginnode = new WebMsnContNode;
         memset(loginnode,0,sizeof(WebMsnContNode));
         memcpy(loginnode,pktInfo_,COPY_BYTES);
		 loginnode->reciv_content = new char [10000];
         loginnode->post_content = NULL;
         loginnode->ok_start = false;
         loginnode->packetType = Signin;
         char strnode_post[100]={0};
         sprintf(strnode_post,"%lu%lu%u%u",pktInfo_->srcIpv4,pktInfo_->destIpv4,pktInfo_->srcPort,pktInfo_->destPort);
         msnmap[strnode_post]=loginnode;
   }
   else
   if (iter_ok != msnmap.end())
   {
      //only deal with ok packet  (note :include ack packet
      if(!strncmp(pktInfo_->body,"HTTP/1.1 200 OK\r\n",15))
      {//start to combine the packet
        iter_ok->second->ok_start_seq = seq;
		memset(iter_ok->second->reciv_content,0,10000);
		iter_ok->second->ok_start = true;
      }
      if(iter_ok->second->ok_start && iter_ok->second->reciv_content != NULL)
	  {
		  off_seq = seq - iter_ok->second->ok_start_seq;
		  range = off_seq + pktInfo_->bodyLen;
		  if (range < 10000)
		  {
			  memcpy(iter_ok->second->reciv_content + off_seq, pktInfo_->body,pktInfo_->bodyLen);
		  }
	  }
     if(iter_ok->second->ok_start && !memcmp(pktInfo_->body + pktInfo_->bodyLen - 3, "}\r}",3) || range > 10000)
	 {
          boost::cmatch matchedStr;
		  const char * first = iter_ok->second->reciv_content;
		  int length = strlen(iter_ok->second->reciv_content);
		  const char * last = iter_ok->second->reciv_content + length;
		  if (boost::regex_search(first,last,matchedStr,*loginRule_))
		  {
			  int len = matchedStr[1].length();
			  char *str = new char [len + 1];
			  str[len] = 0;
			  memcpy(str,matchedStr[1].first,len);
			  WriteNodeSignin(str,iter_ok);
		  }
		  Del_MapNode(iter_ok);
	 }
   }
	
   return ;
}*/


/*/*
void WebMSNExtractor::Session_analyse(PacketInfo* pktInfo)
{
	  bool erased = false;
	  pktInfo_ = pktInfo;
	  unsigned int seq=ntohl(pktInfo_->tcp->seq);
	  int off_seq;
	  int range=0;
      char strnode_post[100]={0};
      sprintf(strnode_post,"%lu%lu%u%u",pktInfo_->srcIpv4,pktInfo_->destIpv4,pktInfo_->srcPort,pktInfo_->destPort);
      char strnode_ok[100]={0};
      sprintf(strnode_ok,"%lu%lu%u%u",pktInfo_->destIpv4,pktInfo_->srcIpv4,pktInfo_->destPort,pktInfo_->srcPort);
      map<string,WebMsnContNode*>::iterator iter_p;
      iter_p = msnmap.find(strnode_post);
      map<string,WebMsnContNode*>::iterator iter_ok;
      iter_ok = msnmap.find(strnode_ok);
    
	  if(!strncmp(pktInfo_->body,"POST /gateway/gateway.dll?SessionID=",36))
      {
		  
		  if (iter_p != msnmap.end())
		  {//not the first, delet the old post, get the new post
			  memset(iter_p->second->post_content,0,10000);
			  iter_p->second->start_seq = seq;
			  iter_p->second->done = false;
			  iter_p->second->ok_start = false;
			  memcpy(iter_p->second->post_content,pktInfo_->body,pktInfo_->bodyLen);
          
		  }
		  else
		  {
			  WebMsnContNode * messagenode;
			  messagenode = new WebMsnContNode;
			  memset(messagenode,0,sizeof(WebMsnContNode));
			  memcpy(messagenode,pktInfo_,COPY_BYTES);
			  messagenode->reciv_content = new char [10000];
			  messagenode->post_content = NULL;
			  messagenode->from = NULL;
			  messagenode->to = NULL;
			  messagenode->start_seq = seq;
			  messagenode->post_content = new char [10000];
			  
			  memcpy(messagenode->post_content,pktInfo_->body,pktInfo_->bodyLen);
			  messagenode->packetType = Session;
			  messagenode->done = false;
			  messagenode->ok_start=false;
			  msnmap[strnode_post] = messagenode;
		  }
      
      }
	  else if(iter_p != msnmap.end())
	  {
		  if(iter_p->second->post_content!=NULL&& !iter_p->second->done)
		  {
          //start combine packet 
			  off_seq = seq - iter_p->second->start_seq;
			  range = off_seq + pktInfo_->bodyLen;
			  if (range < 10000)
			  {
				  memcpy(iter_p->second->post_content+off_seq,pktInfo_->body, pktInfo_->bodyLen);
			  }
		  } 
	  }
	  else if (iter_ok != msnmap.end())
	  {
		  if(!strncmp(pktInfo_->body,"HTTP/1.1 200 OK\r\n",15))
		  {
			  if (!iter_ok->second->done)
			  {//deal with session send content 
				  boost::cmatch matchedStr;
				  const char *first = iter_ok->second->post_content;
				  int length = strlen(iter_ok->second->post_content);
				  const char *last = iter_ok->second->post_content + length;
				  if (boost::regex_search(first,last,matchedStr,*telnameRule_))
				  {
					  int len = matchedStr[1].length();
					  char *str= new char[len+1];
					  str[len] = 0;
					  memcpy(str,matchedStr[1].first,len);
               
					  len = matchedStr[2].length();
					  char * str2 = new char[len+1];
					  str2[len] = 0;
					  memcpy(str2,matchedStr[2].first,len);
					  if (!strncmp(str,"2",1))
					  {
						  iter_ok->second->from=str2;
					  }
					  else if(!strncmp(str,"3",1))
					  {
						  iter_ok->second->to = str2;
					  }
					  iter_ok->second->done = true;
					  delete [] str;
				  }
				  else if(boost::regex_search(first,last,matchedStr,*contentRule_))
				  {
					  iter_ok->second->done = true;
					  char *p1=NULL;
					  p1 = strstr(first,"\r\n\r\nMSG ");
					  if (p1 == NULL) return ;
					  p1 +=8;
					  char *p2=NULL;
					  p2 = strstr(p1,"\r\n\r\n");
					  if (p2 == NULL) return ;
					  p2 += 4;
					  while(p2 !=NULL)
					  {
						  int len=0;
						  char *str=NULL;
						  p1 = strstr(p2,"MSG ");
						  if ( p1 != NULL)
						  {
							  len = p1 - p2;
						  }
						  else 
						  {
							  len=strlen(p2);
						
						  }
						  str = new char [len+1];
						  str[len]=0;
						  memcpy(str,p2,len);

						  WriteNode(str,iter_ok,1);
						  if (p1 != NULL )
						  {
							  p2 = strstr(p1,"\r\n\r\n");
							  if(p2 != NULL)
							  { 	
								  p2= p2+4;
							  }
						  }
						  else p2 = NULL;
					  }//end while	
				  }//end content
				  else 
				  {
					  Del_MapNode(iter_ok);
					  erased = true;
				  }
				  
			  }//end send content
			  if (!erased)
			  {
			   iter_ok->second->ok_start_seq = seq;    //first copy ok packet
			   memset(iter_ok->second->reciv_content,0,10000);
			   iter_ok->second->ok_start = true;
			  }
		  }
		  if(!erased && iter_ok->second->ok_start && iter_ok->second->reciv_content != NULL)
		  {
			  off_seq = seq - iter_ok->second->ok_start_seq;
			  range = off_seq + pktInfo_->bodyLen;
			  if (range < 10000)
			  {
				  memcpy(iter_ok->second->reciv_content + off_seq, pktInfo_->body,pktInfo_->bodyLen);
			  }
		  }
		  if(!erased && iter_ok->second->ok_start)
		  {
		      const char * first = iter_ok->second->reciv_content;
		      int length = strlen(iter_ok->second->reciv_content);
		      const char * last = iter_ok->second->reciv_content + length;
		      boost::cmatch matchedOkStr;
		      if (boost::regex_search(first,last,matchedOkStr,*recivContentRule_))
		      {
			    int len= matchedOkStr[1].length();
			    char * str = new char [len+1];
			    str[len] =0;
			    memcpy(str, matchedOkStr[1].first,len);
			    WriteNode(str,iter_ok,0);
			    memset(iter_ok->second->reciv_content,0,10000);
		      }
			  if( pktInfo_->tcp->psh== 1)
			  {
				  iter_ok->second->ok_start = false;
			  }
				
		  }  
	  }	  
	  return ;
}


void WebMSNExtractor::Del_MapNode(map<string,WebMsnContNode *>::iterator iter)
{
	//first free space then erase
	if (iter->second->post_content != NULL)
	{
		delete [] iter->second->post_content;
		iter->second->post_content = NULL;
	}
	if (iter->second->reciv_content != NULL)
	{
		delete [] iter->second->reciv_content;
		iter->second->reciv_content = NULL;
	}
	if (iter->second->from != NULL)
	{
		delete [] iter->second->from;
		iter->second->from = NULL;
	}
	if (iter->second->to != NULL)
	{
		delete [] iter->second->to;
		iter->second->to = NULL;
	}
	delete iter->second;
	 msnmap.erase(iter);
}

void WebMSNExtractor::WriteNode(char *textstr,map<string,WebMsnContNode*>::iterator iter,int sign)
{//sign =0 ,write recive content,sign =1 write send content
	char *str=textstr;
	Node* node = new Node;
	memset(node,0,sizeof(Node));
	memcpy(node,iter->second,COPY_BYTES);
	node->text = str;
	int len=0;				
	  if(iter->second->from != NULL)
	  {
		len = strlen(iter->second->from);
		str = new char [len+1];
		str[len] = 0;
		memcpy(str,iter->second->from,len);
		if (sign == 1)
		{
		  node->from = str;
		}
		else
		{
			node->to = str;
		}	
	  }
					
	  if (iter->second->to != NULL)
	  {
		len = strlen(iter->second->to);
		str = new char [len+1];
		str[len] = 0;
		memcpy(str,iter->second->to,len);
		if (sign == 1)
		{
		 node->to = str;
		}
		else
		{
			node->from = str;
		}
	  }
	node->msgType = Text;
	node->time = NULL;
	time(&node->timeVal);
					
	u_int clueId = 0;
	node->protocolType = PROTOCOL_ID_WEBMSN;
	char strmac[20];
	memset(strmac,0,20);
	ParseMac(iter->second->srcMac,strmac);
	char strmac2[20];
	memset(strmac2,0,20);
	ParseMac(iter->second->destMac,strmac2);
	clueId=(GetClueId(protoType_,strmac,node->srcIpv4,node->from)|GetClueId(protoType_,strmac2,node->destIpv4,node->to));
	node->clueId = clueId;
	node->fileName = NULL;
	PushNode(node);
}
/*
void WebMSNExtractor::WriteNodeSignin(char *fromstr, map<string,WebMsnContNode*>::iterator iter)
{
	
	Node * node = new Node;
	memset(node,0,sizeof(Node));
	memcpy(node,iter->second,COPY_BYTES);
	node->text = NULL;
	node->from = fromstr;
	node->to = NULL;
	node->msgType = Login;
	node->time = NULL;
	time(&node->timeVal);
	u_int clueId = 0;
	node->protocolType = PROTOCOL_ID_WEBMSN;
	char strmac[20];
	memset(strmac,0,20);
	ParseMac(iter->second->srcMac,strmac);
	clueId = GetClueId(protoType_,strmac,iter->second->srcIpv4,node->from);
	node->clueId = clueId;
	node->fileName = NULL;
	PushNode(node);
}
*/
// End of file
