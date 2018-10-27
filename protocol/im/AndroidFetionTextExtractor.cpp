
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AndroidFetionTextExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"
//#include "Analyzer_log.h"

// Regular expression rules.
#define SRC_POS        2
#define DEST_POS       5
#define TEXT           7
#define V10QUN_RULE "^<events>.*?<group\\suri=.*sip:PG(\\d+)@fetion.com.cn.*?\\sgroup-attributes-version=.*/></group></event></events>$"
#define V10LIST_RULE "^<events>.*?<p\\sv=.*sid=.(\\d+).*/>.*</events>$"
#define V10USER_RULE "^BN\\s(\\w+)\\sSIP-C/4.0$"
#define V10PHONE_RULE "^<events>.*m=.(\\d+).*</events>$"
#define BUDDIES        1
#define LOGIN_RULE "^F:\\s(\\w+?)$"
//-----------------------------------------------------------------------------------------------
#define LOGIN_RULEM "GET /oauth/access_token HTTP/1.1"   //android飞信账号密码请求规则
#define SEND_RULEM "^.{6}(fetion.com.cn).{18,19}(\\w+)(.{2})(sip):(\\w+)@(fetion.com.cn).*?SaveHistory.{2}(.+)"                     
#define RECV_RULEM "(.{6})(\\w+)(.{2})(sip):(\\w+)@(fetion.com.cn);p="
#define RECV_RULEM "(.{6})(\\w+)(.{2})(sip):(\\w+)@(fetion.com.cn);p=.{57,59}(.+?)"
#define QUN_RULEM_SEND "^.{6}(fetion.com.cn).{18,19}(\\w+)(.{2})(sip):PG(\\w+)@(fetion.com.cn).*?SaveHistory.{2}(.+)"
//#define QUN_RULEM_RECV  "(.{6})(\\w+)(.{2})(sip):PG(\\w+)@(fetion.com.cn);p="
#define FEIXIN_CONTENT 0x00
#define FEIXIN_USER    0x02
//-----------------------------------------------------------------------------------------------

#define USER           1
#define TAG            0x204d
#define LOGIN_TAG      0x2052
#define L_TAG          0x4c
#define V10L_TAG       0x4e43
#define V10_TAG        0x4e42
#define V08_TAG        0x2d504953

#define FILTER_RULE "<[^>]*>"
#define MIN_PKT_LEN    64
//#define FILE_DIREC     "/home/nodeData/moduleData/Fetion/file"

//-----------------------------------------------------------------------
// Func Name   : FetionTextExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
AndroidFetionTextExtractor::AndroidFetionTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/Fetion");
	//protoType_ = PROTOCOL_FETION;
    // Create a directory to store the Fetion message files.
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	//sendRule_ = new boost::regex(SEND_RULE);
	       ///////////////////////////////android///
        MRecvRule_ = new boost::regex(RECV_RULEM);
        MSendRule_ = new boost::regex(SEND_RULEM);
        MLoginRule_ = new boost::regex(LOGIN_RULEM);
	MQunRule_ = new boost::regex(QUN_RULEM_SEND);
        ////////////////////////////////////////

  //      recvRule_ = new boost::regex(RECV_RULE);
    //v08listRule_ = new boost::regex(V08LIST_RULE);
//        loginRule_ = new boost::regex(LOGIN_RULE);
    //v08listRule_ = new boost::regex(V08LIST_RULE);
    //v08userRule_ = new boost::regex(V08USER_RULE);
        v10listRule_ = new boost::regex(V10LIST_RULE);
        v10qunRule_ = new boost::regex(V10QUN_RULE);
        v10userRule_ = new boost::regex(V10USER_RULE);
        v10phoneRule_ = new boost::regex(V10PHONE_RULE);
        memcpy(tableName_, "FETION", 7);
        sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);

}
// Func Name   : ~AndroidFetionTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
AndroidFetionTextExtractor::~AndroidFetionTextExtractor()
{
	//////////////////////////////android
        delete MRecvRule_;
	delete MSendRule_;
	delete MLoginRule_;
	delete MQunRule_;
        /////////////////////////////////////
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
bool AndroidFetionTextExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isFetionText = false;
	//assert(pktInfo != NULL);

    boost::cmatch matchedStr;
    const char* first = pktInfo->body;
	const char* last = pktInfo->body + pktInfo->bodyLen;
	pktInfo_ = pktInfo;
    // Filter the port and packet lenth at the first.
  	if ((pktInfo_->bodyLen > MIN_PKT_LEN) && *(pktInfo_->body) == FEIXIN_CONTENT)  //所发信息
	{
//	        cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"MFETION CONTENT!!!"<<endl;
		isFetionText = MatchFetion();
	}
	else if (boost::regex_search(first, last, matchedStr, *MLoginRule_))
	{
            //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"MFETION LOGIN!!!"<<endl;
        	StoreAccount2DB(CreateMLoginNode(matchedStr, USER, pktInfo_->srcIpv4, pktInfo_->srcPort));
		isFetionText == true;
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
bool AndroidFetionTextExtractor::MatchFetion()
{
	bool matched = false;
	boost::cmatch matchedStr;
    const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
    // Get the packet body on TCP layer.

	if(boost::regex_match(first, last, matchedStr, *MSendRule_))
	{
//       		cout<<"飞信发送(群)消息！！"<<endl;
        StoreMsg2DB(CreateMsgNodeA(matchedStr, SRC_POS, DEST_POS, pktInfo_->srcIpv4, pktInfo_->srcPort));
		return true;
	}
	return matched;
}


MsgNode* AndroidFetionTextExtractor::CreateMsgNodeA(boost::cmatch& matchedStr,
                                            u_short from,
                                            u_short to,
                                            u_int ip,
                                            u_short port)
{ 
    u_short text = TEXT;
//    if(DEST_POS == from)
//    {
//	from = 2;
//        to = 1;
//        text = 3;
//    } 
//    cout<<"WENBEN:"<<matchedStr[0].first<<endl; 
    int clueId = 0;
    // Create the message node.
    MsgNode* node = new MsgNode;
    memset(node, 0, sizeof(MsgNode));
    node->msgType = Text;
    // Get the sender.
    int len = matchedStr[from].length();
    char* str = new char[len + 1];
    str[len] = 0;
    memcpy(str, matchedStr[from].first, len);
    node->from = str;
   // cout<<"SRCPOS:"<<str<<endl;
	LOG_INFO("SRCPOS:%s\n",str);
    // Get the receiver.
    len = matchedStr[to].length();
   // char* to
    str = new char[len + 1];
   // to
    str[len] = 0;
    memcpy(str, matchedStr[to].first, len);
   // node->to = str;
    if(strstr(str, "PG"))
    {
//	str +=2;
	node->to = str;
//	node->to += 2;
	node->affixFlag = 0;
    }
    else
    {
	node->to = str;
	node->affixFlag = 1;
    }
    //cout<<"DESTPOS:"<<node->to<<endl;
	LOG_INFO("DESTPOS:%s\n",node->to);
    // Get the text.
    len = matchedStr[text].length();
   // char* text
    str = new char[len + 1];
    str[len] = 0;
    memcpy(str, matchedStr[text].first, len);
    node->text = str;
    //cout<<"MSG:"<<str<<endl;
	LOG_INFO("MSG:%s\n",str);
    // Get the current time.
    node->time = NULL;
   // time(&node->timeVal);
    node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
    // Copy basic data to message node
    memcpy(node, pktInfo_, COPY_BYTES);
    // Create the file name to store the corresponding messages.
    // And use the file name to map a talk session.
    /*
    char* fileName = new char[FILE_NAME_LEN];
    sprintf(fileName, "%s/%lu_%d.xml\0", DIRECTORY, ip, port);*/


   // cout << "A:" << protoType_ << "B:" << pktInfo_->srcIpv4 << "C:" << node->from << endl;

    char strmac[20] = {0};
    ParseMac(pktInfo_->srcMac, strmac);
    char strmac2[20] = {0};
    ParseMac(pktInfo_->destMac, strmac2);

	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;
	
    //clueId = (GetObjectId(strmac)|GetObjectId(strmac2));
	clueId = get_clue_id(strmac, inet_ntoa(addr));
	if (clueId == 0)
	{
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac2, inet_ntoa(addr));
		node->affixFlag = 9000;
	}
	
    node->clueId = clueId;
    node->fileName = NULL;
    node->protocolType = 504;

    node->user=NULL;
    node->pass=NULL;
    node->subject=NULL;
//    node->affixFlag=0;
    node->cc=NULL;
    node->path=NULL;
    pktInfo_ = NULL;
    return node;


}


MsgNode* AndroidFetionTextExtractor::CreateMLoginNode(boost::cmatch& matchedStr,u_short from,
											   u_int ip,
											   u_short port)
{   
	std::string USERstr = "x_auth_username=\"(.+?)\"";
    boost::regex Userex(USERstr);
	boost::cmatch Umatchstr;
	std::string PASSstr = "x_auth_password=\"(.+?)\"";
    boost::regex Passrex(PASSstr);
	boost::cmatch Pmatchstr;
	const char *begin = pktInfo_->body;
	const char *end = pktInfo_->body + pktInfo_->bodyLen;
	int clueId=0;
    // Create the message node.
	MsgNode* loginNode = new MsgNode;
	memset(loginNode, 0, sizeof(MsgNode));
	loginNode->msgType = Login;
    // Get the sender.
	int len = matchedStr[from].length();
	char* str = new char[len + 1];
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
    // Create the file name to store the corresponding messages.
    // And use the file name to map a talk session.
    //cout<<"LOGIN RULE!!!"<<endl;
	LOG_DEBUG("LOGIN RULE!!!\n");
	
    if(boost::regex_search(begin, end, Umatchstr, Userex))
	{
         int Ulen = Umatchstr[1].length();
		 if(Ulen<1024)
		 {
			// cout<<"ULEN:"<<Ulen<<"-CreateNLogin return loginNode!!"<<endl;
			LOG_INFO("ULEN:%d-CreateNLogin return loginNode!!\n",Ulen);
			loginNode->user = new char[Ulen+1];
			memset(loginNode->user, 0, Ulen+1);
			memcpy(loginNode->user, Umatchstr[1].first, Ulen);
          //  cout<<"FETION USER:"<<loginNode->user<<endl;
			LOG_INFO("FETION USER:%s\n",loginNode->user);
		 }
	}
	else {
		loginNode->user = NULL;
		//cout<< "account Fail"<<endl;
		LOG_INFO("account Fail\n");
	}
	if(boost::regex_search(begin, end, Pmatchstr, Passrex))
	{
		int Plen = Pmatchstr[1].length();
		if(Plen<1024)
		{
	       // cout<<"ULEN:"<<Plen<<"-CreateNLogin return loginNode!!"<<endl;
			LOG_INFO("ULEN:%d-CreateNLogin return loginNode!!\n",Plen);
			loginNode->pass = new char[Plen+1];
			memset(loginNode->pass, 0, Plen+1);
			memcpy(loginNode->pass, Pmatchstr[1].first, Plen);
			//cout<<"FETION PASS:"<<loginNode->pass<<endl;
			LOG_INFO("FETION PASS:%s\n",loginNode->pass);
		 }
	}
	else{ 
		loginNode->pass = NULL;
		//cout<<"PASS FAIL!!!"<<endl;
		LOG_INFO("PASS FAIL!!!\n");
	}
        
	char strmac[20] = {0};
	ParseMac(pktInfo_->srcMac, strmac);
	struct in_addr addr;
	addr.s_addr = pktInfo_->srcIpv4;

	//clueId = GetObjectId(strmac);
	clueId = get_clue_id(strmac, inet_ntoa(addr));
	
	loginNode->clueId = clueId;
	loginNode->fileName = NULL;
	loginNode->protocolType = 202;
//	loginNode->pass = NULL; 
	loginNode->subject=NULL;
	loginNode->affixFlag=0;
	loginNode->cc=NULL;
	loginNode->path=NULL;
	pktInfo_ = NULL;
        //cout<<"CreateNLogin return loginNode!!"<<endl;	
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
void AndroidFetionTextExtractor::StoreMsg2DB(MsgNode* msgNode)
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

//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void AndroidFetionTextExtractor::StoreAccount2DB(MsgNode* msgNode)
{
	char url[20] = "i.feixin.10086.cn";
	struct in_addr srcaddr, destaddr;	
	char srcMac[20] = {0};
	
	ParseMac(msgNode->srcMac, srcMac);
	srcaddr.s_addr = msgNode->srcIpv4;
	destaddr.s_addr = msgNode->destIpv4;

	/*write webaccount data to shared memory, by zhangzm*/
	WEBACCOUNT_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = msgNode->clueId;
	tmp_data.p_data.readed = 0;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(srcaddr));
	strncpy(tmp_data.p_data.clientMac, srcMac, 17);
	sprintf(tmp_data.p_data.clientPort, "%d", msgNode->srcPort);
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(destaddr));
	sprintf(tmp_data.p_data.serverPort, "%d", msgNode->destPort);
	
	tmp_data.p_data.captureTime = msgNode->timeVal;
	strcpy(tmp_data.url, url);
	strncpy(tmp_data.username, msgNode->user, 64);
	strncpy(tmp_data.password, msgNode->pass, 64);
	
	tmp_data.p_data.proType = msgNode->protocolType;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));

	xmlStorer_.ClearNode(msgNode);	
}

// End of file
