#include "N2PTextExtractor.h"
#include "Public.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

#define USR_NAME 1
#define TEXT 2
#define N2P_TAG  0x50534349
#define LOGIN_RULE  "^ICSP/1.2\\sLOGIN\\s(.+?)\\s.+?\r\nSN:.*\r\n\r\n"
#define RECV_RULE "^ICSP/1.2\\sPAGE\\s(.+?)\r\nDate:.+?\r\n.+?\r\n.+?\r\n.+\r\n\r\n.*?<body.*?>(.*?)</body>.*"
#define SEND_RULE "^ICSP/1.2\\sPAGE\\s(.+?)\r\nSN:.*?\r\n.+?\r\n.+?\r\n.+?\r\n\r\n.*?<body.*?>(.*?)</body>.*"
#define MIN_PKT_LEN   25

N2PTextExtractor::N2PTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",nodeDataPath,"/nodeData/moduleData/N2P");
    protoType_ = PROTOCOL_N2P;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

    loginRule_ = new boost::regex(LOGIN_RULE);
    recvRule_ = new boost::regex(RECV_RULE);
    sendRule_ = new boost::regex(SEND_RULE);
    memcpy(tableName_, "N2P", 4);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

N2PTextExtractor::~N2PTextExtractor()
{
    delete loginRule_;
    delete recvRule_;
    delete sendRule_;
}

bool N2PTextExtractor::IsImText(PacketInfo* pktInfo)
{
    bool isN2PText = false;
    //assert(pktInfo != NULL);
    pktInfo_ = pktInfo;

    if ((pktInfo_->bodyLen > MIN_PKT_LEN) && *reinterpret_cast<const u_int*>(pktInfo_->body) == N2P_TAG) {
        MatchN2P();
        if (pktInfo_) {
            pktInfo_ = NULL;
        }
        isN2PText = true;
    }

    return isN2PText;
}

bool N2PTextExtractor::MatchN2P()
{
    bool matched = false;
	boost::regex expression_login(LOGIN_RULE);
	boost::regex expression_recv(RECV_RULE);
	boost::regex expression_send(SEND_RULE);
    boost::cmatch matchedStr;
    const char* first = pktInfo_->body;
    const char* last = pktInfo_->body + pktInfo_->bodyLen;
    /*
    char str[pktInfo_->bodyLen + 1];
    str[pktInfo_->bodyLen] = 0;
    memcpy(str, pktInfo_->body, pktInfo_->bodyLen);*/
    if (boost::regex_match(first, last, matchedStr, *sendRule_)) {
        MsgNode* sendNode = new MsgNode;
        memset(sendNode, 0, sizeof(MsgNode));
        sendNode->msgType = Text;
        sendNode->from = NULL;
        // Get the receiver.
        int len = matchedStr[USR_NAME].length();
        char* str = new char[len + 1];
        str[len] = 0;
        memcpy(str, matchedStr[USR_NAME].first, len);
        sendNode->to = str;
        // Get the text.
        len = matchedStr[TEXT].length();
        str = new char[len + 1];
        str[len] = 0;
        memcpy(str, matchedStr[TEXT].first, len);
        sendNode->text = str;
        // Get the current time.
        sendNode->time = NULL;
        time(&sendNode->timeVal);
        // Copy basic data to message node
        memcpy(sendNode, pktInfo_, COPY_BYTES);
        /*
        char* fileName = new char[FILE_NAME_LEN];
        sprintf(fileName, "%s/%lu_%d.xml\0", DIRECTORY, pktInfo_->srcIpv4, pktInfo_->srcPort);*/
        sendNode->fileName = NULL;
        PushNode(sendNode);
        pktInfo_ = NULL;
        matched = true;
    } else if (boost::regex_match(first, last, matchedStr, *recvRule_)) {
        MsgNode* recvNode = new MsgNode;
        memset(recvNode, 0, sizeof(MsgNode));
        recvNode->msgType = Text;
        // Get the sender.
        int len = matchedStr[USR_NAME].length();
        char* str = new char[len + 1];
        str[len] = 0;
        memcpy(str, matchedStr[USR_NAME].first, len);
        recvNode->from = str;
        recvNode->to = NULL;
        // Get the text.
        len = matchedStr[TEXT].length();
        str = new char[len + 1];
        str[len] = 0;
        memcpy(str, matchedStr[TEXT].first, len);
        recvNode->text = str;
        // Get the current time.
        recvNode->time = NULL;
        time(&recvNode->timeVal);
        // Copy basic data to message node
        memcpy(recvNode, pktInfo_, COPY_BYTES);
        /*
        char* fileName = new char[FILE_NAME_LEN];
        sprintf(fileName, "%s/%lu_%d.xml\0", DIRECTORY, pktInfo_->destIpv4, pktInfo_->destPort);*/
        recvNode->fileName = NULL;
        PushNode(recvNode);
        pktInfo_ = NULL;
        matched = true;
    } else if (boost::regex_match(first, last, matchedStr, *loginRule_)) {
        MsgNode* loginNode = new MsgNode;
        memset(loginNode, 0, sizeof(MsgNode));
        loginNode->msgType = Login;
        // Get the sender.
        int len = matchedStr[USR_NAME].length();
        char* str = new char[len + 1];
        str[len] = 0;
        memcpy(str, matchedStr[USR_NAME].first, len);
        loginNode->from = str;
        loginNode->to = NULL;
        loginNode->text = NULL;
        // Get the current time.
        loginNode->time = NULL;
        time(&loginNode->timeVal);
        // Copy basic data to message node
        memcpy(loginNode, pktInfo_, COPY_BYTES);
        /*
        char* fileName = new char[FILE_NAME_LEN];
        sprintf(fileName, "%s/%lu_%d.xml\0", DIRECTORY, pktInfo_->srcIpv4, pktInfo_->srcPort);*/
        loginNode->fileName = NULL;
        PushNode(loginNode);
        pktInfo_ = NULL;
        matched = true;
    }

    return matched;
}

void N2PTextExtractor::StoreUsrInfo2Text(const string& usrName)
{
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    stringstream fileName;
    fileName << DIRECTORY << "/" << pktInfo_->srcIpv4 << ":" << pktInfo_->srcPort;
    stringstream content;
    content << "\n\n++++++++++++++++Login Msg++++++++++++++++++++\n";
    content << "User " << usrName << " login.\n";
    content << "Address: " << pktInfo_->srcIpv4 << " Port: " << pktInfo_->srcPort << endl;
    content << "+++++++++++++++++++++++++++++++++++++++++++++\n\n";
    ofstream file(fileName.str().c_str(), ios::out | ios::app);
    file << content.str();
    file.close();
}

void N2PTextExtractor::StoreRecvInfo2Text(const string& usrName, const string& text)
{
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    stringstream fileName;
    fileName << DIRECTORY << "/" << pktInfo_->destIpv4 << ":" << pktInfo_->destPort;
    stringstream content;
    string* currentTime = GetCurrentTime();
    content << "\n\n++++++++++++++++Receive Msg++++++++++++++++++\n";
    content << "Message from: " << usrName << endl;
    content << "Time: " << *currentTime << endl;
    content << "From: " << pktInfo_->srcIpv4 << " : " << pktInfo_->srcPort << endl;
    content << "To: " << pktInfo_->destIpv4 << " : " << pktInfo_->destPort << endl;
    content << "Text: \n" << text << endl;
    content << "+++++++++++++++++++++++++++++++++++++++++++++\n\n";
    ofstream file(fileName.str().c_str(), ios::out | ios::app);
    file << content.str();
    file.close();
}

void N2PTextExtractor::StoreSendInfo2Text(const string& usrName, const string& text)
{
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    stringstream fileName;
    fileName << DIRECTORY << "/" << pktInfo_->srcIpv4 << ":" << pktInfo_->srcPort;
    stringstream content;
    string* currentTime = GetCurrentTime();
    content << "\n\n+++++++++++++++++Send Msg++++++++++++++++++++\n";
    content << "Message to: " << usrName << endl;
    content << "Time: " << *currentTime;
    content << "From: " << pktInfo_->srcIpv4 << " : " << pktInfo_->srcPort << endl;
    content << "To: " << pktInfo_->destIpv4 << " : " << pktInfo_->destPort << endl;
    content << "Text: \n" << text << endl;
    content << "+++++++++++++++++++++++++++++++++++++++++++++\n\n";
    ofstream file(fileName.str().c_str(), ios::out | ios::app);
    file << content.str();
    file.close();
}

