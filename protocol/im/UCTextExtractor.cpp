#include "UCTextExtractor.h"
#include "Public.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <netinet/in.h>

//#define DIRECTORY         "/home/nodeData/moduleData/UC"
#define UC_MAX_NUM_LEN    40
#define UC_MAX_TEXT_LEN   350

UCTextExtractor::UCTextExtractor()
{
	sprintf(DIRECTORY,"%s%s",nodeDataPath,"/nodeData/moduleData/UC");
    protoType_ = PROTOCOL_UC;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

    RegSessionFunc(this->ProcUCSession);
    memcpy(tableName_, "UC", 3);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

UCTextExtractor::~UCTextExtractor()
{
}

bool UCTextExtractor::IsImText(PacketInfo* pktInfo)
{
    bool isUCText = false;
    //assert(pktInfo != NULL);
    pktInfo_ = pktInfo;
    
    if ((pktInfo_->pktType == UDP) && (pktInfo_->bodyLen > UC_HLEN)) {
        cipherLen_ = *reinterpret_cast<const u_short*>(pktInfo_->body + 11);
        u_int unknown = *reinterpret_cast<const u_int*>(pktInfo_->body + 7);
        if (*pktInfo_->body == UC_BEGIN_TAG && unknown == UC_UNKNOWN2 && cipherLen_ == pktInfo_->bodyLen - UC_HLEN) {
            PushMassage();
            isUCText = true;
        }
    }
    //IsRoomText();

    return isUCText;
}

#define UC_ROOM_HLEN  0x08
#define UC_BEGIN_TAG2 0x0302
#define UC_END_TAG    0x04
#define UC_END_TAG2   0x0605

bool UCTextExtractor::IsRoomText()
{
    bool isRoomText = true;
    if (pktInfo_->pktType != TCP) {
        isRoomText = false;
    } else if (pktInfo_->bodyLen <= UC_ROOM_HLEN) {
        isRoomText = false;
    } else if (*pktInfo_->body != UC_BEGIN_TAG) {
        isRoomText = false;
    } else if (*reinterpret_cast<const u_short*>(pktInfo_->body + 1) != UC_BEGIN_TAG2) {
        isRoomText = false;
    }
    if (isRoomText) {
        //cout << "-----------------------------------------\n";
        cipherLen_ = *reinterpret_cast<const u_short*>(pktInfo_->body + 3);
        if (*(pktInfo_->body + UC_ROOM_HLEN + cipherLen_) != UC_END_TAG) {
            isRoomText = false;
        }
        if (*reinterpret_cast<const u_short*>(pktInfo_->body + UC_ROOM_HLEN + cipherLen_ + 1) != UC_END_TAG2) {
            isRoomText = false;
        }
    }
    if (isRoomText){
        u_char ciphertext[cipherLen_ + 1];
        ciphertext[cipherLen_] = 0;
        memcpy(ciphertext, pktInfo_->body + UC_ROOM_HLEN, cipherLen_);
        for(int i = 0; i < cipherLen_/8; i++) {
            ucCrypt_.Decipher(reinterpret_cast<u_long*>(&ciphertext[8*i]),
                              reinterpret_cast<u_long*>(&ciphertext[4 + 8*i]));
        }
      
        for (int i = 0; i < cipherLen_; ++i) {
            cout << ciphertext[i];
        }
        cout << endl;
    }

    return isRoomText;
}

void UCTextExtractor::PushMassage()
{
    // Create and push message node for source address.
    MsgNode* srcNode = new MsgNode;
    memset(srcNode, 0, sizeof(MsgNode));
    srcNode->msgType = Text;
    srcNode->from = NULL;
    srcNode->to = NULL;
    char* text = new char[cipherLen_ + 1];
    text[cipherLen_] = 0;
    memcpy(text, pktInfo_->body + UC_HLEN, cipherLen_);
    srcNode->text = text;
    srcNode->time = NULL;
    time(&srcNode->timeVal);
    // Copy basic data to message node
    memcpy(srcNode, pktInfo_, COPY_BYTES);
    srcNode->fileName = NULL;
    PushNode(srcNode);
}

//-----------------------------------------------------------------------
// Func Name   : ProcessSession
// Description : Decipher and parse the body of UC message.
// Parameter   : session: A UC talk session.
//               obj: the object of UCTextExtractor.
// Return      : void
//-----------------------------------------------------------------------
void UCTextExtractor::ProcUCSession(MsgNode*& msgNode, void* obj)
{
    //assert(msgNode != NULL);
	if (msgNode == NULL)
		return;
	
    UCTextExtractor* yahooExtractor = reinterpret_cast<UCTextExtractor*>(obj);
    if (msgNode->text != NULL) {
        // Decipher the text by Blowfish algorithm.
        int cipherLen = msgNode->bodyLen - UC_HLEN;
        for(int i = 0; i < cipherLen/8; i++) {
            yahooExtractor->ucCrypt_.Decipher(reinterpret_cast<u_long*>(msgNode->text + 8*i),
                              reinterpret_cast<u_long*>(msgNode->text + 4 + 8*i));
        }
        char* ciphertext = msgNode->text;
        msgNode->text = NULL;
        // Position the index to command tag(offset is 5).
        u_short index = 5;
        u_short tag;
SUB_MESSAGE:
        tag = *reinterpret_cast<u_short*>(ciphertext + index);
        switch (tag) {
            case UC_STORE_1:
            case UC_STORE_2: {
                // Position the index to destination user number(offset add 2).
                index += 2;
                char* to = new char[12];
                // The destination user number stored by the unsigned int.
                u_int* recvNum = reinterpret_cast<u_int*>(ciphertext + index);
                sprintf(to, "%d\0", *recvNum);
                msgNode->to = to;
                // Position the index to head of sub message(offset add 10).
                index += 10;
                goto SUB_MESSAGE;
            }
            case UC_CMD_REDIR: {
                index += 2;
                if (msgNode->to == NULL) {
                    char* to = new char[12];
                    u_int* recvNum = reinterpret_cast<u_int*>(ciphertext + index);
                    sprintf(to, "%d\0", *recvNum);
                    msgNode->to = to;
                }
                index += 0x15;
                u_short sectionLen = *reinterpret_cast<u_short*>(ciphertext + index);
                if((sectionLen%8) || sectionLen >= cipherLen - index) {
                    break;
                }
                index += 2;
                for(int i = 0; i < sectionLen/8; i++) {
                    yahooExtractor->ucCrypt_.Decipher(reinterpret_cast<u_long*>(ciphertext + index + 8*i),
                                                      reinterpret_cast<u_long*>(ciphertext + index + 4 + 8*i));
                }
                index += 5;
                goto SUB_MESSAGE;
            }
            case UC_TALK_1:
            case UC_TALK_2: {
                index += 2;
                // The length of source user number stored by the unsigned int.
                tag = *reinterpret_cast<u_short*>(ciphertext + index);
                if (tag > cipherLen - index) {
                    break;
                }
                // Position the index to source user number(offset add 2).
                index += 2;
                // The source user number stored by the c string.
                char* from = new char[tag + 1];
                from[tag] = 0;
                memcpy(from, reinterpret_cast<void*>(ciphertext + index), tag);
                if (tag > UC_MAX_NUM_LEN) {
                    from[UC_MAX_NUM_LEN] = 0;
                }
                msgNode->from = from;
                // Position the index to length of nick name(offset add length of source user number).
                index += tag;
                tag = *reinterpret_cast<u_short*>(ciphertext + index);
                if (tag > cipherLen - index) {
                    break;
                }
                // Position the index to length of text.
                index += 2;
                index += tag;
                index += 6;
                tag = *reinterpret_cast<u_short*>(ciphertext + index);
                if (tag > cipherLen - index) {
                    break;
                }
                // Position the index to text.
                index += 2;
                char* text = ::GBK2UTF8(ciphertext + index, tag);
                if (strlen(text) > UC_MAX_TEXT_LEN) {
                    text[UC_MAX_TEXT_LEN] = 0;
                }
                msgNode->text = text;
                break;
            }
        }
        if (msgNode->text == NULL || *(msgNode->text) == 0) {
            if (msgNode->fileName) {
                delete msgNode->fileName;
                msgNode->fileName = NULL;
            }
            if (msgNode->from) {
                delete msgNode->from;
                msgNode->from = NULL;
            }
            if (msgNode->to) {
                delete msgNode->to;
                msgNode->to = NULL;
            }
            if (msgNode->text) {
                delete msgNode->text;
                msgNode->text = NULL;
            }
            if (msgNode->time) {
                delete msgNode->time;
                msgNode->time = NULL;
            }
            delete msgNode;
            msgNode = NULL;
        }
		else
		{
			char strmac[20];
			memset(strmac,0,20);
			ParseMac(msgNode->srcMac,strmac);
			msgNode->clueId = GetClueId(PROTOCOL_UC, strmac,msgNode->srcIpv4, msgNode->from);
        }
        delete ciphertext;
    }
}

void UCTextExtractor::StoreMsg2Text(const string& from, const string& to, const string& text)
{
    stringstream srcFileName;
    srcFileName << DIRECTORY << "/" << pktInfo_->srcIpv4 << ":" << pktInfo_->srcPort;
    stringstream destFileName;
    destFileName << DIRECTORY << "/" << pktInfo_->destIpv4 << ":" << pktInfo_->destPort;
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
    ofstream destFile(destFileName.str().c_str(), ios::out | ios::app);
    destFile << content.str();
    destFile.close();
}


