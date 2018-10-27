#include "UCFileExtractor.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
using namespace std;

//#define DIRECTORY          "/home/nodeData/moduleData/UC"
//#define SUB_DIREC          "/home/nodeData/moduleData/UC/File"
#define FILE_NAME_LEN      41
#define BEGIN              0x0003
#define TRANS              0x0005
#define END                0x0007
#define MIN_BEGIN_LEN      12
#define TRANS_HLEN         6
#define END_HLEN           12
#define FILE_NAME_LEN_POS  6
#define FILE_NAME_POS      8 
#define SEQ_POS            2 
#define PORT_BITS          16
const int MAP_SIZE = 1024;

UCFileExtractor::UCFileExtractor()
{
	sprintf(DIRECTORY,"%s%s",nodeDataPath,"/nodeData/moduleData/UC");
	sprintf(SUB_DIREC,"%s%s",nodeDataPath,"/nodeData/moduleData/UC/File");
    protoType_ = PROTOCOL_UC;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

    dampedMap_ = new DampedMap<uint64_t>(MAP_SIZE, 2, 3);
    memcpy(tableName_, "UC", 3);
    sprintf(dataFile_, "%s/%s", DIRECTORY, tableName_);
}

UCFileExtractor::~UCFileExtractor()
{
    delete dampedMap_;
}

bool UCFileExtractor::IsImFile(PacketInfo* pktInfo)
{
    //assert(pktInfo != NULL);
    pktInfo_ = pktInfo;
    if (pktInfo_->pktType != UDP) {
        return false;
    }
    if (pktInfo_->bodyLen <= MIN_BEGIN_LEN) {
        return false;
    }
    const u_short command = *reinterpret_cast<const u_short*>(pktInfo_->body);
    switch (command) {
        case BEGIN: {
            //cout << "111111111111111111111111111111111" << endl;
            const u_short fileNameLen = *reinterpret_cast<const u_short*>(pktInfo_->body + FILE_NAME_LEN_POS);
            if (pktInfo_->bodyLen != fileNameLen + MIN_BEGIN_LEN) {
                break;
            }
            //cout << "222222222222222222222222222222222" << endl;
            const u_int endTag = *reinterpret_cast<const u_int*>(pktInfo_->body + pktInfo_->bodyLen - 4);
            if (endTag != 0) {
                break;
            }
            //cout << "333333333333333333333333333333333" << endl;
            char* srcFileName = new char[fileNameLen + 1];
            memcpy(srcFileName, pktInfo_->body + FILE_NAME_POS, fileNameLen + 1);
            FileSession* fileSession = new FileSession(GetTimeStr(), srcFileName, SUB_DIREC);
            uint64_t key = pktInfo_->destIpv4;
            key = key << PORT_BITS;
            key += pktInfo_->destPort;
            dampedMap_->Push(key, fileSession);
            break;
        }
        case TRANS: {
            if (pktInfo_->bodyLen <= TRANS_HLEN) {
                break;
            }
            //cout << "55555555555555555555555555555555555" << endl;
            uint64_t key = pktInfo_->srcIpv4;
            key = key << PORT_BITS;
            key += pktInfo_->srcPort;
            FileSession* fileSession = reinterpret_cast<FileSession*>(dampedMap_->Find(key));
            if (!fileSession) {
                break;
            }
            const int seq = *reinterpret_cast<const u_int*>(pktInfo_->body + SEQ_POS);
            //cout << "+++++++++++++++++++++++++++" << seq << endl;
            const int nextSeq = fileSession->GetNextSeq();
            if (seq == nextSeq) {
                fileSession->IncNextSeq();
                ofstream file(fileSession->GetFileName(), ios::out | ios::app);
                fileSession->SetZero();
                file.write(pktInfo_->body + TRANS_HLEN, pktInfo_->bodyLen - TRANS_HLEN);
                file.close();
            } else if (seq > nextSeq) {
                // Here can be refined for a seq buffer.
                dampedMap_->Pop(key);
            } else {
                fileSession->Release();
            }
            break;
        }
        case END: {
            if (pktInfo_->bodyLen <= END_HLEN) {
                break;
            }
            //cout << "66666666666666666666666666666666666666" << endl;
            uint64_t key = pktInfo_->srcIpv4;
            key = key << PORT_BITS;
            key += pktInfo_->srcPort;
            FileSession* fileSession = reinterpret_cast<FileSession*>(dampedMap_->Find(key));
            if (!fileSession) {
                break;
            }
            u_int seq = *reinterpret_cast<const u_int*>(pktInfo_->body + SEQ_POS);
            //cout << "-------------------------------" << seq << endl;
            if (seq == fileSession->GetNextSeq()) {
                ofstream file(fileSession->GetFileName(), ios::out | ios::app);
                file.write(pktInfo_->body + END_HLEN, pktInfo_->bodyLen - END_HLEN);
                file.close();
                fileSession->Finish();
                char* srcFileName = fileSession->GetSrcFileName();
                const char* time = fileSession->GetCurrentTime();
                fileSession->SetZero();
                PushMassage(srcFileName, time);
            }
            dampedMap_->Pop(key);
            break;
        }
        default:
            return false;
    }
    if (!pktInfo_) {
        pktInfo_ = NULL;
    }

    return true;
}

void UCFileExtractor::PushMassage(char* srcFileName, const char* timeStr)
{
    // Create and push message node for source address.
    MsgNode* node = new MsgNode;
    node->msgType = File;
    node->from = NULL;
    node->to = NULL;
    node->text = srcFileName;
    node->time = timeStr;
    //time(&node->timeVal);
    node->timeVal = (time_t)pktInfo_->pkt->ts.tv_sec;
    // Copy basic data to message node
    memcpy(node, pktInfo_, COPY_BYTES);
    char* fileName = new char[FILE_NAME_LEN];
    sprintf(fileName, "%s/%lu_%d.xml\0", DIRECTORY, pktInfo_->srcIpv4, pktInfo_->srcPort);
    node->fileName = fileName;
    pktInfo_ = NULL;
    PushNode(node);
}

// End of file.
