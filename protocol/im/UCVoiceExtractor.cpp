#include "UCVoiceExtractor.h"
#include "threadpool/include/threadpool.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <time.h>
#include <unistd.h>

const u_short UC_CHANNEL = 1;
const u_int UC_SAMP_PER_SEC = 1000;
const u_short UC_BIT = 16;
const int UC_VOICE_HLEN = 13;
const u_int STORE_COUNT = 50000;

using namespace boost::threadpool;
pool threadPool;

UCVoiceExtractor::UCVoiceExtractor()
{
    //threadPool.size_controller().resize(2);
    //threadPool.schedule(boost::bind(&LoopStore, this));
}

UCVoiceExtractor::~UCVoiceExtractor()
{
}

bool UCVoiceExtractor::GetVoice(const PacketInfo* pktInfo)
{
    bool getOkay = true;

    if (!pktInfo) {
        getOkay = false;
    } else {
        switch (pktInfo->pktType) {
            case UDP:
                if (pktInfo->bodyLen <= UC_VOICE_HLEN) {
                    getOkay = false;
                // Verify the packet if have the UC voice feature (800B...).
                } else {
                    ucHead_ = (UcHead*)pktInfo->body;
                    if (ucHead_->id != 2944) {
                        getOkay = false;
                    } else {
                        //cout << "++++++++++++++++++Seqence: " << ucHead_->sequence << " ++++++++++++++++++"<< endl;
                        VoiceClean();
                        pktInfo_ = pktInfo;
                        // Connect the IP and port to a string.
                        stringstream ipPort;
                        ipPort << pktInfo_->srcIpv4 << ":" <<  pktInfo_->srcPort;
                        scrIpPort_ = ipPort.str();
                        StoreVoice();
                    }
                }
                break;
            case TCP:
                break;
            default:
                break;
        }
    }

    return getOkay;
}

void UCVoiceExtractor::VoiceClean()
{
    pktInfo_ = NULL;
    voicePkt_ = NULL;
}

bool UCVoiceExtractor::StoreVoice()
{
    bool storeOkay = true;
    VoiceList* voiceLst = NULL;
    u_short voiceLen = pktInfo_->bodyLen - UC_VOICE_HLEN;

    u_char* buf = new u_char[voiceLen];
    memcpy(buf, pktInfo_->body - UC_VOICE_HLEN, voiceLen);
    voicePkt_ = new VoicePacket;
    voicePkt_->data = buf;
    voicePkt_->dataLen = voiceLen;
    voicePkt_->seqNum = ucHead_->sequence;

    UsrVoiceMap::iterator it = usrVoiceTable_.find(scrIpPort_);
    if (it == usrVoiceTable_.end()) {
       voiceLst = CreateVoiceLst();
    } else {
       voiceLst = it->second;
    }

    if (!voiceLst) {
        storeOkay = false;
    } else {
        voiceLst->lst.push_back(voicePkt_);
        voiceLst->dataLen += voicePkt_->dataLen;
        if (voiceLst->dataLen >= STORE_COUNT) {
            boost::mutex::scoped_lock lock(bufMut_);
            storeBuf_.push_back(voiceLst);
            usrVoiceTable_.erase(it);
        }
    }

    return storeOkay;
}

VoiceList* UCVoiceExtractor::CreateVoiceLst()
{
    VoiceList* voicelst = new VoiceList;
    voicelst->dataLen = 0;
    voicelst->ipPort = scrIpPort_;
    UsrVoicePair pair(scrIpPort_, voicelst);
    usrVoiceTable_.insert(pair);

    return voicelst;
}

void UCVoiceExtractor::LoopStore(void* obj)
{
    UCVoiceExtractor* ucvExtractor = (UCVoiceExtractor*) obj;
    while (1) {
        sleep(1);
        ucvExtractor->CheckBuf();
    }
}

void UCVoiceExtractor::CheckBuf()
{
    VoiceList* voiceLst = NULL;
    {
        boost::mutex::scoped_lock lock(bufMut_);
        list<VoiceList*>::iterator it = storeBuf_.begin();
        if (it != storeBuf_.end()) {
            voiceLst = *it;
            storeBuf_.erase(it);
        }
    }
    if (voiceLst) {
        SortVoice(voiceLst); 
        StoreVoice(voiceLst);
        delete voiceLst;
        //MergeAndStoreVoice(voicelst);
    }
}

void UCVoiceExtractor::SortVoice(VoiceList* voiceLst)
{
    list<VoicePacket*>::iterator it = voiceLst->lst.begin();
    list<VoicePacket*>::iterator index = it;
    list<VoicePacket*>::iterator tmp = it;
    for (; it != voiceLst->lst.end(); ++it) {
        for ( ; index != voiceLst->lst.begin(); --index) {
            if ((*it)->seqNum < (*index)->seqNum) {
                continue;
            } else if (index != tmp) {
                VoicePacket* tmpPacket = *it;
                it = voiceLst->lst.erase(it);
                voiceLst->lst.insert(++index, tmpPacket);
                break;
            } else {
                break;
            }
        }
        index = it;
        tmp = it;
    }
}

bool UCVoiceExtractor::StoreVoice(VoiceList* voiceLst)
{
    bool storeOkay = true;
    time_t timeVal;
    time(&timeVal);
    stringstream fileName;
    WaveHead wavHead;
    ofstream* file = NULL;

    fileName << voiceLst->ipPort << "_" <<  timeVal << ".wav";
    Wave::InitWaveHdr(&wavHead, UC_CHANNEL, UC_SAMP_PER_SEC, UC_BIT, voiceLst->dataLen);
    if (!(file = Wave::StoreWaveHdr(fileName.str().c_str(), &wavHead))) {
        storeOkay = false;
    } else {
        list<VoicePacket*>::iterator it = voiceLst->lst.begin();
        for (; it != voiceLst->lst.end(); ++it) {
            Wave::StoreWaveData(file, (*it)->data, (*it)->dataLen);
            delete (*it)->data;
            delete *it;
        }
        voiceLst->lst.clear();
        file->close();
    }
//    cout << "++++++++++++++++++++++++dataLen:" << voiceLst->dataLen << endl;

    return storeOkay;
}

bool UCVoiceExtractor::MergeAndStoreVoice(VoiceList* voiceLst)
{
    bool mergeOkay = true;
    u_int index = 0;

    u_char* buf = new u_char[voiceLst->dataLen];

    for (list<VoicePacket*>::iterator it = voiceLst->lst.begin(); it != voiceLst->lst.end(); ++it) {
        memcpy(buf + index, (*it)->data, (*it)->dataLen);
        delete (*it)->data;
        index += (*it)->dataLen;
        delete *it;
    }
//    cout << "++++++++++++++++++++++++index:" << index << "dataLen:" << voiceLst->dataLen << endl;
    voiceLst->lst.clear();

    time_t timeVal;
    time(&timeVal);
    stringstream fileName;
    fileName << voiceLst->ipPort << "_" <<  timeVal << ".wav";
    //string timeStr = ctime(&timeVal);
    //string fileName = voiceLst->ipPort + "_" + timeVal;
    WaveHead wavHead;
    ofstream* file = NULL;
    Wave::InitWaveHdr(&wavHead, UC_CHANNEL, UC_SAMP_PER_SEC, UC_BIT, voiceLst->dataLen);
    if (!(file = Wave::StoreWaveHdr(fileName.str().c_str(), &wavHead))) {
        mergeOkay = false;
    } else {
        mergeOkay = Wave::StoreWaveData(file, buf, voiceLst->dataLen);
    }
    delete buf;
    delete voiceLst;

    return mergeOkay;
}

/*
const string* UCVoiceExtractor::GetUsr()
{
    string* str = NULL;

    UsrAddrMap::iterator it = usrAddrTable_->find(scrIpPort_);
    if (it == usrAddrTable_->end()) {
       ;
    } else {
       str = &(it->second);
    }
    return str;
}
*/
