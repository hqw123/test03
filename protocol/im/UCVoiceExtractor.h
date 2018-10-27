#ifndef UC_VOICE_EXTRACTOR
#define UC_VOICE_EXTRACTOR

//#include "PacketParser.h"
#include "PacketInfo.h"
#include "Wave.h"
#include <string>
#include <list>
#include <map>
#include <boost/thread/mutex.hpp>

using namespace std;

struct VoicePacket
{
    const u_char* data;
    u_short dataLen;
    u_short seqNum;
};

struct UcHead
{
    u_short id; //800B
    u_short sequence;
    u_int time;
    u_int sourceId;
    u_char voiceHead[12];
};

struct VoiceList
{
    list<VoicePacket*> lst;
    u_int dataLen;
    string ipPort;
};

typedef map<string, VoiceList*> UsrVoiceMap;
typedef pair<string, VoiceList*> UsrVoicePair;
typedef map<string, string> UsrAddrMap;
typedef pair<string, string> UsrAddrPair;


class UCVoiceExtractor
{
public:
    UCVoiceExtractor();
    virtual ~UCVoiceExtractor();
    bool GetVoice(const PacketInfo* pktInfo);
private:
    void VoiceClean();
    bool StoreVoice();
    VoiceList* CreateVoiceLst();
    void CheckBuf();
    void SortVoice(VoiceList* voiceLst);
    bool StoreVoice(VoiceList* voiceLst);
    bool MergeAndStoreVoice(VoiceList* voiceLst);
    const string* GetUsr();
    static void LoopStore(void* obj);
private:
    const PacketInfo* pktInfo_;
    VoicePacket* voicePkt_;
    //UsrAddrMap* usrAddrTable_;
    UsrVoiceMap usrVoiceTable_;
    string scrIpPort_;
    UcHead* ucHead_;
    list<VoiceList*> storeBuf_;
    boost::mutex bufMut_;
};

#endif
