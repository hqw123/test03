#ifndef VOICE_MAP
#define VOICE_MAP

#include <pcap.h>
#include "DampedMap.h"
#include "RtpParser.h"

struct IpPair
{
    IpPair(const u_int  srcIp, const u_short srcPort, const u_int  destIp, const u_short destPort);
    bool operator <(const IpPair& ipPair) const;
    u_int  bigIp;
    u_short bigPort;
    u_int  smallIp;
    u_short smallPort;
};

const u_short RTP_BUF_NUM = 4;
const u_short FILE_NAME_LEN = 256;

class VoiceSession : public DampedData
{
public:
    VoiceSession(void* obj, const char* filePath);
    virtual ~VoiceSession();
    bool AddPacket(RtpPkt* rtpPkt);
private:
    bool IsNextPkt(RtpPkt* rtpPkt);
    bool CreatePcapFile();
    void ClosePcapFile();
    void SaveMsg();
private:
    void* obj_;
    u_int rtpNum_;
    pcap_dumper_t* voiceDumper_;
    rtphdr lastComingRtp_;
    u_int srcIp_;
    u_short srcPort_;
    u_int destIp_;
    u_short destPort_;
    u_char srcMac_[6];
    u_char destMac_[6];
    char fileName_[FILE_NAME_LEN];
    const char* filePath_;
    bool isComing_;
};

#endif

// End of file
