#ifndef WAVE_H
#define WAVE_H
#include <fstream>

using namespace std;

const int RIFF_SIZE_POS = 4;
const int DATA_SIZE_POS = 40;
const int WAVE_POS = 8;
const int WAVE_HLEN = 44;

struct WaveHead { 
    //   RIFF_TRUNK
    u_char     riffID[4];      //   'R','I','F','F' 
    u_int     riffSize; 
    u_char     riffFmt[4];     //   'W','A','V','E' 
    //   FMT_TRUNK 
    u_char     fmtID[4];       //   'f','m','t',' ' 
    u_int     fmtSize;     
    u_short    fmtTag; 
    u_short    channels; 
    u_int     samplesPerSec; 
    u_int     avgBytesPerSec; 
    u_short    blockAlign; 
    u_short    bitsPerSample;
    /*
    u_short    ultraMsg; 
    //   FACT_TRUNK 
    u_char     factID[4];      //   'f','a','c','t' 
    u_int     factSize; 
    */
    //   DATA_TRUNK 
    u_char     dataID[4];      //   'd','a','t','a' 
    u_int     dataSize; 
};
 
class Wave
{
public:
    Wave();
    virtual ~Wave();
    static int InitWaveHdr(WaveHead* wavHead, const u_short channels, const u_int sampPerSec, const u_short bit, const u_int dataLen);
    static ofstream* StoreWaveHdr(const char* filename, const WaveHead* wavHead);
    static bool StoreWaveData(ofstream* filename, const u_char* data, u_short dataLen);
    static bool AddWaveData(const char* filename, const u_char* data, u_short dataLen);
};

#endif
