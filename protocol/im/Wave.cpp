#include <iostream>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>

#include "Wave.h"

Wave::Wave()
{
}

Wave::~Wave()
{
}

int Wave::InitWaveHdr(WaveHead* wavHead, const u_short channels, const u_int sampPerSec, const u_short bit, const u_int dataLen)
{
    //RIFF_TRUNK
    memcpy(wavHead->riffID, "RIFF", 4);
    wavHead->riffSize = 36 + dataLen;
    memcpy(wavHead->riffFmt, "WAVE", 4);

    //FMT_TRUNK
    memcpy(wavHead->fmtID, "fmt ", 4);
    wavHead->fmtSize = 16; //No ultra message.
    wavHead->fmtTag = 0x0001;
    wavHead->channels = channels;
    wavHead->samplesPerSec = sampPerSec;
    wavHead->avgBytesPerSec = channels * sampPerSec * bit / 8;
    wavHead->blockAlign = channels * bit / 8;
    wavHead->bitsPerSample = bit;

    //DATA_TRUNK
    memcpy(wavHead->dataID, "data", 4);
    wavHead->dataSize = dataLen;

    return WAVE_HLEN;
}

ofstream* Wave::StoreWaveHdr(const char* filename, const WaveHead* wavHead)
{
    ofstream* wavfile = new ofstream(filename, ios::out | ios::binary);
    if (wavfile) {
        wavfile->write(reinterpret_cast<const char*>(wavHead), WAVE_HLEN);
    }

    return wavfile;
}

bool Wave::StoreWaveData(ofstream* file, const u_char* data, u_short dataLen)
{
    bool storeOkay = true;
    if (!file) {
        storeOkay = false;
    } else {
        file->write(reinterpret_cast<const char*>(data), dataLen);
    }

    return storeOkay;
}

bool Wave::AddWaveData(const char* filename, const u_char* data, u_short dataLen)
{
    bool storeOkay = true;
    int wavfile;
    void* wavMem;
    struct stat statbuf;

    //Opem wav file.
    if ((wavfile = open(filename, O_RDWR)) < 0) {
        storeOkay = false;
    //Get file information, and check the file lenth whether is more than wave head.
    } else if (fstat(wavfile, &statbuf) < 0 && statbuf.st_size < WAVE_HLEN) {
        storeOkay = false;
    //File memory map.
    } else if ((wavMem = mmap(0, WAVE_HLEN, PROT_READ | PROT_WRITE, MAP_SHARED, wavfile, 0)) == MAP_FAILED) {
        storeOkay = false;
    //Check the file whether is wave format.
    } else if (memcmp(reinterpret_cast<char*>(wavMem), "RIFF", 4) || memcmp(reinterpret_cast<char*>(wavMem) + WAVE_POS, "WAVE", 4)){
        storeOkay = false;
    } else {
        u_int riffSize;
        u_int dataSize;
        //Get the original riff size and data size,
        memcpy(&riffSize, reinterpret_cast<char*>(wavMem) + RIFF_SIZE_POS, sizeof(u_int));
        memcpy(&dataSize, reinterpret_cast<char*>(wavMem) + DATA_SIZE_POS, sizeof(u_int));
        //Update the new size.
        riffSize += dataLen;
        dataSize += dataLen;
        //Sync with the file in disk.
        memcpy(reinterpret_cast<char*>(wavMem) + RIFF_SIZE_POS, &riffSize, sizeof(u_int));
        memcpy(reinterpret_cast<char*>(wavMem) + DATA_SIZE_POS, &dataSize, sizeof(u_int));
        msync(wavMem, WAVE_HLEN, MS_SYNC);
        munmap(wavMem, WAVE_HLEN);
        //Append the wave data to end of file.
        ofstream wavfile(filename, ios::app | ios::binary);
        wavfile.write(reinterpret_cast<const char*>(data), dataLen);
        wavfile.close();
    }

    return storeOkay;
}

