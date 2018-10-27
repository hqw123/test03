#ifndef QQ_FILE_EXTRACTOR
#define QQ_FILE_EXTRACTOR
#include "PacketInfo.h"
#include "DampedMap.h"
#include "FileStream.h"
#include "BaseFileExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <iostream>
//add 20100409
#include <map>
using namespace std;
struct QQFile{
    u_int fileNum;
   
    char* fileData;
    u_int fileDataLen;
};

struct Files{
    char* filename;
    u_int filesize;  
};
class QQFileExtractor : public BaseFileExtractor

{
public:
	QQFileExtractor();
    virtual ~QQFileExtractor();
    bool IsFile(PacketInfo* pktInfo);
private:
    bool IsImFileUdp();
    void StoreMsg2DB(MsgNode* msgNode);
    bool CreatFile(char* fileName);
    void StoreToFile(char* body, u_int bodyLen);
    void CloseFile();
    bool IsQQ09UdpFile();
    int Decomp_gzip(char *src, unsigned int len, char **dest);
    int Decomp_gzip_1(char *src, unsigned int len, char **dest);
    int Decomp_gzip_2(char *src, unsigned int len, char **dest);
    int Decomp_gzip_3(char *src, unsigned int len, char **dest);
    //void PushMassage(char* srcFileName, const char* timeStr);
private:
    //DampedMap<uint64_t>* dampedMap_;
    u_short command;
    char filePath_[96];
    map<u_int,QQFile>fileMap;
    char* fileName_;
    map<uint64_t,Files> my_map;
    std::ofstream* file_;
    char DIRECTORY[255];
    char SUB_DIREC[255];
};

#endif
// End of file.
