#ifndef MSN_FILE_EXTRACTOR
#define MSN_FILE_EXTRACTOR
#include "PacketInfo.h"
//#include "DampedMap.h"
//#include "FileStream.h"
#include "BaseFileExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <iostream>

#include <map>
#include <string>
using namespace std;
/*struct MSNFile{
    //uint32_t the_seq;
    char* fileBody;
    u_int fileBodylen;
    uint32_t next_seq;
}*/
struct MSNUDPFile{
   u_int filebodylen;
   char* filebody;
};
class MSNFileExtractor : public BaseFileExtractor

{
public:
    MSNFileExtractor();
    virtual ~MSNFileExtractor();
    bool IsFile(PacketInfo* pktInfo);
private:
   
    void StoreMsg2DB(MsgNode* msgNode);
   
    bool MatchMSNFile();
    bool MatchMSNUDPFile();
	bool MatchMSNHTTPSFile();
    
private:
    map<uint64_t,char*>keyMap;
    map<u_int,MSNUDPFile>my_map;
    //map<uint32_t,MSNFile>fileMap;
    //boost::regex* fileRule_;
    std::ofstream* file_;
    string s;
    char filePath_[96];
    char DIRECTORY[255];
    char SUB_DIREC[255];

	//PublicOcci* occi_;
};

#endif
// End of file.
