#ifndef BASE_GAME_EXTRACTOR
#define BASE_GAME_EXTRACTOR
//#include "PacketParser.h"
#include "PacketInfo.h"
#include "Public.h"
#include "XmlStorer.h"
#include "Buffer.h"
#include "Occi.h"
//#include "../clue/Clue.h"
//#include "threadpool/include/threadpool.hpp"
// Compiling with -lboost_thread.
#include <boost/thread/mutex.hpp>
#include <string>
#include <fstream>
#include <set>

using namespace std;

typedef void (*SessionProc)(MsgNode*&, void*);


class BaseGameExtractor
{
public:
    BaseGameExtractor();
    virtual ~BaseGameExtractor();
    // Each derivative class should implement this interface.
    virtual bool IsImText(PacketInfo* pktInfo) = 0;
    void OnSysClosed();
    bool IsSysClosed();
    void AddFilterPort(int port);
    void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing);
protected:
    void PushNode(MsgNode* msgNode);
    void RegSessionFunc(SessionProc sessionProc);
private:
    // Static function for thread creation.
    static void LoopStore(void* obj);
    void CheckBuf();
    void MoveDataFile();
    void StoreMsg2Xml(MsgNode* msgNode);
    void StoreMsg2DB(MsgNode* msgNode, u_int clueId);
    void ProcessSession(MsgNode*& msgNode);
protected:
    u_int protoType_;
    u_int protoId_;
    //oracle::occi::Statement* stmt_;
    u_int devNum_;
    PacketInfo* pktInfo_;
    SessionProc sessionProc_;
    char tableName_[20];
    char dataFile_[160];
    set<u_short> portSet_;
    boost::mutex setMut_;
    bool isRunning_;
    u_int attachSize_;
    bool isDeepParsing_;
private:
    // The mutex for message buffer. (Need Boost lib)
    //boost::mutex bufMut_;
    // Thread pool. (Need Boost lib)
    //boost::threadpool::pool threadPool_;
    // Map each chat session with IP and port.
    //map<string, Session*>* sessionMap_;
    // Message buffer.
    Buffer<MsgNode*>* msgBuf_;
    // Xml file handler.
    XmlStorer xmlStorer_;
    boost::mutex sigMut_;
    bool sysClosed_;
    u_short msgNum_;
    fstream file_;
};

#endif
// End of file
