                                                                   

#ifndef GTALK_TEXT_EXTRACTOR
#define GTALK_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>
#define MESSAGE_LEN 100

using namespace std;
struct Log{
	string from;
};

typedef struct Message
{
	unsigned int srcIpv4;
	u_int32_t seq;
	u_int32_t next_seq;
}Message;

//-----------------------------------------------------------------------
// Class Name  : GtalkTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Gtalk.
//               It checks the packets if are from Gtalk. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class GtalkTextExtractor : public BaseTextExtractor
{
public:
    GtalkTextExtractor();
    virtual ~GtalkTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchGtalk();
    void StoreMsg2DB(MsgNode* msgNode);
private:
    // The rule of regular expression to match a message sending from an address.
    boost::regex* setRule_;
    boost::regex* loginRule_;

    boost::regex* sendRule_;
    boost::regex* senddRule_;
    boost::regex* recvRule_;
    boost::regex* recvvRule_;
    boost::regex* id16Rule_;

    boost::regex* itemRule_;
    boost::regex* itemmRule_;
    unsigned int sendSrcIpv4_;
    u_int32_t sendSeq_;
    char* sendBody_;
    unsigned short int sendBodyLen_;
    unsigned int recvSrcIpv4_;
    u_int32_t recvSeq_;
    char* recvBody_;
    unsigned short int recvBodyLen_;
    map<uint64_t,Log>keyMap;
    char DIRECTORY[255];

    PacketInfo* message[MESSAGE_LEN];
    Message message_send;
    Message message_recv;
    int message_int;

    int off_line_;
    int len_;
    int f_mes_;
};

#endif
// End of file
