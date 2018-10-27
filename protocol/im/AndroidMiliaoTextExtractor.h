                                                                   

#ifndef AMILIAO_TEXT_EXTRACTOR
#define AMILIAO_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>

using namespace std;

struct Miliao_Login{
	string from;
};

//-----------------------------------------------------------------------
// Class Name  : AndroidMiliaoTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Fetion.
//               It checks the packets if are from Fetion. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class AndroidMiliaoTextExtractor : public BaseTextExtractor
{
public:
    AndroidMiliaoTextExtractor();
    virtual ~AndroidMiliaoTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchMiliao();
    void StoreMsg2DB(MsgNode* msgNode);
    bool CheckPort(u_short port);
private:
    boost::regex* loginRule_;
    boost::regex* sendrule_;
    map<uint64_t,Miliao_Login>keyMap;
    char DIRECTORY[255];
};
#endif
// End of file
