                                                                   

#ifndef WANGWANG_TEXT_EXTRACTOR
#define WANGWANG_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>
#include <map>

using namespace std;
struct LoginFrom{
	string from;
};
//-----------------------------------------------------------------------
// Class Name  : WangwangTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Wangwang.
//               It checks the packets if are from Wangwang. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class WangwangTextExtractor : public BaseTextExtractor
{
public:
    WangwangTextExtractor();
    virtual ~WangwangTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    void StoreMsg2DB(MsgNode* msgNode);
    
private:
    // The rule of regular expression to match a message sending from an address.

    map<uint64_t,LoginFrom>keyMap;
    char DIRECTORY[255];
};

#endif
// End of file
