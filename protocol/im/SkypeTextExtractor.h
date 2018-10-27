                                                                   

#ifndef SKYPE_TEXT_EXTRACTOR
#define SKYPE_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>

using namespace std;

//-----------------------------------------------------------------------
// Class Name  : SkypeTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Skype.
//               It checks the packets if are from Skype. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class SkypeTextExtractor : public BaseTextExtractor
{
public:
    SkypeTextExtractor();
    virtual ~SkypeTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchSkype();
    void StoreMsg2DB(MsgNode* msgNode);
private:
    // The rule of regular expression to match a message sending from an address.
 
    boost::regex* loginRule_;
    boost::regex* logintRule_;
    char DIRECTORY[255];
};

#endif
// End of file
