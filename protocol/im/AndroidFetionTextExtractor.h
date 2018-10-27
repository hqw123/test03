                                                                   

#ifndef AFETION_TEXT_EXTRACTOR
#define AFETION_TEXT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>

using namespace std;

//-----------------------------------------------------------------------
// Class Name  : AndroidFetionTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Fetion.
//               It checks the packets if are from Fetion. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class AndroidFetionTextExtractor : public BaseTextExtractor
{
public:
    AndroidFetionTextExtractor();
    virtual ~AndroidFetionTextExtractor();
    // Implement the pure virtual function of base class.
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchFetion();
//    MsgNode* CreateMsgNode(boost::cmatch& matchedStr, u_short from, u_short to, u_int ip, u_short port);
    MsgNode* CreateMsgNodeA(boost::cmatch& matchedStr, u_short from, u_short to, u_int ip, u_short port);
//    MsgNode* CreateLoginNode(boost::cmatch& matchedStr, u_short from, u_int ip, u_short port);
    MsgNode* CreateMLoginNode(boost::cmatch& matchedStr, u_short from, u_int ip, u_short port);
    void StoreMsg2DB(MsgNode* msgNode);
    void StoreAccount2DB(MsgNode* msgNode);
private:
    // The rule of regular expression to match a message sending from an address.
/////////////////////////////////////////////android
    boost::regex* MRecvRule_;
    boost::regex* MSendRule_;
    boost::regex* MLoginRule_;
    boost::regex* MQunRule_;
//////////////////////////////////////////////////////
    // The rule of regular expression to match a message receiving from an address.
    boost::regex* v10listRule_;
    boost::regex* v10qunRule_;
    boost::regex* v10userRule_;
    boost::regex* v10phoneRule_;
    char DIRECTORY[255];
};
#endif
// End of file
