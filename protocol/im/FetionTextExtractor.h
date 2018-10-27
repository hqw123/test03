#ifndef FETION_TEXT_EXTRACTOR
#define FETION_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"
#include <boost/regex.hpp>
#include <string>

struct FetionMsg {
	char *from;
	char *text;
};

//-----------------------------------------------------------------------
// Class Name  : FetionTextExtractor
// Interface   : IsImText
// Description : The class processes the text messages from Fetion.
//               It checks the packets if are from Fetion. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class FetionTextExtractor:public BaseTextExtractor {
public:
	FetionTextExtractor();
	virtual ~ FetionTextExtractor();
	// Implement the pure virtual function of base class.
	bool IsImText(PacketInfo * pktInfo);

private:
	bool MatchFetion();
	MsgNode *CreateMsgNode(boost::cmatch & matchedStr, u_short from, u_short to, unsigned int ip, u_short port);
	MsgNode *CreateLoginNode(boost::cmatch & matchedStr, u_short from, unsigned int ip, u_short port);
	MsgNode *CreateLogoutNode(boost::cmatch & matchedStr, unsigned int ip, u_short port);
	void StoreMsg2DB(MsgNode * msgNode);

private:
	// The rule of regular expression to match a message sending from an address.
	boost::regex * sendRule_;
	// The rule of regular expression to match a message receiving from an address.
	boost::regex * recvRule_;
	boost::regex * loginRule_;
	boost::regex * logoutRule_;
	boost::regex * v10listRule_;
	boost::regex * v10qunRule_;
	boost::regex * v10userRule_;
	boost::regex * v10phoneRule_;
	char DIRECTORY[255];
};

#endif /* FETION_TEXT_EXTRACTOR */
