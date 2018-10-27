
#ifndef GAMBLE_ACCOUNT_EXTRACTOR
#define GAMBLE_ACCOUNT_EXTRACTOR
//#include "PacketParser.h"
#include "BaseTextExtractor.h"
// Compiling with -lboost_regex.
#include <boost/regex.hpp>
#include <string>
#include <map>

using namespace std;
struct BjlCrypt
{
	string mkey;
	string crypt;	
};

//-----------------------------------------------------------------------
// Class Name  : GambleAccountExtractor
// Interface   : IsImText
// Description : The class processes the text messages from GambleAccount.
//               It checks the packets if are from GambleAccount. If so, stores
//               them into the message buffer. Meanwhile, there is a  
//               thread pool loops to get the messages from buffer, and
//               stores them into XML file.
//-----------------------------------------------------------------------
class GambleAccountExtractor : public BaseTextExtractor
{
	public:
		GambleAccountExtractor();
		virtual ~GambleAccountExtractor();
    // Implement the pure virtual function of base class.
		bool IsImText(PacketInfo* pktInfo);
	private:
		bool MatchSuncity();
		bool MatchBjl();
	private:
    // The rule of regular expression to match a message sending from an address.
		boost::regex* suncityRule_;
		char DIRECTORY[255];
		map<uint64_t,BjlCrypt> keyMap;
};

#endif
// End of file
