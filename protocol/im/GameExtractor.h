#ifndef GAME_EXTRACTOR
#define GAME_EXTRACTOR

#include "BaseGameExtractor.h"

#include <boost/regex.hpp>
#include <string>

using namespace std;

class GameExtractor : public BaseGameExtractor
{
public:
    GameExtractor();
    virtual ~GameExtractor();
    
    bool IsImText(PacketInfo* pktInfo);
private:
    bool MatchWOW();
    bool MatchTLBB();
    bool MatchYOU();
    bool MatchLTSJ();
    bool MatchRXJH();
    bool MatchWMSJ();
    bool MatchXQJSJ();
    bool MatchZX2();
	bool MatchCGA();
	bool MatchVS();
	bool MatchOurGame();
	bool MatchChinaGame();
	bool MatchGame4399();
	bool MatchQQGame();
	bool MatchPOPKART();
    MsgNode* CreateLoginNode(char* user ,char* passwd ,u_int type);
    
private:
	boost::regex* vsUserRule_;
	boost::regex* chinaGameUserRule_;
	boost::regex* game4399UserRule_;
	boost::regex* popkartRule_;
	char DIRECTORY[255];
};

#endif
// End of file
