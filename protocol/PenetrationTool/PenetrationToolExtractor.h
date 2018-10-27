#ifndef PENETRATIONTOOL_EXTRACTOR
#define PENETRATIONTOOL_EXTRACTOR

#include "BaseToolsExtractor.h"

#include <boost/regex.hpp>
#include <string>

using namespace std;

class PenetrationToolExtractor : public BaseToolsExtractor
{
	public:
		PenetrationToolExtractor();
		virtual ~PenetrationToolExtractor();
    
		bool IsTool(PacketInfo* pktInfo);
	private:
		bool MatchUnBounded();
		bool MatchFreeGate();
		bool MatchSocks();
		bool MatchHttps();
		bool MatchDynaPass();//lihan 2017.1.23 dwt
		bool MatchFFvpn(); //lihan 2017.1.23 FFvpn
		bool MatchFQRouter(); // jacky Thu Mar 16 02:39:23 PDT 2017
		bool MatchAppCobber(); // jacky Thu Mar 16 04:15:10 PDT 2017
		bool MatchGAE(); // jacky Thu Mar 16 04:37:37 PDT 2017
		bool Matchsupervpn(); //add by hqw 
		bool Matchvpnunlimited(); //add by hqw
		bool Matcharkvpn();//add by hqw
// 		bool MatchFreeU();
// 		bool MatchDynapass();
		MsNode* CreateNode(u_int type);
		void StoreMsg2DB(MsNode* msgNode);
		void StoreMsg2DB2(MsNode* msgNode);
		void StoreMsg2DB2(MsNode* msgNode,int affixFilag);
	private:
		char DIRECTORY[255];
		
};

#endif
// End of file
