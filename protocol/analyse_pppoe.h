
#ifndef ANALYSE_PPPOE_T
#define ANALYSE_PPPOE_T
#include "sniffer_header.h"
#include "PacketParser.h"
#include <linux/if_pppox.h>
#include <string>
#include "ring_util.h"
//#define PROTOCOL_PPPOE    7
using std::string;

typedef struct PPPOE_ACCOUNT_INF{
	unsigned  char srcMac[6];
	string account;
	string pass;
}pppoe_account_inf;

typedef std::map<uint16_t,pppoe_account_inf> Map_session_accountInfo;

class ParsePPPOE
{
public:
	ParsePPPOE();
	virtual ~ParsePPPOE();
	void analyse_pppoe(PacketInfo* pktInfo);
public:
	Map_session_accountInfo map_session_accountInfo;  // store accountInfo(account/passs)
        pppoe_account_inf accountInfo_;

private:
	struct pppoe_hdr *pppoeHeader;
	void StoreData(unsigned int cap_time);
	void StoreData(struct in_addr IP,unsigned short int sID,unsigned int cap_time);
	char *ParseMac(const u_char* packet);
    char mac_[20];
    Ring_Util util_;
	unsigned int sum_count;
};

#endif  /*ANALYSE_PPPOE_T*/
