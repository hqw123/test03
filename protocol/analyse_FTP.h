#ifndef ANALYSE_FTP
#define ANALYSE_FTP

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>
#include <map>
#include <string>
#include <boost/unordered_map.hpp>

#include "PacketParser.h"
#include "Public.h"

using namespace std;
struct USERINFO
{
	char* user;
	char* pass;
	uint64_t trans_port;
};

struct FTPFILE
{
	char* filename;
	string filedata;
	u_int datalen;
	char* user;
	char* pass;
};

class FTP
{
	public:
		FTP();
		virtual ~FTP();
		bool IsFTP(PacketInfo* pktInfo);
	private:
		bool IsFtpTcp();
		char* ParseMac(const u_char* packet, char* mac);
		uint64_t makeHashkey(PacketInfo *pkt, bool reverse)
		{ return reverse ? (((uint64_t)(pkt->srcIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->destPort << 16 | (uint32_t)pkt->srcPort)):\
            (((uint64_t)(pkt->destIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->srcPort << 16 | (uint32_t)pkt->destPort)); }

	private:
		//map<uint64_t,USERINFO>UserMap;
		//map<uint64_t,FTPFILE>fileMap;
		boost::unordered_map<uint64_t, USERINFO> UserMap;
		boost::unordered_map<uint64_t, FTPFILE> fileMap;
		char DIRECTORY[255];
		char SUB_DIREC[255];
		char filePath_[96];
		u_int command;
		PacketInfo* pktInfo_;
		u_int attachSize_;
};

#endif
// End of file.
