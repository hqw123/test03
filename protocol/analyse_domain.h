#ifndef ANALYSE_DOMAIN
#define ANALYSE_DOMAIN

#include "PacketParser.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "Public.h"
#include <iostream>
#include <map>
#include <string>

using namespace std;

struct DNShdr {
	unsigned short id;                /* DNS packet ID */
#ifdef WORDS_BIGENDIAN
   u_char  qr: 1;             /* response flag */
   u_char  opcode: 4;         /* purpose of message */
   u_char  aa: 1;             /* authoritative answer */
   u_char  tc: 1;             /* truncated message */
   u_char  rd: 1;             /* recursion desired */
   u_char  ra: 1;             /* recursion available */
   u_char  unused: 1;         /* unused bits */
   u_char  ad: 1;             /* authentic data from named */
   u_char  cd: 1;             /* checking disabled by resolver */
   u_char  rcode: 4;          /* response code */
#else /* WORDS_LITTLEENDIAN */
   u_char  rd: 1;             /* recursion desired */
   u_char  tc: 1;             /* truncated message */
   u_char  aa: 1;             /* authoritative answer */
   u_char  opcode: 4;         /* purpose of message */
   u_char  qr: 1;             /* response flag */
   u_char  rcode: 4;          /* response code */
   u_char  cd: 1;             /* checking disabled by resolver */
   u_char  ad: 1;             /* authentic data from named */
   u_char  unused: 1;         /* unused bits */
   u_char  ra: 1;             /* recursion available */
#endif
   unsigned short num_q;             /* Number of questions */
   unsigned short num_answer;        /* Number of answer resource records */
   unsigned short num_auth;          /* Number of authority resource records */
   unsigned short num_res;           /* Number of additional resource records */
};


class ANALYSEDOMAIN
{
	public:
		ANALYSEDOMAIN();
		virtual ~ANALYSEDOMAIN();
		bool IsDomain(PacketInfo* pktInfo);
	private:
		bool Match();
	//	char* ParseMac(const u_char* packet, char* mac);
	private:

		char DIRECTORY[255];

		PacketInfo* pktInfo_;
		//MySQL * sqlConn_;
        struct DNShdr * dnsHdr;
};

#endif
// End of file.
