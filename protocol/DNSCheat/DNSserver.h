#ifndef LZ_DNS_SERVER_H
#define LZ_DNS_SERVER_H

#include "DNSutil.h"


#ifndef SIP_TYPE_CARD
#define SIP_TYPE_CARD 1
#endif
#ifndef SIP_TYPE_DOMAIN
#define SIP_TYPE_DOMAIN 2
#endif


class DNSserver{
	private:
		struct ServerIP* sip;
		struct DnsPkt* pkt;
		int  type;
	public:
		DNSserver();
		int setDomain(const char* domain,int type);
		int run(int sleepSec);
		int setDev(const char* dev,int type);
		int setDnsIP(unsigned int ip);
};


#endif

