#ifndef DNS_SERVER_UTIL_H
#define DNS_SERVER_UTIL_H





#ifdef __cplusplus
extern "C" {
#endif

struct ServerIP{
	int effective;
	unsigned int ip[10];
	unsigned int count[10];
	char devIN[64];
	char devOUT[64];
	char domain[256];
	unsigned short transID;
	unsigned short port;
	unsigned int dnsIP;
	
};

struct Address{
	unsigned int ipSrc;
	unsigned int ipDst;
	char macSrc[6];
	char macDst[6];
	char data[128];
	short offset;
	int len;	
};

struct Link{
	int effecitive;
	int len[2];
	char data[2][512];
};

struct Ip{
	int effective;
	int len[2];
	char data[2][284];
};

struct Udp{
	int effective;
	unsigned short len[2];
	char data[2][264];
};

struct Dns{
	short len;
	char data[256];
};

struct DnsPkt{
	int effective;
	struct Link link;
	struct Ip ip;
	struct Udp udp;
	struct Dns dns;
	unsigned int dnsIP;
};



int buildDns();
int buildUdp(unsigned int ipsrc,unsigned int ipdst,int index);
int buildIp(unsigned int ipsrc,unsigned int ipdst,int index);
int buildLink(const struct Address* address,char* macSrc,char* macDst,int index);
int getSSLstatus();
void* runA(void* dat);
void* runB(void* dat);

#ifdef __cplusplus
}
#endif

#endif

