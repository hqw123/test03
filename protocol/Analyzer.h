#ifndef _ANALYZER_H_
#define _ANALYZER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_pkthdr_n {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

#ifdef __cplusplus
extern "C"
{
#endif
    extern int analyzer_init(int num);
    extern int analyzer_cleanup(void);
    extern int analyzer_main(const char *packet, const struct pcap_pkthdr_n *pkt_hdr);
#ifdef __cplusplus
}
#endif

#endif

