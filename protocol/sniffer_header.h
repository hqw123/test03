#ifndef _SNIFFER_
#define _SNIFFER_

#define APP_NAME 	"snifferx"
#define APP_DESC 	"Sniffer example using libpcap"
#define APP_COPYRIGHT 	"Copyright (c) 2010 Baihong CORPORATION"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <map>
#include <vector>
#include <iostream>
#include <algorithm>
#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <fstream>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <sys/stat.h>
#include <sys/mman.h>  /* for mmap and munmap */
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <iconv.h>
#include <libxml/parser.h>

//#include "oracle.h"
//#include "im/Occi.h"
//#include "clue/Clue.h"
//#include "clue/ProtocolID.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet address are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet IP are 4 bytes */
#define ETHER_IP_LEN 4

/* define packet kind*/
#define UNKNOWN_PACKET 0
#define SMTP_PACKET    1
#define POP3_PACKET    2
#define FTP_PACKET     3
#define MSN_PACKET     4
#define HTTP_PACKET    5
#define HTTPS_PACKET   6
#define TELNET_PACKET  7
#define QQ_PACKET      8
#define UC_PACKET      9



/* Ethernet header */
struct sniff_ethernet{
	u_char  ether_dhost[ETHER_ADDR_LEN];  // destination host address
	u_char  ether_shost[ETHER_ADDR_LEN];  // source host address
	u_short ether_type;		      // IP? ARP? RARP? etc
};

/* IP_header */
struct sniff_ip{
	u_char  ip_vh1;			      // version << 4 | header length >> 2
	u_char  ip_tos;			      // type of service
	u_short ip_len;			      // total length
	u_short ip_id;			      // identification
	u_short ip_off;			      // fragment offset field
	#define IP_RF 0x8000		      // reserved fragment flag
	#define IP_DF 0x4000		      // don't fragment flag
	#define IP_MF 0x2000		      // more fragments flag
	#define IP_OFFMASK 0x1fff	      // mask for fragmenting bits
	u_char  ip_ttl;			      // time to live
	u_char  ip_p;			      // protocol
	u_short ip_sum;			      // checksum
	struct  in_addr ip_src, ip_dst;	      // source and destination address
};

#define IP_HL(ip) ( ((ip)->ip_vh1) & 0x0f )
#define IP_V(ip)  ( ((ip)->ip_vh1) >> 4   )

/* TCP_header */
struct sniff_tcp{
	u_short th_sport;		      // source port
	u_short th_dport;		      // destination port
	uint32_t th_seq;			    // sequence number
	uint32_t th_ack;			    // acknowledgement number
	u_char  th_offx2;		      // data offset, rsvd
	#define TH_OFF(th) ( ((th)->th_offx2 & 0xf0) >> 4 )
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS ( TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR )
	u_short th_win;			       // window
	u_short th_sum;			       // checksum
	u_short th_urp;			       // urgent pointer
};

/* TCP fake header, used for checksum */
struct fake_tcphdr{
	u_int32_t saddr; 	         // source ip address
	u_int32_t daddr;           // destination ip address
	u_char ttl;				         // set zero
	u_char ptcl; 			         // protocol, set 6
	u_short tcp_len;           //TCP data length
};

/* ARP_header */
struct sniff_arp{
	u_short ar_hrd;			       // Type of hardware address
	u_short ar_pro;			       // Type of protocol address
	u_char  ar_hlen;		       // Length of hardware address
	u_char  ar_plen;		       // Length of protocol address
	u_short ar_optype;		     // ARP operation type
	u_char  ar_sadr[6];		     // Sender hardware address
	u_char  ar_sip[4];		     // Sender IP address
	u_char  ar_tadr[6];		     // Target hardware address
	u_char  ar_tip[4];		     // Target IP address
};

/* UDP_header */
struct sniff_udp{
	u_short  udp_sport;		     // Source port
	u_short  udp_dport;		     // Destination port
	u_short  udp_length;		   // UDP length
	u_short  udp_chksum;		   // UDP checksum
};

/* SSL Record header */
struct sniff_rssl{
	u_char  content_type;		   // the higher layer's protocol type
	u_char  major_version;		 // Indicates the major version of SSL in use. E.g.3
	u_char  minor_version;		 // Indicates the minor version of SSL in use. E.g.0
	u_char  hlen;		       // The length in bytes of the plain text fragment.  
	u_char  llen;		       // The length in bytes of the plain text fragment.  
	u_char handshake_type;		 // Type of SSL handshake protocol.  
};

/* SSL Handshake header(Client Hello) */
struct hssl_client_hello{
	u_char  type;		           // handshake type
	u_char  h_length;		     	 // handshake length(high byte)
	u_short l_length;		       // handshake length(low bytes)
	u_short version;				   // SSL version
	u_int32_t u_time;					 // gmt unix time
	u_char  content[28];			 // Random bytes
	u_char  len_session;			 // Session ID length
	u_short len_cipher_suite;	 // cipher suite length
	u_char  cipher_suite[22];			// cipher suites
	u_char  len_method;			   // compression method length
	u_char  cmps_method;			 // compress methods	
};

/* SSL Handshake header(Server Hello) */
struct hssl_svr_hello{
	u_char  type;		           // handshake type
	u_char  h_length;		       // handshake length(high byte)
	u_short l_length;		       // handshake length(low bytes)
	u_short version;				   // SSL version
	u_int32_t u_time;					 // gmt unix time
	u_char  content[28];			 // Random bytes
	u_char  len_session;			 // Session ID length
	u_short cipher_suite;			 // cipher suites
	u_char  cmps_method;			 // compress methods
};

/* SSL Handshake header(Certificate) */
struct hssl_certificate{
	u_char  type;		           // handshake type
	u_int32_t  length;		     // handshake length
	//TODO
};

/* SSL Handshake header(Client Key Exchange) */
struct hssl_key_exchange{
	u_char  type;		           // handshake type
	u_int32_t  length;		     // handshake length
	//TODO
};

/* SSL Handshake header(Server hello done) */
struct hssl_svr_done{
	u_char  type;		           // handshake type
	u_int32_t  length;		     // handshake length
	//TODO
};

struct deal_packet{
	u_char* arg;
	const struct pcap_pkthdr_n* hdr;
	const u_char* pack;
};

#endif
