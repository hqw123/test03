//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BAIHONG Information Security Techology CO.,
//
//------------------------------------------------------------------------
//
// Module Name      : DNSSpoof.h
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class DNSSpoof.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100527  wu zhonghua Initial
//
//------------------------------------------------------------------------

#ifndef DNS_SPOOF
#define DNS_SPOOF
#include "PacketParser.h"
#include <libnet.h>

#ifndef DEV_LENTH
#define DEV_LENTH 50
#endif
//#include <occi.h>

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

typedef enum __ns_class {
	ns_c_invalid = 0,	/* Cookie. */
	ns_c_in = 1,		/* Internet. */
	ns_c_2 = 2,		/* unallocated/unsupported. */
	ns_c_chaos = 3,		/* MIT Chaos-net. */
	ns_c_hs = 4,		/* MIT Hesiod. */
	/* Query class values which do not appear in resource records */
	ns_c_none = 254,	/* for prereq. sections in update requests */
	ns_c_any = 255,		/* Wildcard match. */
	ns_c_max = 65536
} ns_class;

/*
 * Currently defined opcodes.
 */
typedef enum __ns_opcode {
	ns_o_query = 0,		/* Standard query. */
	ns_o_iquery = 1,	/* Inverse query (deprecated/unsupported). */
	ns_o_status = 2,	/* Name server status query (unsupported). */
	/* Opcode 3 is undefined/reserved. */
	ns_o_notify = 4,	/* Zone change notification. */
	ns_o_update = 5,	/* Zone update message. */
	ns_o_max = 6
} ns_opcode;


/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
	ns_t_invalid = 0,	/* Cookie. */
	ns_t_a = 1,		/* Host address. */
	ns_t_ns = 2,		/* Authoritative server. */
	ns_t_md = 3,		/* Mail destination. */
	ns_t_mf = 4,		/* Mail forwarder. */
	ns_t_cname = 5,		/* Canonical name. */
	ns_t_soa = 6,		/* Start of authority zone. */
	ns_t_mb = 7,		/* Mailbox domain name. */
	ns_t_mg = 8,		/* Mail group member. */
	ns_t_mr = 9,		/* Mail rename name. */
	ns_t_null = 10,		/* Null resource record. */
	ns_t_wks = 11,		/* Well known service. */
	ns_t_ptr = 12,		/* Domain name pointer. */
	ns_t_hinfo = 13,	/* Host information. */
	ns_t_minfo = 14,	/* Mailbox information. */
	ns_t_mx = 15,		/* Mail routing information. */
	ns_t_txt = 16,		/* Text strings. */
	ns_t_rp = 17,		/* Responsible person. */
	ns_t_afsdb = 18,	/* AFS cell database. */
	ns_t_x25 = 19,		/* X_25 calling address. */
	ns_t_isdn = 20,		/* ISDN calling address. */
	ns_t_rt = 21,		/* Router. */
	ns_t_nsap = 22,		/* NSAP address. */
	ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	ns_t_sig = 24,		/* Security signature. */
	ns_t_key = 25,		/* Security key. */
	ns_t_px = 26,		/* X.400 mail mapping. */
	ns_t_gpos = 27,		/* Geographical position (withdrawn). */
	ns_t_aaaa = 28,		/* Ip6 Address. */
	ns_t_loc = 29,		/* Location Information. */
	ns_t_nxt = 30,		/* Next domain (security). */
	ns_t_eid = 31,		/* Endpoint identifier. */
	ns_t_nimloc = 32,	/* Nimrod Locator. */
	ns_t_srv = 33,		/* Server Selection. */
	ns_t_atma = 34,		/* ATM Address */
	ns_t_naptr = 35,	/* Naming Authority PoinTeR */
	ns_t_kx = 36,		/* Key Exchange */
	ns_t_cert = 37,		/* Certification record */
	ns_t_a6 = 38,		/* IPv6 address (deprecates AAAA) */
	ns_t_dname = 39,	/* Non-terminal DNAME (for IPv6) */
	ns_t_sink = 40,		/* Kitchen sink (experimentatl) */
	ns_t_opt = 41,		/* EDNS0 option (meta-RR) */
	ns_t_tsig = 250,	/* Transaction signature. */
	ns_t_ixfr = 251,	/* Incremental zone transfer. */
	ns_t_axfr = 252,	/* Transfer zone of authority. */
	ns_t_mailb = 253,	/* Transfer mailbox records. */
	ns_t_maila = 254,	/* Transfer mail agent records. */
	ns_t_any = 255,		/* Wildcard match. */
	ns_t_zxfr = 256,	/* BIND-specific, nonstandard. */
	ns_t_max = 65536
} ns_type;

//-----------------------------------------------------------------------
// Class Name  : DNSSpoof
// Interface   : ParseDNSQueries
// Description : Parse DNS Queries ,and send fake DNS answers.
//-----------------------------------------------------------------------
class DNSSpoof
{
	public:
		DNSSpoof();
		virtual ~DNSSpoof();
		bool ParseDNSQueries(PacketInfo* pktInfo);
		
	private:
		int SendFakeDNS(unsigned int srcIP,unsigned int destIP,unsigned short int updDestPort,unsigned char *destMac,unsigned char *srcMac,unsigned short int checkID, unsigned char *data, size_t datalen, unsigned short int addi_rr,unsigned short ethType,unsigned char * ethPalyload,unsigned short ethPalyloadLen);
		char* ParseMac(const u_char* packet, char* mac);
		
	private:
   
		struct DNShdr * dnsHdr;
		char payload[512];
		libnet_t *libnetL2;
		char sendDevice[50];
		char dnsIp[21];
	
};

#endif
