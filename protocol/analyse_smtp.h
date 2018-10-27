//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BAIHONG Information Security Techology CO.,
//
//------------------------------------------------------------------------
//
// Module Name      :analyse_smtp.h
//
//------------------------------------------------------------------------
// Notes:
//      
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 080928   Initial
// $d1= -------- 1.1  002 081006   Add Function is_smtp
//
//------------------------------------------------------------------------


#ifndef ANALYSE_SMTP
#define ANALYSE_SMTP

#include "ring_util.h"
#include "threadpool/include/threadpool.hpp"
#include <set>
#include "PacketParser.h"
#include "sniffer_header.h"
// using namespace std;

typedef struct packet_element_smtp{
	uint32_t the_seq;
	string packet;
	uint32_t next_seq;
}Pack_Elem_smtp;
 


typedef std::vector<string> NameVector_smtp;
typedef std::map<uint64_t,string> NameMap_smtp;
typedef std::map<uint64_t,NameVector_smtp> Map_Vector_smtp;

// added
typedef std::vector<Pack_Elem_smtp> PackVector_smtp;
typedef std::map<uint64_t,PackVector_smtp> Map_Pack_smtp;




class SMTP
{
	public:
		static NameMap_smtp email_smtp;
		static Map_Pack_smtp smtp_email_contents;
		static Map_Pack_smtp smtp_lost_contents;
		static Map_Vector_smtp smtp_userinfo;
	public:
		SMTP() ;
		~SMTP() ;
	//void analyse_smtp(struct pfring_pkthdr* header, const struct sniff_ip* ip, const struct sniff_tcp* tcp, u_char*  payload);
		bool analyse_smtp(PacketInfo* pktInfo);
		static string smtp_task(Ring_Util& util, const struct pcap_pkthdr_n* header, uint64_t dip_port);
		void get_ds_sock(const struct iphdr* ip, const struct tcphdr* tcp, uint64_t& sip_port, uint64_t& dip_port);

		void clear_info();
		void AddFilterPort(int port);
		void ClearFilterPort();
		void SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing);

		void init(PacketInfo* pktInfo);
		bool analyse_server();
		void analyse_client();

		void save_emailsub(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info);
		void save_emailfrom(NameMap_smtp& userinfo,const uint64_t& ip_port, const string& pack_info);
		void save_emailto(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info);
		void save_emailcc(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info);
		

	private:
		set<u_short> portSet_;
		boost::mutex setMut_;
		bool isRunning_;
		u_int attachSize_;
		bool isDeepParsing_;
		static char mac_[20];
		
		bool  s_to_c;
		const struct pcap_pkthdr_n* header;
		struct iphdr* ip;
		struct tcphdr* tcp;
		u_char*  payload;
		u_char* mac;
		time_t  timeVal;
		Pack_Elem_smtp packet_element; 
		
		Ring_Util util;
		int size_payload;
		string pack_info;
		uint64_t dip_port, sip_port;
		unsigned int   srcIpv4;
		unsigned int   destIpv4;
	private:
		char* ParseMac(const u_char* packet);
};

#endif
// end of file

