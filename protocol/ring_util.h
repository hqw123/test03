//
// Copyright (C) 2010 BAIHONG! CORPORATION. All rights reserved.
// BAIHONG! PROPRIETARY/CONFIDENTIAL
//
//------------------------------------------------------------------------
//
// Module Name      :ring_util.h
//
//------------------------------------------------------------------------
// Notes:
//   Comment character code - EUC
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 080928  Initial
// $d1= -------- 1.1  002 081006  Add Function mkdir_for_today
// $d2= -------- 1.2  003 081012   Add Function write_info
// $d3= -------- 1.3  004 081110  Add Function parse_packet
// $d4= -------- 1.4  005 081125  Add Function is_ftp
// $d5= -------- 1.5  006 081129   Add Function validate_tcp_data
// $d6= -------- 1.6  007 081208   Add Function print_binary_line
// $d7= -------- 1.7  008 090302  Add Function save_emailinfo
// $d8= -------- 1.8  009 090330  Add Function Get_Current_Time
//
#ifndef RING_UTIL
#define RING_UTIL

#include "sniffer_header.h"
//#include "global.h"

using namespace std;

typedef struct packet_element{
	uint32_t the_seq;
	string packet;
	uint32_t next_seq;
}Pack_Elem;

typedef struct ftp_packet{
	int length;
	u_char* packet;
}Ftp_Elem;

typedef std::vector<string> NameVector;
typedef std::map<string,string> NameMap;
typedef std::map<string,NameVector> Map_Vector;

// added
typedef std::vector<Pack_Elem> PackVector;
typedef std::map<string,PackVector> Map_Pack;

//added for ftp
typedef std::vector<Ftp_Elem> FTPVector;
typedef std::map<string,FTPVector> FTP_Map;

//typedef unsigned char BYTE;
//typedef unsigned int  DWORD;

class Ring_Util
{
private:
	char* m_Base64_Table;	//Base64 encode/decode table

public:
	Ring_Util();
	void print_payload(const u_char* payload, int len, FILE *stream_dst);
	void print_hex_ascii_line(const u_char* payload, int len, int offset, FILE *stream_dst);

	void print_payload2(const u_char* payload, int len, FILE *stream_dst);
	void print_hex_ascii_line2(const u_char* payload, int len, int offset, FILE *stream_dst);
	int parse_packet(struct pfring_pkthdr* header, const u_char* packet, const struct sniff_ip*& ip, const struct sniff_tcp*& tcp, u_char*&  payload);
	const string mkdir_for_today(string module,string file,const char* table);
	void write_info(FILE* stream_dst, const struct sniff_ip* ip, const struct sniff_tcp* tcp, u_char*  payload);
	FILE* construct_email(string sip, u_short sport, string packet_info, NameMap& email_map);

	string get_subject(string subject);
	bool is_ftp(const struct sniff_ip* ip,const struct sniff_tcp* tcp,string& packet);
	string get_email( string sip, u_short sport, string packet_info, NameMap& email_map );
	bool validate_tcp_data(u_short *tcp_load, int len, struct fake_tcphdr* hdr);
	bool validate_ip_header(u_short *ip_header, int len);

	void print_binary_payload(const u_char* payload, int len, FILE *stream_dst);
	void print_binary_line(const u_char* payload, int len, int offset, FILE *stream_dst);
	void get_ds_sock(const struct sniff_ip* ip, const struct sniff_tcp* tcp, string& sip_port, string& dip_port);
	void save_userinfo(Map_Vector& userinfo, const string& ip_port, const string& info, string module);
	string Base64Decode(string strSource);
	string getlocalip();
	void save_emailinfo(Map_Vector& userinfo, const string& ip_port, const string& pack_info);
	const string Get_Current_Time();
	u_short HashTime();
	string set_xmlname(string module, int count);
	void HashXml(string module);
	int utf8togb2312(const char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen);
	int get_dbinfo(const char*& user,const char*& pass,const char*& constr,const char*&localIp,const char*&LzDataPath, int& devicenum);
	
	void save_emailsub(NameMap& userinfo, const string& ip_port, const string& pack_info);
	void save_emailfrom(NameMap& userinfo, const string& ip_port, const string& pack_info);
	void save_emailto(NameMap& userinfo, const string& ip_port, const string& pack_info);
	void save_emailcc(NameMap& userinfo, const string& ip_port, const string& pack_info);
};

#endif // RING_UTIL
// end of file

