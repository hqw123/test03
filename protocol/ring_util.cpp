//
// Copyright (C) 2008 BAIHONG! CORPORATION. All rights reserved.
// BAIHONG! PROPRIETARY/CONFIDENTIAL
//
//------------------------------------------------------------------------
//
// Module Name      :ring_util.cpp
//
//------------------------------------------------------------------------
// Notes:
//   Comment character code - EUC
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 080928   Initial
// $d1= -------- 1.1  002 081006   Add Function mkdir_for_today
// $d2= -------- 1.2  003 081012   Add Function write_info
// $d3= -------- 1.3  004 081110   Add Function parse_packet
// $d4= -------- 1.4  005 081125   Add Function is_ftp
// $d5= -------- 1.5  006 081129   Add Function validate_tcp_data
// $d6= -------- 1.6  007 081208   Add Function print_binary_line
// $d7= -------- 1.7  008 090302   Add Function save_emailinfo
// $d8= -------- 1.8  009 090330   Add Function Get_Current_Time
//

#include "ring_util.h"
#include "Analyzer_log.h"

//#include "base64.h"
//#include "logger.h"
//#include "PacketParser.h"

//std::vector<string> ftp_data_port;

//--------------------------------------------------------------------------------------
// Function name: Ring_Util
//
// Description  : construct function
// Parameter    :
// Return				: 
//--------------------------------------------------------------------------------------
Ring_Util::Ring_Util()
{
	//Base64 encode/decode table
	this->m_Base64_Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

//--------------------------------------------------------------------------------------
// Function name: print_hex_ascii_line
//
// Description  : save packet's data in xml format
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_hex_ascii_line(const u_char* payload, int len, int offset, FILE *stream_dst)
{
	int i;
	const u_char* ch;
	const u_char* tmp;

	//printf("		");
	fprintf( stream_dst, "		" );
	
	ch = payload;
	tmp= payload;
	for(i=0; i<len; i++){
		tmp++;
		if(isprint(*ch)){
			// added to exclude xml error, replace < with "
			if( *ch=='<' ){
				fprintf( stream_dst, "%s", "\"" );	
			}
			else if( *ch=='>' ){
				fprintf( stream_dst, "%s", "\"" );	
			}
			else{
				//printf("%c", *ch);
				fprintf( stream_dst, "%c", *ch );
			}
		}
		else{
			if(*ch=='\t'){
				//printf("	");
				fprintf( stream_dst, "%s", "	" );
			}
			// if the currrent char is \n
			else if( *ch=='\n' ){
				//printf("\n		");
				fprintf( stream_dst, "%s		", "\n" );		
			}
			//else
			//	fprintf( stream_dst, "%c", *ch );
		}
		
		ch++;
	}

	//printf("\n");
	//fprintf( stream_dst, "%s", "\n" );
}

//--------------------------------------------------------------------------------------
// Function name: print_payload
//
// Description  : display packets' information
// Parameter    :
// Return	: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_payload(const u_char* payload, int len, FILE *stream_dst)
{
	int offset = 0;		// zero-based offset counter
	const u_char* ch = payload;

	if(len <= 0) return;
	print_hex_ascii_line(ch, len, offset, stream_dst);

	return;
}

//--------------------------------------------------------------------------------------
// Function name: print_hex_ascii_line2
//
// Description  : save packet's data in normal format
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_hex_ascii_line2(const u_char* payload, int len, int offset, FILE *stream_dst)
{
	int i;
	const u_char* ch;
	const u_char* tmp;

	//fprintf( stream_dst, "		" );
	
	ch = payload;
	tmp= payload;
	for(i=0; i<len; i++){
		tmp++;
		if(isprint(*ch)){
			fprintf( stream_dst, "%c", *ch );
		}
		else{
			if(*ch=='\t'){
				fprintf( stream_dst, "%s", "	" );
			}
			// if the currrent char is \n
			else if( *ch=='\n' ){
				//printf("\n		");
				fprintf( stream_dst, "%s", "\n" );		
			}
			//else
			//	fprintf( stream_dst, "%c", *ch );
		}
		
		ch++;
	}

	//fprintf( stream_dst, "%s", "\n" );
}

//--------------------------------------------------------------------------------------
// Function name: print_payload2
//
// Description  : display packets' information
// Parameter    :
// Return	: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_payload2(const u_char* payload, int len, FILE *stream_dst)
{
	int offset = 0;		// zero-based offset counter
	const u_char* ch = payload;

	if(len <= 0) return;
	print_hex_ascii_line2(ch, len, offset, stream_dst);

	return;
}

//--------------------------------------------------------------------------------------
// Function name: parse_packet
//
// Description  : function determine the packet belong to which protocol
// Parameter    :
// Return				: int
//--------------------------------------------------------------------------------------
int Ring_Util::parse_packet(struct pfring_pkthdr* header, const u_char* packet, const struct sniff_ip*& ip, const struct sniff_tcp*& tcp, u_char*&  payload)
{
	int packet_kind = 0;

	// declare pointers to packet headers
	const struct sniff_udp* udp;		// The UDP header
	int size_ip, size_tcp, size_payload;
	string pack_info;
	bool ftp_flag = false;

	// define/compute ip header offset
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20) return UNKNOWN_PACKET;

	if(ip->ip_p==IPPROTO_TCP){
		// define/compute tcp header offset
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp) * 4;
		if(size_tcp < 20) return UNKNOWN_PACKET;

		// compute tcp payload (segment) size
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		if( size_payload<0 ) return UNKNOWN_PACKET;
			
		payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		string pack_temp = (const char*)payload;
		pack_info = pack_temp.substr(0,size_payload);
		ftp_flag = is_ftp(ip,tcp,pack_info);
	}
	else if(ip->ip_p==IPPROTO_UDP){
		// define/compute udp header offset
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		if(udp->udp_length -SIZE_ETHERNET - size_ip < 8){
			return UNKNOWN_PACKET;
		}	
	}

	// determine the packet
	// http packet
	if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==80)||(ntohs(tcp->th_dport)==80)) )
		packet_kind = HTTP_PACKET;
	// smtp packet
	else if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==25)||(ntohs(tcp->th_dport)==25)) )
		packet_kind = SMTP_PACKET;
	// pop3 packet
	else if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==110)||(ntohs(tcp->th_dport)==110)) )
		packet_kind = POP3_PACKET;
	// ftp packet
	else if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==21)||(ntohs(tcp->th_sport)==20)||(ntohs(tcp->th_dport)==21) ) )
		packet_kind = FTP_PACKET;
	// ftp packet
	else if( (ip->ip_p==IPPROTO_TCP) && (ftp_flag==true) )
		packet_kind = FTP_PACKET;
	// telnet packet
	else if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==23)||(ntohs(tcp->th_dport)==23)) )
		packet_kind = TELNET_PACKET;	
	// tcp msn packet
	else if( (ip->ip_p==IPPROTO_TCP) && ((ntohs(tcp->th_sport)==1863)||(ntohs(tcp->th_dport)==1863)) )
		packet_kind = MSN_PACKET;
	else
		packet_kind = UNKNOWN_PACKET;

	return packet_kind;	

}
/*
int Ring_Util::parse_packet(PacketInfo* pktInfo)
{
	bool ftp_flag = false;
	string pack_info;
    string pack_temp = (const char*)pktInfo->body;
    pack_info = pack_temp.substr(0, pktInfo->bodyLen);
    ftp_flag = is_ftp((const struct sniff_ip*) pktInfo->ip, (const struct sniff_tcp*) pktInfo->tcp, pack_info);
}
*/
//--------------------------------------------------------------------------------------
// Function name: mkdir_for_today
//
// Description  : determine today and mkdir for it
//							:	input "smtp", "file.txt"��then file.txt will put into dir smtp/today/
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
const string Ring_Util::mkdir_for_today(string module,string file,const char* table)
{
	time_t v_t = time(NULL);
	tm* vp_local_time = localtime(&v_t);
	
	char v_buf[256];
	::memset(v_buf, 0, sizeof(v_buf));
	sprintf(v_buf, "%d%02d%02d", vp_local_time->tm_year+1900, vp_local_time->tm_mon+1, vp_local_time->tm_mday);
	

	char tmp[255];
	sprintf(tmp,"%s","/home");//LzDataPath
	string v_file_path =tmp;
	v_file_path.append("/spyData/moduleData/");
	v_file_path += module;
	v_file_path.append("/");
	v_file_path.append(v_buf);
	v_file_path.append("/");

	string v_file = v_file_path;
	v_file.append(file.c_str());
	//file.append(".xml");

	// dir not exist
	if(::access(v_file_path.c_str(), F_OK) != 0){
		::mkdir(v_file_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}
	
	// file not exist
	if( (::access(v_file.c_str(), 0) != 0) && (v_file.find(".xml")!=string::npos||v_file.find(".txt")!=string::npos) && (table!=NULL) ){
		FILE *stream_dst = fopen( v_file.c_str(), "wb+" ); // append info to file
		if( stream_dst==NULL ){
			//CLogger::Get_Instance().Error(module,"file was not opened correctly!");
			return "NULL"; 
		}
		fprintf( stream_dst, "%s%s%s%s%s\n", "<?xml version=\"1.0\"?>", "\n<table name=\"", table, "\">\n", "</table>");
		fclose(stream_dst);		
	}
	return v_file;
}

//--------------------------------------------------------------------------------------
// Function name: get_email
//
// Description  : get email subject, and save it as subject.eml
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
string Ring_Util::get_email( string sip, u_short sport, string packet_info, NameMap& email_map )
{
	string sip_port = sip;
	char s_port[10];
	string pack_info;
	string subject;

	sprintf(s_port, ":%d", sport);
	sip_port.append(s_port);

	// determine the packet belong to which email, and write to the same email file
	if( packet_info.find("Subject:")!=string::npos ){ 			// if the packet contain email header
		if( email_map.find( sip_port )==email_map.end() ){  // the user don't exist��add him to map
			int index1 = packet_info.find("Subject: ");
			int index2 = packet_info.find('\r',index1);		// \r after subject
			subject = packet_info.substr( index1+strlen("Subject: "), index2-index1-strlen("Subject: ") );
			subject = get_subject(subject);
			subject.append(".eml");
		}
	}

	return subject;
}

//--------------------------------------------------------------------------------------
// Function name: get_subject
//
// Description  : return subject, decoding gb2312
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
string Ring_Util::get_subject(string subject)
{
	int pos1,pos2,pos3,pos4;
	string sub;

	if( subject.find("=?")!=string::npos ){
		pos1 = subject.find("?");
		pos2 = subject.find("?",pos1+1);
		pos3 = subject.find("?",pos2+1);
		pos4 = subject.find("?=");
		sub = subject.substr(pos3+1,pos4-pos3-1);
		sub = Base64Decode(sub);
		//Base64Decode((char*)subject.c_str(), strlen(subject));
	}
	else{
		sub = subject;
	}

	return sub;
}

//--------------------------------------------------------------------------------------
// Function name: validate_tcp_data
//
// Description  : when received a packet,  according to checksum
//								validate the packet is correct or not
// Parameter    : tcp_load including tcp header and tcp data
//								hdr is fake tcp header
//								len = sizeof(tcp_header) + sizeof(tcp_data)
// Return				: true or false
//--------------------------------------------------------------------------------------
bool Ring_Util::validate_tcp_data(u_short *tcp_load, int len, struct fake_tcphdr* hdr)
{
	int nleft = len;
	u_short *w = tcp_load;
	u_int32_t sum = 0;

	sum = sum + (hdr->saddr>>16) + (hdr->saddr & 0xffff);
	sum = sum + (hdr->daddr>>16) + (hdr->daddr & 0xffff);
	sum += (u_short)hdr->ptcl;
	sum += hdr->tcp_len;

	while (nleft > 1){
		sum += ntohs(*w++);
		nleft -= 2;
	}

	if (nleft == 1){
		u_char tmp = *(u_char *)w;
		u_short last = (u_short)(tmp<<8);		// add 0
		sum += last;
	}

	sum = (sum>>16) + (sum & 0xffff);
	sum += (sum>>16);

	LOG_INFO("validate tcp_sum = %04x\n",(u_short)sum);
	
	if((u_short)sum!=0xffff)
		LOG_ERROR("error tcp data!\n");
		
	if( (u_short)sum==0xffff )
		return true;
	else
		return false;

}

//--------------------------------------------------------------------------------------
// Function name: validate_checksum
//
// Description  : when received a packet,  according to checksum
//								validate the packet is correct or not
// Parameter    : tcp_load including tcp header and tcp data
//								hdr is fake tcp header
//								len = sizeof(tcp_header) + sizeof(tcp_data)
// Return				: true or false
//--------------------------------------------------------------------------------------
bool Ring_Util::validate_ip_header(u_short *ip_header, int len)
{
	int nleft = len;
	u_short *w = ip_header;
	u_int32_t sum = 0;

	while (nleft > 0){
		sum += ntohs(*w++);
		nleft -= 2;
	}

	sum = (sum>>16) + (sum & 0xffff);
	sum += (sum>>16);

	LOG_INFO("validate ip_sum = %04x\n",(u_short)sum);

	if((u_short)sum!=0xffff)
		LOG_ERROR("error ip header!\n");
	
	if( (u_short)sum==0xffff )
		return true;
	else
		return false;

}

//--------------------------------------------------------------------------------------
// Function name: is_ftp
//
// Description  : analyse the packet is ftp or not(ftp data info)
//								if packet contains words like	"220 ICS FTP Server ready" and its port
//								is not 21, it is also ftp packet, record its sip_port
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
bool Ring_Util::is_ftp(const struct sniff_ip* ip,const struct sniff_tcp* tcp,string& packet)
{
	/*string sip = (const char*)inet_ntoa(ip->ip_src);
	string dip_port, sip_port;
	get_ds_sock(ip, tcp, sip_port, dip_port);

	vector<string>::iterator iter1 = find( ftp_data_port.begin(), ftp_data_port.end(), sip_port );
	vector<string>::iterator iter2 = find( ftp_data_port.begin(), ftp_data_port.end(), dip_port );
	
	// if the packet's src ip and port exist in ftp server ip and data port 
	if ( (iter1!=ftp_data_port.end())||(iter2!=ftp_data_port.end()) ) return true;
	else if ( packet.find("Passive Mode")!=string::npos ){
		int index1 = packet.find(')');
		int index2 = packet.rfind(',');							// the last dot
		int index3 = packet.rfind(',',index2-1);		// dot before the last dot
		
		int port1 = atoi(packet.substr(index3+1, index2-index3+1).c_str());
		int port2 = atoi(packet.substr(index2+1, index1-index2+1).c_str());
		int port  = port1*256+port2;
		
		char next_port[10];
		sprintf(next_port, ":%d", port);
	
		string ip_port = sip;
		ip_port.append(next_port);

		vector<string>::iterator iter = find( ftp_data_port.begin(), ftp_data_port.end(), ip_port );
		if( iter == ftp_data_port.end() ){
			// save ftp server ip and data port
			ftp_data_port.push_back(ip_port);
		}
		return true;
	}
	else*/
		return false;
}

//--------------------------------------------------------------------------------------
// Function name: construct_email
//
// Description  : reconstruct email from packet
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
FILE* Ring_Util::construct_email( string sip, u_short sport, string packet_info, NameMap& email_map )
{
	FILE *stream_dst;
	string sip_port = sip;
	char s_port[10];
	string pack_info;

	sprintf(s_port, ":%d", sport);
	sip_port.append(s_port);

	// determine the packet belong to which email, and write to the same email file
	if( packet_info.find("Subject:")!=string::npos ){ 			// if the packet contain email header
		if( email_map.find( sip_port )==email_map.end() ){  // the user don't exist��add him to map
			int index1 = packet_info.find("Subject: ");
			int index2 = packet_info.find('\r',index1);		// \r after subject
			string subject = packet_info.substr( index1+strlen("Subject: "), index2-index1-strlen("Subject: ") );
			subject = get_subject(subject);
			subject.append(".eml");		
			email_map[sip_port] = subject;
		}
		stream_dst = fopen( email_map[sip_port].c_str(), "a+" );
	}
	else if( packet_info.find("attachment")!=string::npos ){ // if the packet contain email attached file
		stream_dst = fopen( email_map[sip_port].c_str(), "a+" );		
	}
	else if( email_map.find( sip_port )!=email_map.end() ){
		stream_dst = fopen( email_map[sip_port].c_str(), "a+" );
	}
	else
		stream_dst = fopen( "email.eml", "a+" );	

	return stream_dst;
}

//--------------------------------------------------------------------------------------
// Function name: write_info
//
// Description  : function write packet info into file
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::write_info(FILE* stream_dst, const struct sniff_ip* ip, const struct sniff_tcp* tcp, u_char*  payload)
{
	//int size_payload = ntohs(ip->ip_len) - (IP_HL(ip)*4 + TH_OFF(tcp)*4);

	//printf("	IP Header\n");
	//fprintf( stream_dst, "	<IP_Header>\n" );
	//printf("		Protocol:	%d\n", ip->ip_p);
	//fprintf( stream_dst, "%s%d%s\n", "		<Protocol>", ip->ip_p, "</Protocol>");
	LOG_INFO("	Source IP:	%s\n", inet_ntoa(ip->ip_src));
	fprintf( stream_dst, "%s%s%s\n", "	<Source_IP>", inet_ntoa(ip->ip_src), "</Source_IP>" );
	LOG_INFO("	Source port:	%d\n", ntohs(tcp->th_sport));
	fprintf( stream_dst, "%s%d%s\n", "	<Source_Port>", ntohs(tcp->th_sport), "</Source_Port>");
	//fprintf( stream_dst, "	</IP_Header>\n" );

	//printf("	TCP Header\n");
	//fprintf( stream_dst, "	<TCP_Header>\n" );
	LOG_INFO("	Destination IP:	%s\n", inet_ntoa(ip->ip_dst));
	fprintf( stream_dst, "%s%s%s\n", "	<Dest_IP>", inet_ntoa(ip->ip_dst), "</Dest_IP>" );
	LOG_INFO("	Dest   port:	%d\n", ntohs(tcp->th_dport));
	fprintf( stream_dst, "%s%d%s\n", "	<Dest_Port>", ntohs(tcp->th_dport), "</Dest_Port>");
	//fprintf( stream_dst, "%s%d%s\n", "	<SYN_Flag>", (tcp->th_flags & 0x02)>1, "</SYN_Flag>");
	//fprintf( stream_dst, "%s%d%s\n", "	<FIN_Flag>", tcp->th_flags & 0x01, "</FIN_Flag>");
	//fprintf( stream_dst, "%s%d%s\n", "	<Seq_Number>", ntohl(tcp->th_seq), "</Seq_Number>");
	//fprintf( stream_dst, "%s%d%s\n", "	<Ack_Number>", ntohl(tcp->th_ack), "</Ack_Number>");
	//fprintf( stream_dst, "	</TCP_Header>\n" );

	// Print payload data, it might be binary, so don't just treat it as a string...
	//if( size_payload > 0 ){
	//	printf("	Payload (%d bytes):\n", size_payload);
	//	fprintf( stream_dst, "%s%d%s\n", "	<Payload_", size_payload, ">");
	//	print_payload(payload, size_payload, stream_dst);
	//	fprintf( stream_dst, "%s%d%s\n", "</Payload_", size_payload, ">");
	//}

}

//--------------------------------------------------------------------------------------
// Function name: print_binary_line
//
// Description  : print packet's data in binary format
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_binary_line(const u_char* payload, int len, int offset, FILE *stream_dst)
{
	int i;
	const u_char* ch;
	ch = payload;
	
	/* hex */
	for(i = 0; i < len; i++) {
		printf("%02x", *ch);
		fprintf( stream_dst, "%02x", *ch );
		ch++;
	}

	return;
}

//--------------------------------------------------------------------------------------
// Function name: print_binary_payload
//
// Description  : display packets' information, binary format
// Parameter    :
// Return	: void
//--------------------------------------------------------------------------------------
void Ring_Util::print_binary_payload(const u_char* payload, int len, FILE *stream_dst)
{
	int offset = 0;		// zero-based offset counter
	const u_char* ch = payload;

	if(len <= 0) return;
	print_binary_line(ch, len, offset, stream_dst);

	return;
}

//--------------------------------------------------------------------------------------
// Function name: get_ds_sock
//
// Description  : from a packet, get it's sip_port and dip_port
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::get_ds_sock(const struct sniff_ip* ip, const struct sniff_tcp* tcp, string& sip_port, string& dip_port)
{
	string sip = (const char*)inet_ntoa(ip->ip_src);
	sip_port = sip;
	char s_port[10];
	sprintf(s_port, ":%d", ntohs(tcp->th_sport));
	sip_port.append(s_port);

	string dip = (const char*)inet_ntoa(ip->ip_dst);
	dip_port = dip;
	char d_port[10];
	sprintf(d_port, ":%d", ntohs(tcp->th_dport));
	dip_port.append(d_port);

	return;
}

//--------------------------------------------------------------------------------------
// Function name: save_userinfo
//
// Description  : save user's name and password
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_userinfo(Map_Vector& userinfo, const string& ip_port, const string& info, string module)
{
	if(userinfo[ip_port].size()<2) 
		return;
	
	string sub = "user_info.txt";
	sub = mkdir_for_today(module, sub, "EMAIL");

	FILE *stream_dst;
	stream_dst = fopen( sub.c_str(), "a+" ); // append info to file
	if( stream_dst==NULL ){
		//CLogger::Get_Instance().Error(module,"failed to record user's username and password!");
		return; 
	}

	fprintf( stream_dst, "%s\n", ip_port.c_str() );
	if(module=="smtp") 
		fprintf( stream_dst, "%s%s\n", info.c_str(), "'s sender's username and passwd is:");
	else if (module=="pop3") 
		fprintf( stream_dst, "%s%s\n", info.c_str(), "'s receiver's username and passwd is:");
	
	for(size_t i=0; i<userinfo[ip_port].size(); i++){
		if(module=="smtp"){
			if(i==0) fprintf( stream_dst, "%s%s\n", "User:", Base64Decode(userinfo[ip_port][i]).c_str() );
			else if(i==1) fprintf( stream_dst, "%s%s\n", "Pass:", Base64Decode(userinfo[ip_port][i]).c_str() );
			else fprintf( stream_dst, "%s%s\n", "Info:", userinfo[ip_port][i].c_str() );
		}
		else
			fprintf( stream_dst, "%s", userinfo[ip_port][i].c_str() );
	}

	fprintf( stream_dst, "\n");
	fclose( stream_dst );

	return;
}

//--------------------------------------------------------------------------------------
// Function name: Base64Decode
//
// Description  : decode base64 format
// Parameter    :
// Return				: strSource
//--------------------------------------------------------------------------------------
string Ring_Util::Base64Decode(string strSource)
{
	string strDecode;
	char cTemp[5];
	int Length=0;

	for(size_t i=0;i<strSource.size();i+=4){
		memset(cTemp,0,5);
		cTemp[0]=strSource[i];
		cTemp[1]=strSource[i+1];
		cTemp[2]=strSource[i+2];
		cTemp[3]=strSource[i+3];

		Length+=4;
		if(Length==76){
			i+=2;
			Length=0;
		}

		int asc[4];
		for(int j=0;j<4;j++){
			for(int k=0;k<(int)strlen(this->m_Base64_Table);k++){
				if(cTemp[j]==this->m_Base64_Table[k]) asc[j]=k;
			}
		}

		if('='==cTemp[2] && '='==cTemp[3]){
			strDecode+=(char)(int)(asc[0] << 2 | asc[1] << 2 >> 6);
		}
		else if('='==cTemp[3]){
			strDecode+=(char)(int)(asc[0] << 2 | asc[1] << 2 >> 6);
			strDecode+=(char)(int)(asc[1] << 4 | asc[2] << 2 >> 4);
		}
		else{
			strDecode+=(char)(int)(asc[0] << 2 | asc[1] << 2 >> 6);
			strDecode+=(char)(int)(asc[1] << 4 | asc[2] << 2 >> 4);
			strDecode+=(char)(int)(asc[2] << 6 | asc[3] << 2 >> 2);
		}  
	}
	
	return strDecode;

}

//--------------------------------------------------------------------------------------
// Function name: getlocalip
//
// Description  : return local ip 
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
string Ring_Util::getlocalip()
{
	int sockfd;
	char ip[15];
  
	if(-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0))){   
		perror( "socket" );   
		return " ";   
	}   
  
	struct ifreq req;
	struct sockaddr_in *host;
  
	bzero(&req, sizeof(struct ifreq));
	strcpy(req.ifr_name, "eth0");
	ioctl(sockfd, SIOCGIFADDR, &req);
	host = (struct sockaddr_in*)&req.ifr_addr;
	strcpy(ip, inet_ntoa(host->sin_addr));
	close(sockfd);
	
	string localip = ip;

	return localip;
}  

//--------------------------------------------------------------------------------------
// Function name: save_emailinfo
//
// Description  : save email's from��to��subject information
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_emailinfo(Map_Vector& userinfo, const string& ip_port, const string& pack_info)
{
	if( pack_info.find("Subject: ")==string::npos ) return;

	// ���淢���˵�ַ
	if( pack_info.find("From: ")!=string::npos ){
		int index1 = pack_info.find("From: ");
		int index2 = pack_info.find('\r', index1);
		string email_from = pack_info.substr(index1,index2-index1); // ��ȡFrom: "zhangpeng" <zhang.peng@founder.com>

		vector<string>::iterator itr = find( userinfo[ip_port].begin(), userinfo[ip_port].end(), email_from );
		if( itr==userinfo[ip_port].end() ){
			int index3 = email_from.find('<');
			int index4 = email_from.find('>');
			string from = email_from.substr(index3+1,index4-index3-1);
			if(from.find('@')!=string::npos) {
				if(from.find("From: ")!=string::npos) userinfo[ip_port].push_back(from.substr(6,from.length()-6));
    		else userinfo[ip_port].push_back(from);
			}
		}		
	}

	// �����ռ��˵�ַ
	if( pack_info.find("To: ")!=string::npos ){
		int index1 = pack_info.find("To: ");
		int index2 = pack_info.find('\r', index1);
		string email_to = pack_info.substr(index1,index2-index1); 
			if(email_to.find('<')==string::npos){
			if(email_to.find('@')!=string::npos) userinfo[ip_port].push_back(email_to.substr(4,email_to.length()-4));
		}
		else{
			vector<string>::iterator itr = find( userinfo[ip_port].begin(), userinfo[ip_port].end(), email_to );
			if( itr==userinfo[ip_port].end() ){
				int index3 = email_to.find('<');
				int index4 = email_to.find('>');
				string to = email_to.substr(index3+1,index4-index3-1);
				if(to.find('@')!=string::npos) {
					if(to.find("To: ")!=string::npos) userinfo[ip_port].push_back(to.substr(4,to.length()-4));
	    		else userinfo[ip_port].push_back(to);
				}
			}
		}
	}

	// �����ʼ�����
	if( pack_info.find("Subject: ")!=string::npos ){
		int index1 = pack_info.find("Subject: ");
		int index2 = pack_info.find('\r',index1);		// \r after subject
		string subject = pack_info.substr( index1+strlen("Subject: "), index2-index1-strlen("Subject: ") );
		subject = get_subject(subject);

		vector<string>::iterator itr = find( userinfo[ip_port].begin(), userinfo[ip_port].end(), subject );
		if( itr==userinfo[ip_port].end() ){
			// ȥ�������е�&����
			const char* ch = subject.c_str();
			for(size_t i=0; i<subject.length(); i++){
				if( *ch=='&' ){
					subject.replace(subject.find('&'),1," ");
				}
				ch++;
	    }
			// ȥ��&���ź󱣴�
			userinfo[ip_port].push_back(subject);
		}
	}

	// ���泭���˵�ַ
	if( pack_info.find("Cc: ")!=string::npos ){
		int index1 = pack_info.find("Cc: ");
		int index2 = pack_info.find('\r', index1);
		string email_cc = pack_info.substr(index1,index2-index1); // ��ȡCc: "zhang.peng" <zhang.peng@founder.com>

		vector<string>::iterator itr = find( userinfo[ip_port].begin(), userinfo[ip_port].end(), email_cc );
		if( itr==userinfo[ip_port].end() ){
			int index3 = email_cc.find('<');
			int index4 = email_cc.find('>');
			string cc = email_cc.substr(index3+1,index4-index3-1);
			if(cc.find('@')!=string::npos) userinfo[ip_port].push_back(cc);
		}		
	}
	else if( pack_info.find("Cc: ")==string::npos && pack_info.find("Subject: ")!=string::npos){
		userinfo[ip_port].push_back(" ");
	}

	return;
}

//--------------------------------------------------------------------------------------
// Function name: Get_Current_Time()
//
// Description  : internal function
//								get current time
// Parameter    :
// Return				: time like "Mon Mar 23 10:19:09 2009"
//--------------------------------------------------------------------------------------
const string Ring_Util::Get_Current_Time()
{
	time_t v_t;
	char v_buf[64];
	v_t=time(NULL);
	tm* vp_local_time = localtime(&v_t);
	strftime(v_buf, sizeof(v_buf), "%c", vp_local_time);
	return v_buf;
}

//--------------------------------------------------------------------------------------
// Function name: HashTime()
//
// Description  : get subdir name
// Parameter    :
// Return				: 1~12
//--------------------------------------------------------------------------------------
u_short Ring_Util::HashTime()
{
    time_t timeVal;
    time(&timeVal);
    return (timeVal/300)%12;
}

//--------------------------------------------------------------------------------------
// Function name: set_xmlname()
//
// Description  : set xml name
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
string Ring_Util::set_xmlname(string module, int count)
{
	char v_buf[50];
	sprintf(v_buf, "%s-%d", module.c_str(),count);
	string xml_name = v_buf;
	xml_name.append(".xml");
	
	return xml_name;
}

//--------------------------------------------------------------------------------------
// Function name: HashXml()
//
// Description  : mv xml file to hash directory
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::HashXml(string module)
{
	time_t v_t = time(NULL);
	tm* vp_local_time = localtime(&v_t);
		
	char v_buf[256];
	::memset(v_buf, 0, sizeof(v_buf));
	sprintf(v_buf, "%d%02d%02d", vp_local_time->tm_year+1900, vp_local_time->tm_mon+1, vp_local_time->tm_mday);
	
	int subDir = HashTime();
	char v_dir[10];
	sprintf(v_dir, "%d", subDir);

	string search = "mv " ;  // /home;
	search.append("/home");//错误：‘LzDataPath’ 

	search.append("/spyData/moduleData/");
	search.append(module.c_str());
	search.append("/");
	search.append(v_buf);
	search.append("/*.xml ");
	search.append("/home");//LzDataPath
	search.append("/spyData/");
	search.append(v_dir);

	LOG_INFO("mv system: %s\n", search.c_str());

	FILE *fp = NULL;
	if (NULL == (fp = popen(search.c_str(), "r")))
	{
		LOG_ERROR("mv system, popen error!\n");
		exit(0);
	}

	if (0 > pclose(fp))
	{
		LOG_ERROR("mv system, pclose error!\n");
		exit(0);
	}
	
	//if( system(search.c_str())<0 ) {
	//	LOG_ERROR("mv system error!\n");
	//	exit(0);
	//}
}

//--------------------------------------------------------------------------------------
// Function name: utf8togb2312()
//
// Description  : convert gb2312 charset to utf-8
// Parameter    :
// Return				: string
//--------------------------------------------------------------------------------------
int Ring_Util::utf8togb2312(const char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen)
{
  iconv_t cd;
  if ((cd = iconv_open("utf-8","gb2312")) == (iconv_t)-1)
    return -1;
  memset(destbuf,0,destlen);
  const char **source = &sourcebuf;
  char **dest = &destbuf;

  if (-1 == iconv(cd,(char**)source,&sourcelen,dest,&destlen))
    return -1;
  iconv_close(cd);
  return 0;
}

//--------------------------------------------------------------------------------------
// Function name: get_dbinfo()
//
// Description  : get db connection info from config file
// Parameter    :
// Return				: int
//--------------------------------------------------------------------------------------
int Ring_Util::get_dbinfo(const char*& user,const char*& pass,const char*& constr,const char*&localIp,const char*&LzDataPath, int& devicenum)
{
	/*const char* configfile = "/NodesSystem/DeviceInfo.xml";

	if(::access(configfile, F_OK) != 0){
		cout<<"file not exist"<<endl;
		return -1;
	}
    
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;

	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if (!doc) {
		fprintf(stderr, "Read configure file failed!\n");
		return -1;
	}

	curNode = xmlDocGetRootElement(doc);
	if (!curNode) {
		fprintf(stderr, "Empty configure file!\n");
		xmlFreeDoc(doc);
		return -1;
	}

	if (xmlStrcmp(curNode->name, BAD_CAST "device")) {
		fprintf(stderr, "Root node error!\n");
		xmlFreeDoc(doc);
		return -1;
	}
    
	xmlChar* dataPath = NULL;
	xmlChar* formatFile = NULL;
	xmlChar* dbName = NULL;
	xmlChar* dbUser = NULL;
	xmlChar* dbPassword = NULL;
	xmlChar* dnum = NULL;
	xmlChar* lip=NULL;
	xmlChar* ndPath=NULL;
	itemNode = curNode->xmlChildrenNode;
	while (itemNode) {
		if (itemNode->type != XML_ELEMENT_NODE) {
			itemNode = itemNode->next;
			continue;
		}
		if (!xmlStrcmp(itemNode->name, BAD_CAST "dataPath")) {
			dataPath = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "formatFile")) {
			formatFile = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbName")) {
			dbName = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbUser")) {
			dbUser = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbPassword")) {
			dbPassword = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "devicenum")) {
			dnum = xmlNodeGetContent(itemNode);
		} else if (!xmlStrcmp(itemNode->name, BAD_CAST "localIp")) {
			lip = xmlNodeGetContent(itemNode);
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "LzDataPath")) {
			ndPath = xmlNodeGetContent(itemNode);
		}
		
		itemNode = itemNode->next;
	}
	
	xmlFreeDoc(doc);
	if (!(dataPath || formatFile || dbName || dbUser || dbPassword)) {
		fprintf(stderr, "Config file error, no enough item!\n");
		return -1;
	}

	user = (const char*)dbUser;
	pass = (const char*)dbPassword;
	constr = (const char*)dbName;
	localIp = (const char *)lip;
	lzDataPath=(const char*)ndPath;

	const char* device = (const char*)dnum;
	devicenum = atoi(device);*/
	
	return 0;
}

//--------------------------------------------------------------------------------------
// Function name: save_emailsub
//
// Description  : save email's subject information
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_emailsub(NameMap& userinfo, const string& ip_port, const string& pack_info)
{
	// �����ʼ�����
	if( pack_info.find("Subject: ")!=string::npos ){
		int index1 = pack_info.find("Subject: ");
		int index2 = pack_info.find('\r',index1);		// \r after subject
		string subject = pack_info.substr( index1+strlen("Subject: "), index2-index1-strlen("Subject: ") );
		subject = get_subject(subject);

		// ȥ�������е�&����
		const char* ch = subject.c_str();
		for(size_t i=0; i<subject.length(); i++){
			if( *ch=='&' ){
				subject.replace(subject.find('&'),1," ");
			}
			ch++;
		}
		// ȥ��&���ź󱣴�
		userinfo[ip_port] = subject;
	}

	return;
}

//--------------------------------------------------------------------------------------
// Function name: save_emailfrom
//
// Description  : save email's from information
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_emailfrom(NameMap& userinfo, const string& ip_port, const string& pack_info)
{
	// ���淢���˵�ַ
	if( pack_info.find("From: ")!=string::npos ){
		int index1 = pack_info.find("From: ");
		int index2 = pack_info.find('\r', index1);
		string email_from = pack_info.substr(index1,index2-index1); // ��ȡFrom: "zhangpeng" <zhang.peng@founder.com>

		int index3 = email_from.find('<');
		int index4 = email_from.find('>');
		string from = email_from.substr(index3+1,index4-index3-1);
		if(from.find('@')!=string::npos) {
			if(from.find("From: ")!=string::npos) userinfo[ip_port] = from.substr(6,from.length()-6);
    	else userinfo[ip_port] = from;
		}
	}

	return;
}

//--------------------------------------------------------------------------------------
// Function name: save_emailto
//
// Description  : save email's to information
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_emailto(NameMap& userinfo, const string& ip_port, const string& pack_info)
{
	if( userinfo[ip_port].find('@')!=string::npos) return;

	// �����ռ��˵�ַ
	if( pack_info.find("\r\nTo: ")!=string::npos ){
		int index1 = pack_info.find("\r\nTo: ");
		int index2 = pack_info.find("\r\n", index1);
		string email_to = pack_info.substr(index1+2,index2-index1-1);
		if(email_to.find('<')==string::npos){
			if(email_to.find('@')!=string::npos) {
				int index3 = email_to.find("\r\n");
				userinfo[ip_port] = email_to.substr(4,index3-4);
			}
		}
		else if(email_to.find(',')!=string::npos){
			// multiple to address which is seperated by ','
			int index3 = email_to.find('<');
			int index4 = email_to.find('>');
			int index5 = email_to.find(',');
	
			string to = email_to.substr(index3+1,index4-index3-1);
			userinfo[ip_port] += to;
				
			while(index4+1 == index5){
				index3 = email_to.find('<', index5);
				index4 = email_to.find('>', index5);
				index5 = email_to.find(',', index4);
				to = email_to.substr(index3+1,index4-index3-1);
				userinfo[ip_port] += ",";
				userinfo[ip_port] += to;
			}
		}
		else{
			int index3 = email_to.find('<');
			int index4 = email_to.find('>');
			string to = email_to.substr(index3+1,index4-index3-1);
			if(to.find('@')!=string::npos) {
				if(to.find("To: ")!=string::npos) userinfo[ip_port] = to.substr(4,to.length()-4);
	    	else userinfo[ip_port] = to;
			}
		}
	}
	// ���ʼ�û��������
	else{
		userinfo[ip_port] = " ";
	}

	return;
}

//--------------------------------------------------------------------------------------
// Function name: save_emailcc
//
// Description  : save email's cc information
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void Ring_Util::save_emailcc(NameMap& userinfo, const string& ip_port, const string& pack_info)
{
	if( userinfo[ip_port].find('@')!=string::npos) return;

	// ���泭���˵�ַ
	if( pack_info.find("Cc: ")!=string::npos ){
		int index1 = pack_info.find("Cc: ");
		int index2 = pack_info.find(">\r\n", index1);
		string email_cc = pack_info.substr(index1,index2-index1+1); // ��ȡCC: "zhang.peng" <zhang.peng@founder.com>

		//printf("%s\n",email_cc.c_str());
		
		// ���û�
		if(email_cc.find(',')!=string::npos){
			int index3 = email_cc.find('<');
			int index4 = email_cc.find('>');
			int index5 = email_cc.find(',');
		
			string cc = email_cc.substr(index3+1,index4-index3-1);
			userinfo[ip_port] += cc;
					
			while(index4+1 == index5){
				index3 = email_cc.find('<', index5);
				index4 = email_cc.find('>', index5);
				index5 = email_cc.find(',', index4);
				cc = email_cc.substr(index3+1,index4-index3-1);
				userinfo[ip_port] += ",";
				userinfo[ip_port] += cc;
			}
		}
		// ���û�
		else{
			int index3 = email_cc.find('<');
			int index4 = email_cc.find('>');
			string cc = email_cc.substr(index3+1,index4-index3-1);
			if(cc.find('@')!=string::npos) userinfo[ip_port] = cc;
		}
		/*
		int index1 = pack_info.find("Cc: ");
		int index2 = pack_info.find('\r', index1);
		string email_cc = pack_info.substr(index1,index2-index1); // ��ȡCc: "zhang.peng" <zhang.peng@founder.com>

		int index3 = email_cc.find('<');
		int index4 = email_cc.find('>');
		string cc = email_cc.substr(index3+1,index4-index3-1);
		if(cc.find('@')!=string::npos) userinfo[ip_port] = cc;
		*/
	}
	else if( pack_info.find("CC: ")!=string::npos ){
		int index1 = pack_info.find("CC: ");
		int index2 = pack_info.find(">\r\n", index1);
		string email_cc = pack_info.substr(index1,index2-index1+1); // ��ȡCC: "zhang.peng" <zhang.peng@founder.com>

		//printf("%s\n",email_cc.c_str());
		
		// ���û�
		if(email_cc.find(',')!=string::npos){
			int index3 = email_cc.find('<');
			int index4 = email_cc.find('>');
			int index5 = email_cc.find(',');
		
			string cc = email_cc.substr(index3+1,index4-index3-1);
			userinfo[ip_port] += cc;
					
			while(index4+1 == index5){
				index3 = email_cc.find('<', index5);
				index4 = email_cc.find('>', index5);
				index5 = email_cc.find(',', index4);
				cc = email_cc.substr(index3+1,index4-index3-1);
				userinfo[ip_port] += ",";
				userinfo[ip_port] += cc;
			}
		}
		// ���û�
		else{
			int index3 = email_cc.find('<');
			int index4 = email_cc.find('>');
			string cc = email_cc.substr(index3+1,index4-index3-1);
			if(cc.find('@')!=string::npos) userinfo[ip_port] = cc;
		}

	}
	else if( pack_info.find("Cc: ")==string::npos && pack_info.find("Subject: ")!=string::npos){
		userinfo[ip_port] = " ";
	}
	else if( pack_info.find("CC: ")==string::npos && pack_info.find("Subject: ")!=string::npos){
		userinfo[ip_port] = " ";
	}


	return;
}

// end of file

