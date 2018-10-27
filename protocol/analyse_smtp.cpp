//------------------------------------------------------------------------
// Lz System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG SOFTWARE  CO.,
//
//------------------------------------------------------------------------
//
// Module Name      :analyse_smtp.cpp
//
//------------------------------------------------------------------------
// Notes:
//      
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101020 WUZHONGHUA   Initial
//
//------------------------------------------------------------------------

#include "analyse_smtp.h"
#include "clue_c.h"
#include "Analyzer_log.h"
#include "db_data.h"

NameMap_smtp SMTP::email_smtp = NameMap_smtp();
Map_Pack_smtp SMTP::smtp_email_contents = Map_Pack_smtp(); // store packet whose sequence is correct
Map_Pack_smtp SMTP::smtp_lost_contents = Map_Pack_smtp();	 // store packet whose sequence is not correct
Map_Vector_smtp SMTP::smtp_userinfo = Map_Vector_smtp();	 // store user's username and password
std::map<uint64_t,int> smtp_flag;
std::map<uint64_t,int> smtp_stat;
std::map<uint64_t,uint32_t> smtp_user_sequence;
char SMTP::mac_[20];

NameMap_smtp smtp_subject;  //主题
NameMap_smtp smtp_from;   //发送人
NameMap_smtp smtp_to;    //接收人
NameMap_smtp smtp_cc;    //抄送人
std::map<uint64_t,int> smtp_affixFlag; //是否有附件。

SMTP::SMTP()
{ 
	isRunning_ = true; 
	isDeepParsing_ = false; 
	ClearFilterPort();
}

SMTP::~SMTP()
{

}

void SMTP::get_ds_sock(const struct iphdr* ip, const struct tcphdr* tcp, uint64_t& sip_port, uint64_t& dip_port)
{
	uint16_t sport = ntohs(tcp->source);
	sip_port =0;
	sip_port=ip->saddr<<16|sport;

	uint16_t dport = ntohs(tcp->dest);
	dip_port = 0;
	dip_port = ip->daddr<<16|dport;
	return;
}

//--------------------------------------------------------------------------------------
// Function name: smtp_task
//
// Description  : function deals with smtp constructure using threadpool
// Parameter    :
// Return		: void
//--------------------------------------------------------------------------------------
string SMTP::smtp_task(Ring_Util& util, const struct pcap_pkthdr_n * header, uint64_t dip_port)
{
	if(smtp_email_contents[dip_port].size()<=0) 
		return "NULL";
	
	char tmp_sub[20] = {0};
	sprintf(tmp_sub,  "%ld-%ld", header->ts.tv_sec,header->ts.tv_usec);
	string sub = tmp_sub;
	sub.append(".eml");
	string email_name = sub;
	sub = util.mkdir_for_today("smtp", sub, "EMAIL");

	// 1.push losted packet and form the correct packet stream according to sequence number
	for(size_t i=0; i<smtp_lost_contents[dip_port].size();i++)
	{
		if( smtp_lost_contents[dip_port][i].the_seq == smtp_email_contents[dip_port][smtp_email_contents[dip_port].size()-1].next_seq )
		{
			smtp_email_contents[dip_port].push_back(smtp_lost_contents[dip_port][i]);
		}
	}

	ofstream out(sub.c_str(),ios::out|ios::app|ios::binary);
	for(size_t i=0; i<smtp_email_contents[dip_port].size(); i++)
	{
		const u_char* ch = (u_char*)smtp_email_contents[dip_port][i].packet.c_str();
		for(size_t j = 0; j < smtp_email_contents[dip_port][i].packet.length(); j++)
		{
			out.put(*ch);
			ch++;
		}
	}
	Map_Pack_smtp::iterator itr1, itr2;
	itr1 = smtp_email_contents.find(dip_port);
	itr2 = smtp_lost_contents.find(dip_port);
	if(itr1!=smtp_email_contents.end())  smtp_email_contents.erase(itr1);
	if(itr2!=smtp_lost_contents.end() )  smtp_lost_contents.erase(itr2);

	smtp_flag[dip_port]=1; // set flag, that means the email has been constructed
	
	//utstatic int sum_count=1;il.save_userinfo(smtp_userinfo, dip_port, sub, "smtp");type,:userna
	//itr = smtp_userinfo.find(dip_port);
	//if(itr!=smtp_userinfo.end())  smtp_userinfo.erase(itr);

	return sub;
}

void SMTP::init(PacketInfo *pktInfo)
{
	header = pktInfo->pkt;
	mac = pktInfo->destMac;
	ip = ( struct iphdr*) pktInfo->ip;
	tcp = ( struct tcphdr*) pktInfo->tcp;
	payload = (u_char*) pktInfo->body;
	srcIpv4 = pktInfo->srcIpv4;
	destIpv4 = pktInfo->destIpv4;
	timeVal = (time_t)pktInfo->pkt->ts.tv_sec;
// 	cout<<"==========\npktInfo->pkt->caplen:"<<pktInfo->pkt->caplen;
// 	cout<<"len"<<pktInfo->pkt->len;
// 	cout<<"eth_offset:" <<pktInfo->pkt->parsed_pkt.pkt_detail.offset.eth_offset;
// 	cout<<"l3_offset:" <<pktInfo->pkt->parsed_pkt.pkt_detail.offset.l3_offset;
// 	cout<<"l4_offset:" <<pktInfo->pkt->parsed_pkt.pkt_detail.offset.l4_offset;
// 	cout<<"payload:"<<pktInfo->pkt->parsed_pkt.pkt_detail.offset.payload_offset;
	//cout<<"packet"<<pktInfo->packet+54<<endl;
	//cout<<"pktInfo->body:"<<pktInfo->body<<endl;

	size_payload = pktInfo->bodyLen;
	string pack_temp = (const char*)payload;
	//cout<<"LEN: "<<pktInfo->bodyLen<<endl;
	//cout<<"pack_temp:"<<pack_temp<<endl;
	pack_info = pack_temp.substr(0, size_payload);
	//cout<<"pack_info:"<<pack_info<<endl;
	get_ds_sock(ip, tcp, sip_port, dip_port);

	packet_element.the_seq = ntohl(tcp->seq);
	packet_element.packet = pack_info;
	packet_element.next_seq = ntohl(tcp->seq) + size_payload;
}

//--------------------------------------------------------------------------------------
// Function name: analyse_smtp
//
// Description  : function deals with smtp packet which has been filtered
// Parameter    :
// Return	: void
//--------------------------------------------------------------------------------------
//void SMTP::analyse_smtp(struct pfring_pkthdr* header, const struct sniff_ip* ip, const struct sniff_tcp* tcp, u_char*  payload)
bool SMTP::analyse_smtp(PacketInfo* pktInfo)
{
#ifdef MULTI_PORT   // closed by zhangzm
	if (!isRunning_)
	{
		return false;
	}

	boost::mutex::scoped_lock lock(setMut_);
	s_to_c = false;
	if (portSet_.find(pktInfo->srcPort) != portSet_.end()) 
		s_to_c = true;

	if (!s_to_c && portSet_.find(pktInfo->destPort) == portSet_.end())
	{
		return false;
	}
#else
	if (pktInfo->srcPort == 25)
		s_to_c = true;
	else if (pktInfo->destPort == 25)
		s_to_c = false;
	else
		return false;
#endif
	
	init(pktInfo);
	
	if (s_to_c)
	{
		analyse_server();
	}
	else
	{
		analyse_client();
	}
	
	return true;
}

bool SMTP::analyse_server()
{
	if ((size_payload < 100) && (pack_info=="334 VXNlcm5hbWU6\r\n" || pack_info=="334 UGFzc3dvcmQ6\r\n" || pack_info=="334 dXNlcm5hbWU6\r\n"))
	{
		//cout<<"eeeeeeeeeeeeee"<<endl;
		smtp_user_sequence[dip_port] = ntohl(tcp->ack_seq);
		//cout<<"SMTP:name & password  请求应答号：："<<smtp_user_sequence[dip_port]<<endl;
	}
	
	if (tcp->fin==1 && (email_smtp.find(dip_port)!=email_smtp.end()))
	{
		//cout<<"ffffffffffffffffffffff"<<endl;
		if (smtp_flag[dip_port] == 0)
		{
			// 1. construct email
			string email_name = smtp_task(util, header, dip_port);
			if (smtp_userinfo[dip_port].size() < 2)
			{
				LOG_DEBUG("smtp_userinfo[dip_port].size()=%d\n",smtp_userinfo[dip_port].size());
				//return false;
			}
			
			// email from and email to must contains character '@'
			if (smtp_from[dip_port].find('@') == string::npos)
				return false; //|| smtp_to[dip_port].find('@')==string::npos
			
			char subject[256] = {0};
			util.utf8togb2312(smtp_subject[dip_port].c_str(), smtp_subject[dip_port].length(), subject, 256);

			// 2���ж����ؿ����ݻ��Ƿ�������

			char strmac[20] = {0};
			strcpy(strmac, ParseMac(mac));
			//unsigned int clue_id=GetClueId(PROTOCOL_SMTP, strmac,ip->daddr, smtp_from[dip_port].c_str());
            
			// 3.�����Ƿ������ݣ���дxml�ļ�

			//char emlFilePath[256];
			//sprintf(emlFilePath,"%s%s",localIp,email_name.c_str());
			
			
			int clue_id = 0;
			char tmp[256] = {0};
			clue_id = get_clue_id(strmac, inet_ntoa(*(struct in_addr *)&(ip->daddr)));

			/*write email data to shared memory, by zhangzm*/
			EMAIL_T tmp_data;
			memset(&tmp_data, 0, sizeof(tmp_data));
			
			tmp_data.p_data.clueid = clue_id;
			tmp_data.p_data.readed = 0;
			strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&(ip->daddr)));
			strncpy(tmp_data.p_data.clientMac, strmac, 17);
			sprintf(tmp_data.p_data.clientPort, "%d", ntohs(tcp->dest));
			strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&(ip->saddr)));
			sprintf(tmp_data.p_data.serverPort, "%d", ntohs(tcp->source));
			
			tmp_data.p_data.captureTime = (unsigned int)timeVal;

			if(smtp_userinfo[dip_port].size() >= 2)
			{
				strncpy(tmp_data.username, util.Base64Decode(smtp_userinfo[dip_port][0]).c_str(), 64);
				strncpy(tmp_data.password, util.Base64Decode(smtp_userinfo[dip_port][1]).c_str(), 64);
			}
			else if(smtp_userinfo[dip_port].size() == 1)
			{
				strncpy(tmp_data.username, util.Base64Decode(smtp_userinfo[dip_port][0]).c_str(), 64);
				strcpy(tmp_data.password, "");
			}
			else
			{
				strcpy(tmp_data.username, "");
				strcpy(tmp_data.password, "");
			}

			tmp_data.sendTime = (unsigned int)timeVal;
			strncpy(tmp_data.sendAddr, smtp_from[dip_port].c_str(), 259);
			strncpy(tmp_data.recvAddr, smtp_to[dip_port].c_str(), 259);
			strncpy(tmp_data.ccAddr, smtp_cc[dip_port].c_str(), 259);
			strcpy(tmp_data.bccAddr, "");
			strncpy(tmp_data.subject, subject, 259);
			strncpy(tmp_data.datafile, email_name.c_str(), 259);
			
			tmp_data.p_data.proType = 402;
			tmp_data.p_data.deleted = 0;
			msg_queue_send_data(EMAIL, (void *)&tmp_data, sizeof(tmp_data));

			// 4. ��������
			smtp_userinfo[dip_port].clear();
			clear_info();
		}
	}
	return true;
}

void SMTP::analyse_client()
{
	if (ntohl(tcp->seq) == smtp_user_sequence[sip_port])
	{
		//cout<<"确认号：："<<ntohl(tcp->seq)<<endl;
		//cout<<"pack_info"<< pack_info<<endl;
		vector<string>::iterator itr = find(smtp_userinfo[sip_port].begin(), smtp_userinfo[sip_port].end(), pack_info.substr(0, pack_info.find('\r')));
		if (itr == smtp_userinfo[sip_port].end())
		{
			string name_pass = pack_info.substr(0, pack_info.find('\r'));
			//cout<<"neme_pass;;"<<name_pass<<endl;
			smtp_userinfo[sip_port].push_back(name_pass);
		}
	}
	if (5!=smtp_stat[sip_port] && pack_info.find("Subject:")!=string::npos)
	{
		smtp_affixFlag[sip_port]=0;// 0 is no affix ; 1 is affix
		email_smtp[sip_port] = "test.eml";
		smtp_flag[sip_port]=0;	// set to 0,used for construct email
		smtp_stat[sip_port]=5;
		smtp_email_contents[sip_port].push_back(packet_element);
		save_emailsub(smtp_subject, sip_port, pack_info);
		save_emailfrom(smtp_from, sip_port, pack_info);
		save_emailto(smtp_to, sip_port, pack_info);
		save_emailcc(smtp_cc, sip_port, pack_info);
		if(pack_info.find("multipart/mixed;")!=string::npos)
		{
			smtp_affixFlag[sip_port] = 1; //带附件的！
		}
	}
	
	if( 5==smtp_stat[sip_port] && email_smtp.find( sip_port )!=email_smtp.end() )
	{
		size_t e_size = smtp_email_contents[sip_port].size();
		// 1. make sure the packet is the next wanted packet, then push back the packet
		if( ntohl(tcp->seq)==smtp_email_contents[sip_port][e_size-1].next_seq )
		{
			smtp_email_contents[sip_port].push_back(packet_element);
		}
		// 2. if next packet's sequence number in not the expected one, but it contains
		// repeated data, and we should judge its data
		else if( (ntohl(tcp->seq)>smtp_email_contents[sip_port][e_size-1].the_seq)
					&&(ntohl(tcp->seq)<smtp_email_contents[sip_port][e_size-1].next_seq)
					&&(ntohl(tcp->seq)+size_payload>smtp_email_contents[sip_port][e_size-1].next_seq) )
		{
			// 2.1 calculate numbers of bytes repeated
			int count = smtp_email_contents[sip_port][e_size-1].next_seq - ntohl(tcp->seq);
			// 2.2 adjust sequence number of the packet
			packet_element.the_seq = ntohl(tcp->seq) + count;
			// 2.3 adjust length of the packet(minus repeated data length)
			packet_element.next_seq = ntohl(tcp->seq) + size_payload;
			// 2.4 adjust packet info(delete repeated data info)
			u_char* re_payload = (u_char*)(payload + count);
			string re_packet = (const char*)re_payload;
			packet_element.packet = re_packet.substr(0,size_payload-count);
			// 2.5 push back adjusted packet
			smtp_email_contents[sip_port].push_back(packet_element);
		}
		// 3. if next packet's sequence number larger than the expected one, then store it
		// because it may be the packet which has been received in advance
		else if( ntohl(tcp->seq)>smtp_email_contents[sip_port][e_size-1].next_seq )
		{
			smtp_lost_contents[sip_port].push_back(packet_element);
		}
	}

}
	

	// ���淢���˵�ַ���ռ��˵�ַ�����͵�ַ���ʼ�����
	//util.save_emailinfo(smtp_userinfo, sip_port, pack_info);
				//my_occi->SetInt(stmt_, 1, timeVal); //EMAILID


/*
	// �����ô��룬����ʱɾ��
	FILE *stream_dst;
	string file_path = util.mkdir_for_today("smtp", "test.xml");
	stream_dst = fopen( file_path.c_str(), "r+" ); // append info to file
	if( stream_dst==NULL ){
		CLogger::Get_Instance().Error("smtp","The file smtp_info.txt was not opened correctly!");
		return; 
}
	fseek(stream_dst,-8,SEEK_END); // locate to </body>

	//printf("Packet Number %d:\n", count);
	fprintf( stream_dst, "<%s_%d>\n", "Packet_Number", count );
	//util.write_info(stream_dst,ip,tcp,payload);
	fprintf( stream_dst, "%s%s%s\n", "	<Source_IP>", inet_ntoa(ip->ip_src), "</Source_IP>" );
	fprintf( stream_dst, "%s%s%s\n", "	<Dest_IP>", inet_ntoa(ip->ip_dst), "</Dest_IP>" );
	fprintf( stream_dst, "%s%d%s\n", "	<Source_Port>", ntohs(tcp->th_sport), "</Source_Port>");
	fprintf( stream_dst, "%s%d%s\n", "	<Dest_Port>", ntohs(tcp->th_dport), "</Dest_Port>");	
	fprintf( stream_dst, "%s%d%s\n", "	<SYN_Flag>", (tcp->th_flags & 0x02)>1, "</SYN_Flag>");
	fprintf( stream_dst, "%s%d%s\n", "	<FIN_Flag>", tcp->th_flags & 0x01, "</FIN_Flag>");
	fprintf( stream_dst, "%s%d%s\n", "	<Seq_Number>", ntohl(tcp->th_seq), "</Seq_Number>");
	fprintf( stream_dst, "%s%d%s\n", "	<Ack_Number>", ntohl(tcp->th_ack), "</Ack_Number>");
	fprintf( stream_dst, "	</TCP_Header>\n" );

	if( size_payload > 0 ){
		//printf("	Payload (%d bytes):\n", size_payload);
		fprintf( stream_dst, "%s%d%s\n", "	<Payload_", size_payload, ">");
		util.print_payload(payload, size_payload, stream_dst);
		fprintf( stream_dst, "%s%d%s\n", "</Payload_", size_payload, ">");
}

	fprintf( stream_dst, "<%s_%d>\n", "/Packet_Number", count++ );
	fprintf( stream_dst, "%s", "</body>\n");
	fclose( stream_dst );
*/
	//CLogger::Get_Instance().Trace("smtp","SMTP::analyse_smtp(...)---->>>>");

//--------------------------------------------------------------------------------------
// Function name: clear_info
//
// Description  : clear email information when needed
// Parameter    :
// Return				: void
//--------------------------------------------------------------------------------------
void SMTP::clear_info()
{
	smtp_subject.clear();
	smtp_from.clear();
	smtp_to.clear();
	smtp_cc.clear();
	smtp_user_sequence.clear();
	smtp_flag.clear();
	smtp_stat.clear();
}

void SMTP::AddFilterPort(int port)
{
	boost::mutex::scoped_lock lock(setMut_);
	portSet_.insert((u_short)port);
}

void SMTP::ClearFilterPort()
{
	boost::mutex::scoped_lock lock(setMut_);
	portSet_.clear();
	portSet_.insert(25);
}

void SMTP::SetStatus(bool isRunning, u_int attachSize, bool isDeepParsing)
{
	isRunning_ = isRunning;
	attachSize_ = attachSize;
	isDeepParsing_ = isDeepParsing;
}

char* SMTP::ParseMac(const u_char* packet)
{
	//assert(packet != 0);
	if (packet == NULL)
		return NULL;
	
	sprintf(mac_, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\0",
		*reinterpret_cast<const u_char*>(packet),
		*reinterpret_cast<const u_char*>(packet + 1),
		*reinterpret_cast<const u_char*>(packet + 2),
		*reinterpret_cast<const u_char*>(packet + 3),
		*reinterpret_cast<const u_char*>(packet + 4),
		*reinterpret_cast<const u_char*>(packet + 5));

	return mac_;
}
void SMTP::save_emailsub(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info)
{
	// �����ʼ�����

	if( pack_info.find("Subject: ")!=string::npos ){
		int index1 = pack_info.find("Subject: ");
		int index2 = pack_info.find('\r',index1);		// \r after subject
		string subject = pack_info.substr( index1+strlen("Subject: "), index2-index1-strlen("Subject: ") );
		subject =util.get_subject(subject);

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
void SMTP::save_emailfrom(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info)
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
void SMTP::save_emailto(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info)
{
	if( userinfo[ip_port].find('@')!=string::npos) return;

	// �����ռ��˵�ַ
	if( pack_info.find("\r\nTo: ")!=string::npos ){
		int index1 = pack_info.find("\r\nTo: ");
		int index2 = pack_info.find("\r\n", index1);
		string email_to = pack_info.substr(index1+2,index2-index1-1);
		
		//printf("-->%s\n",email_to.c_str());
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
void SMTP::save_emailcc(NameMap_smtp& userinfo, const uint64_t& ip_port, const string& pack_info)
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
