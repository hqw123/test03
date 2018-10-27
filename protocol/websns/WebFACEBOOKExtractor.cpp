
#include <map>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "WebFACEBOOKExtractor.h"
#include "Public.h"
#include "clue_c.h"

static AttachTable attach_list;

#define SEND_STATUS_RULE "POST\\s/ajax/updatestatus.php.__a=1\\sHTTP/1(.+)"
#define SENDD_STATUS_RULE "POST\\s/ajax/updatestatus.php(.+?);\\sc_user=(\\d+?);(.+?)&xhpc_message_text=(.+?)&xhpc_message=(.+)"
#define SEND_RULE "POST\\s/ajax/chat/send.php.__a=1\\sHTTP/1(.+)"
#define SENDD_RULE "POST\\s/ajax/chat/send.php(.+?);\\sc_user=(\\d+?);(.+?)&to=(\\d+?)&num_tabs(.+?)&msg_text=(.+?)&to_offline(.+)"
#define SEND_NEWS_RULE "POST\\s/ajax/messaging/async.php.__a=1\\sHTTP/1(.+)"
#define SENDD_NEWS_1_RULE "POST\\s/ajax/messaging/async.php(.+?);\\sc_user=(\\d+?);(.+?)&body=(.+?)&action=send&recipients\\[0\\]=(\\d+?)&force_sms=(true|false)(.*)&post_form_id=(.+?)&fb_dtsg(.+)"
#define SENDD_NEWS_2_RULE "POST\\s/ajax/messaging/async.php(.+?);\\sc_user=(\\d+?);(.+?)&recipients\\[0\\]=(\\d+?)&body=(.+?)&action=send&force_sms=(true|false)&send_on_enter=false(.*)&post_form_id=(.+?)&fb_dtsg(.+)"
#define UPLOAD_RULE "POST\\s/ajax/messaging/upload.php\\sHTTP/1(.+)"
#define UPLOADD_RULE "Content-Disposition:\\sform-data;\\sname=\"uploadbutton\"\r\n\r\n"
#define REPLY_STATUS_RULE "POST\\s/ajax/ufi/modify.php.__a=1\\sHTTP/1(.+)"
#define REPLYY_STATUS_RULE "POST\\s/ajax/ufi/modify.php(.+?);\\sc_user=(\\d+?);(.+?)%22target_profile_id%22%3A%22(\\d+?)%22(.+?)&add_comment_text=(.+?)&(.+)"
#define RECV_STATUS_RULE "\"from_uid\":(\\d+?),\"context_id\":(.+?),\"owner\":\"(\\d+?)\",\"text\":\"(.+?)\",\"object_id\":(.+)"
#define RECV_RULE "for\\s\\(;;\\);\\{\"t\":\"msg\"(.+?)\"ms\":\\[\\{\"msg\":\\{\"text\":\"(.+?)\",\"time\":(.+?)\\},\"from\":(.+?),\"to\":\"(.+?)\",\"from_name\":(.+?)\"from_gender\":1,\"fl\":1,\"to_name\":(.+?)\"type\":\"msg\"\\}\\]\\}"

using namespace std;

//set<string> chatset;


WebFACEBOOKExtractor::WebFACEBOOKExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/WEBSNS/FACEBOOK");
	sprintf(ATTCHPATH,"%s%s",LzDataPath,"/spyData/moduleData/Facebook");
	sprintf(ATTCHTEMP,"%s%s",LzDataPath,"/spyData/moduleData/Facebook/temp");
	isRunning_ = true;
	isDeepParsing_ = false;
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	mkdir(ATTCHPATH, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	mkdir(ATTCHTEMP, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	sendRule_ = new boost::regex(SEND_RULE);
	senddRule_ = new boost::regex(SENDD_RULE);
	sendNewsRule_ = new boost::regex(SEND_NEWS_RULE);
	senddNews1Rule_ = new boost::regex(SENDD_NEWS_1_RULE);
	senddNews2Rule_ = new boost::regex(SENDD_NEWS_2_RULE);
	uploadRule_ = new boost::regex(UPLOAD_RULE);
	uploaddRule_ = new boost::regex(UPLOADD_RULE);
	sendStatusRule_ = new boost::regex(SEND_STATUS_RULE);
	senddStatusRule_ = new boost::regex(SENDD_STATUS_RULE);
	replyStatusRule_ = new boost::regex(REPLY_STATUS_RULE);
	replyyStatusRule_ = new boost::regex(REPLYY_STATUS_RULE);
	recvStatusRule_ = new boost::regex(RECV_STATUS_RULE);
	recvRule_ = new boost::regex(RECV_RULE);
	memcpy(tableName_, "WEBSNS", 7);
	
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);

	attach_list.head = (Attach_info *)malloc(sizeof(Attach_info));
	if (attach_list.head == NULL)
	{
		perror("websns:init()->malloc()2");
		//return -1;
	}
	attach_list.head->next = NULL;
	attach_list.head->prev = NULL;
	attach_list.tail = attach_list.head;
	attach_list.count = 0;
}

WebFACEBOOKExtractor::~WebFACEBOOKExtractor()
{
	delete sendRule_;
	delete senddRule_;
	delete sendNewsRule_;
	delete senddNews1Rule_;
	delete senddNews2Rule_;
	delete uploadRule_;
	delete uploaddRule_;
	delete sendStatusRule_;
	delete senddStatusRule_;
	delete replyStatusRule_;
	delete replyyStatusRule_;
	delete recvStatusRule_;
	delete recvRule_;
}

bool WebFACEBOOKExtractor::IsWebSNSText(PacketInfo* pktInfo)
{
	bool iswebFBText = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;

	if(boost::regex_match(first, last, matchedStr, *sendRule_)){
//	cout<<"/////////////////////sendRule_!!!"<<endl;
	LOG_INFO("/////////////////////sendRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *sendNewsRule_)){
//cout<<"///////////////////////////sendNewsRule_!!!"<<endl;
		LOG_INFO("///////////////////////////sendNewsRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *uploadRule_)){
//cout<<"///////////////////////////uploadRule_!!!"<<endl;
		LOG_INFO("///////////////////////////uploadRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		if(attach_list.count == 20){
			Attach_info *attach_tmp = attach_list.tail;
			attach_list.tail->prev->next=NULL;
			attach_list.tail=attach_list.tail->prev;
			free(attach_tmp);
			attach_list.count--;
		}
		attach_info = (Attach_info *)malloc(sizeof(Attach_info));
		attach_info->prev = attach_list.head;
		attach_info->next = attach_list.head->next;
		attach_list.head->next = attach_info;
		attach_list.count++;
		if (attach_info->next != NULL)
			attach_info->next->prev = attach_info;
		else
			attach_list.tail = attach_info;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *sendStatusRule_)){
//cout<<"/////////////////////////sendStatusRule_!!!"<<endl;
		LOG_INFO("/////////////////////////sendStatusRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *replyStatusRule_)){
//cout<<"///////////////////////////replyStatusRule_!!!"<<endl;
		LOG_INFO("///////////////////////////replyStatusRule_!!!\n");
		sendSeq_ = -1;
		sendBody_ = NULL;
		sendBodyLen_ = 0;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		sendBodyLen_ = pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = str;

		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(ntohl(pktInfo_->tcp->seq) == sendSeq_){
//cout<<"/////////////////////sendSeq_!!!"<<endl;
		LOG_INFO("/////////////////////sendSeq_!!!\n");
//cout<<"sendBodyLen_ = "<<sendBodyLen_<<"pktInfo_->bodyLen = "<<pktInfo_->bodyLen<<endl;
		LOG_INFO("sendBodyLen_ = %d pktInfo_->bodyLen = %d\n",sendBodyLen_,pktInfo_->bodyLen);
		sendBodyLen_ = sendBodyLen_ + pktInfo_->bodyLen;cout<<"sendBodyLen_ = "<<sendBodyLen_<<endl;
		sendSeq_ = ntohl(pktInfo_->tcp->seq) + pktInfo_->bodyLen;
		char* str = new char[pktInfo_->bodyLen + 1];
		str[pktInfo_->bodyLen] = 0;
		memcpy(str, pktInfo_->body, pktInfo_->bodyLen);
		sendBody_ = (char *)realloc(sendBody_, sendBodyLen_ + 1);
		strncat(sendBody_, str, pktInfo_->bodyLen);

		const char* firstt = sendBody_;
		const char* lastt = sendBody_ + sendBodyLen_;
		if(boost::regex_search(firstt, lastt, matchedStr, *senddRule_)){
//cout<<"/////////////////////senddRule_!!!"<<endl;
			LOG_INFO("/////////////////////senddRule_!!!\n");
			int len = matchedStr[4].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* toId=str;
	
			len = matchedStr[2].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[6].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[6].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);

			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);           // cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                       //  cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=toId;                             //cout<<"toId = "<<node->toId<<endl;
			LOG_INFO("toId = %s\n",node->toId);
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=Msg;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_search(firstt, lastt, matchedStr, *senddNews1Rule_)){

			LOG_INFO("///////////////////////////senddNews1Rule_!!!\n");
			int len = matchedStr[5].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[5].first, len);
			char* toId=str;
	
			len = matchedStr[2].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[4].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);     //cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=toId;                      //cout<<"toId = "<<node->toId<<endl;
			LOG_INFO("toId = %s\n",node->toId);
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=News;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;

			if(matchedStr[7].length() > 0)
			{
				len = matchedStr[8].length();
				str=new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[8].first, len);
				char* id_str=str;
				char save_path[MAX_PATH_LEN + 1];
				memset(save_path,0,MAX_PATH_LEN + 1);
				create_dir(save_path,fromId);
				node->attchmentpath = save_path;
				char writepath[MAX_PATH_LEN] = {0};
				Attach_info *attach_info;
				attach_info=attach_list.head->next;
				int  i=0;
				while(attach_info!=NULL)
				{
					if(!strcmp(attach_info->ID_str,id_str))
					{
						i++;
						char loc_filename[MAX_FN_LEN + 1];
						snprintf(loc_filename, MAX_FN_LEN, "attach%d_%s", i,attach_info->attach_name);
						sprintf(writepath,"%s/%s",save_path,loc_filename);
						link(attach_info->path_of_here,writepath);
						unlink(attach_info->path_of_here);
						node->attchmentname = (char *)malloc(MAX_PATH_LEN);
						memset(node->attchmentname,0,MAX_PATH_LEN);
						if(i > 1)
						{
							strcat(node->attchmentname,"|");
						}
						strcat(node->attchmentname,loc_filename);        // cout<<"attchmentname = "<<node->attchmentname<<endl;
						LOG_INFO("attchmentname = %s\n",node->attchmentname);
						del_attach_node(attach_info);
						free(attach_info);
						continue;
					}
					attach_info = attach_info->next;
				}
			}
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_search(firstt, lastt, matchedStr, *senddNews2Rule_)){
//cout<<"///////////////////////////senddNews2Rule_!!!"<<endl;
			LOG_INFO("///////////////////////////senddNews2Rule_!!!\n");
			int len = matchedStr[4].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* toId=str;
	
			len = matchedStr[2].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[5].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[5].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text, node->text);    // cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n", node->text);
			node->fromId=fromId;                 // cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n", node->fromId);
			node->toId=toId;                      //cout<<"toId = "<<node->toId<<endl;
			LOG_INFO("toId = %s\n", node->toId);
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=News;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;

			if(matchedStr[7].length() > 0)
			{
				len = matchedStr[8].length();
				str=new char[len + 1];
				str[len] = 0;
				memcpy(str, matchedStr[8].first, len);
				char* id_str=str;
				char save_path[MAX_PATH_LEN + 1];
				memset(save_path,0,MAX_PATH_LEN + 1);
				create_dir(save_path,fromId);
				node->attchmentpath = save_path;
				char writepath[MAX_PATH_LEN] = {0};
				Attach_info *attach_info;
				attach_info=attach_list.head->next;
				int  i=0;
				while(attach_info!=NULL)
				{
					if(!strcmp(attach_info->ID_str,id_str))
					{
						i++;
						char loc_filename[MAX_FN_LEN + 1];
						snprintf(loc_filename, MAX_FN_LEN, "attach%d_%s", i,attach_info->attach_name);
						sprintf(writepath,"%s/%s",save_path,loc_filename);
						link(attach_info->path_of_here,writepath);
						unlink(attach_info->path_of_here);
						node->attchmentname = (char *)malloc(MAX_PATH_LEN);
						memset(node->attchmentname,0,MAX_PATH_LEN);
						if(i > 1)
						{
							strcat(node->attchmentname,"|");
						}
						strcat(node->attchmentname,loc_filename);         //cout<<"attchmentname = "<<node->attchmentname<<endl;
						LOG_INFO("attchmentname = %s\n",node->attchmentname);
						del_attach_node(attach_info);
						free(attach_info);
						continue;
					}
					attach_info = attach_info->next;
				}
			}
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_search(firstt, lastt, matchedStr, *uploaddRule_)){
			LOG_INFO("///////////////////////////uploaddRule_!!!\n");
			char *p = strstr(sendBody_, "\r\nContent-Length: ");
			p += 18;
			attach_info->attch_length = 0;
			while( *p != '\r')
			{
				attach_info->attch_length = attach_info->attch_length * 10 + (*p - '0');
				p++;
			}
			char *p1=strstr(sendBody_,"name=\"post_form_id\"\r\n\r\n");
			p1+=23;
			char *p2=strstr(p1,"\r\n----");
			strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
			attach_info->ID_str[p2-p1]=0;
			p1=strstr(p1,"; filename=\"");
			p1+=12;
			p2=strstr(p1,"\"\r\n");
			strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
	                attach_info->attach_name[p2-p1]=0;                       // cout<<",,,,,,,,,,"<<attach_info->attach_name<<endl;
	                LOG_INFO(",,,,,,,,,,%s\n",attach_info->attach_name);
			p1=strstr(p1,"\r\n\r\n");
			p1+=4;
			p2 = memfind(p1, "\r\n----------", attach_info->attch_length-(p1-sendBody_));
			struct timeval tv;//creat temp attach file
			struct timezone tz;
			gettimeofday(&tv,&tz);
			memset(attach_info->path_of_here,0,MAX_PATH_LEN + 1);
			sprintf(attach_info->path_of_here,"%s/%lu-%lu",ATTCHTEMP,tv.tv_sec,tv.tv_usec); //3
			mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
			int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
			write(fd,p1,p2-p1);
			close(fd);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_match(firstt, lastt, matchedStr, *senddStatusRule_)){

			LOG_INFO("/////////////////////////senddStatusRule_!!!\n");
			int len = matchedStr[2].length();
			char *str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[4].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);    // cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=NULL;
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=Status;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=0;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}else if(boost::regex_search(firstt, lastt, matchedStr, *replyyStatusRule_)){
//cout<<"///////////////////////////replyyStatusRule_!!!"<<endl;
			LOG_INFO("///////////////////////////replyyStatusRule_!!!\n");
			int len = matchedStr[4].length();
			char* str = new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[4].first, len);
			char* toId=str;
	
			len = matchedStr[2].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[2].first, len);
			char* fromId =str;
	
			len = matchedStr[6].length();
			str=new char[len + 1];
			str[len] = 0;
			memcpy(str, matchedStr[6].first, len);
			char* text=str;
		
			Node* node = new Node;
			memset(node, 0, sizeof(Node));
			// Copy basic data to message node
			memcpy(node, pktInfo_, COPY_BYTES);
			
			node->text = new char [1500];
			memset(node->text,0,1500);
			htmldecode_full(text,node->text);     //cout<<"text = "<<node->text<<endl;
			delete[] text;
			LOG_INFO("text = %s\n",node->text);
			node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
			LOG_INFO("fromId = %s\n",node->fromId);
			node->toId=toId;                      //cout<<"toId = "<<node->toId<<endl;
			LOG_INFO("toId = %s\n",node->toId);
			node->from=NULL;
			node->to=NULL;
			node->msgType=Text;
			node->contentType=Status;
			node->time = NULL;
			time(&node->timeVal);
			u_int clueId=0;
			
			node->protocolType = 1002;
			char strmac[20] = {0};
			ParseMac(pktInfo_->destMac, strmac);
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->destIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
			
			node->clueId = clueId;
			node->fileName = NULL;
			node->affixFlag=9000;
			node->attchmentname = NULL;
			node->attchmentpath = NULL;
			//StoreMsg2DB(node);
			sendSeq_ = -1;
			sendBody_ = NULL;
			sendBodyLen_ = 0;
		}
		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_search(first, last, matchedStr, *recvStatusRule_)){
//cout<<"///////////////////////////recvStatusRule_!!!"<<endl;
		LOG_INFO("///////////////////////////recvStatusRule_!!!\n");
		int len = matchedStr[3].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[3].first, len);
		char* toId=str;

		len = matchedStr[1].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[1].first, len);
		char* fromId =str;

		len = matchedStr[4].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[4].first, len);
		char* text=str;
	
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text = new char [1500];
		memset(node->text,0,1500);
		htmldecode_full(text,node->text);     //cout<<"text = "<<node->text<<endl;
		delete[] text;
		LOG_INFO("text = %s\n",node->text);
		node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
		LOG_INFO("fromId = %s\n",node->fromId);
		node->toId=toId;                     // cout<<"toId = "<<node->toId<<endl;
		LOG_INFO("toId = %s\n",node->toId);
		node->from=NULL;
		node->to=NULL;
		node->msgType=Text;
		node->contentType=Status;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = 1002;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
		
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag=9000;
		node->attchmentname = NULL;
		node->attchmentpath = NULL;
		//StoreMsg2DB(node);
		iswebFBText = true;
		pktInfo_ = NULL;
	}else if(boost::regex_match(first, last, matchedStr, *recvRule_)){
		LOG_INFO("///////////////////////////recvRule_!!!\n");
		int len = matchedStr[5].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[5].first, len);
		char* toId=str;

		len = matchedStr[4].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[4].first, len);
		char* fromId =str;

		len = matchedStr[2].length();
		str=new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		char* text=str;
	
		Node* node = new Node;
		memset(node, 0, sizeof(Node));
		// Copy basic data to message node
		memcpy(node, pktInfo_, COPY_BYTES);
		
		node->text=text;                     // cout<<"text = "<<node->text<<endl;
		LOG_INFO("text = %s\n",node->text);
		node->fromId=fromId;                  //cout<<"fromId = "<<node->fromId<<endl;
		LOG_INFO("fromId = %s\n",node->fromId);
		node->toId=toId;                      //cout<<"toId = "<<node->toId<<endl;
		LOG_INFO("toId = %s\n",node->toId);
		node->from=NULL;
		node->to=NULL;
		node->msgType=Text;
		node->contentType=Msg;
		node->time = NULL;
		time(&node->timeVal);
		u_int clueId=0;
		
		node->protocolType = 1002;
		char strmac[20] = {0};
		ParseMac(pktInfo_->destMac, strmac);
		//clueId = GetObjectId(strmac);
		struct in_addr addr;
		addr.s_addr = pktInfo_->destIpv4;
		clueId = get_clue_id(strmac, inet_ntoa(addr));
		
		node->clueId = clueId;
		node->fileName = NULL;
		node->affixFlag=9000;
		node->attchmentname = NULL;
		node->attchmentpath = NULL;
		//StoreMsg2DB(node);
		iswebFBText = true;
		pktInfo_ = NULL;
	}
	return iswebFBText;
}


int WebFACEBOOKExtractor::htmldecode_full(char *src, char *dest)
{
	int strlength=strlen(src);
	if(strlength<3)
	{
		strcpy(dest,src);
		return 0;
	}
	int i=0;
	int flag=0;
	int j=0;
	char tmp1=0;
	char tmp2=0;
	char tmpA=0;
	char tmpB=0;
	char A,B;

	for(i=0; i<strlength; i++)
	{
		if(src[i] =='%')
		{
			flag = 1;
			continue;
		}
		switch(flag)
		{
			case 0:
			{	
				
				dest[j]=src[i];
				if(dest[j] == '+') dest[j] = ' ';
				j++;
				break;
			}
			case 1:
				flag = 2;
				if(i < (strlength-12) &&src[i]=='5'   &&src[i+1]=='C'  && src[i+2]=='%' 
				   && src[i+3]=='5'   &&src[i+4]=='C' && src[i+5]=='r' &&src[i+6]=='%'
				   && src[i+7]=='5'   &&src[i+8]=='C' && src[i+9]=='%' && src[i+10]=='5'
				   && src[i+11]=='C'  && src[i+12]=='n' )
				{
					dest[j]=10;
					i=i+12;
					flag=0;
					j++;
					break;
				}
				if(i < (strlength-20)  && src[i]=='5'    && src[i+1]=='C'  && src[i+2]=='%' 
				     && src[i+3]=='2'  && src[i+4]=='2'  && src[i+5]=='%'  && src[i+6]=='2'
				     && src[i+7]=='C'  && src[i+8]=='%'  && src[i+9]=='5'  && src[i+10]=='C' 
				     && src[i+11]=='%' && src[i+12]=='2' && src[i+13]=='2' && src[i+14]=='%' 
				     && src[i+15]=='5' && src[i+16]=='C' && src[i+17]=='%' && src[i+18]=='5'
				     && src[i+19]=='C' && src[i+20]=='n')
				{
					dest[j]=10;
					i=i+20;
					flag=0;
					j++;
					break;
				}
				if(i < (strlength-10) &&src[i]=='5' &&src[i+1]=='C' && src[i+2]=='%' && 
					src[i+3]=='5' &&src[i+4]=='C'  &&src[i+5]=='%'
				   && src[i+6]=='5' &&src[i+7]=='C' && src[i+8]=='%' && 
					src[i+9]=='5' && src[i+10]=='C' )
				{
					dest[j]='\\';
					i=i+10;
					flag=0;
					j++;
					break;
				}
				tmpA = src[i];
				
				break;
			case 2:
				tmpB = src[i];
				tmp1 = toupper(tmpA);
				tmp2 = toupper(tmpB);
				if(((tmp1 >= 48&&tmp1 <= 57) || (tmp1 >= 65&&tmp1 <= 90)) && (
								 (tmp2 >= 48&&tmp2 <= 57) || (tmp2 >= 65 && tmp2 <= 90)))
				{
					if(tmp1 >= 48&&tmp1 <= 57) A = tmp1 - 48;
					else A = 10 + tmp1 - 65;
					if(tmp2 >= 48 && tmp2 <= 57) B = tmp2 - 48;
					else B = 10 + tmp2 - 65;
					dest[j] = A * 16 + B;
					
				}
				else
				{
					dest[j] = '%';
					dest[j+1] = tmp1;
					dest[j+2] = tmp2;
					j += 2;
				}
				flag = 0;
				j++;
				break;
			default:
				break;
		}
	}
	dest[j] = 0;
}


//-----------------------------------------------------------------------
// Func Name   : StoreMsg2DB
// Description : Store the message which is sent in text format.
// Parameter   : from: Source user of the message.
//               to: Destination user of the message.
//               text: Content of the message.
// Return      : void
//-----------------------------------------------------------------------
void WebFACEBOOKExtractor::StoreMsg2DB(Node* msgNode)
{
	struct in_addr addr;
	char tmp[256] = {0};
	char srcMac[20] = {0};

#if 0  //zhangzm websns
	string sql = "insert into websns(objectid,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,sendname,sendid,replyname,replyid,content,type,attchmentname,datafile)";
	sql+=" values(";
	sprintf(tmp, "%lu", msgNode->clueId);
	sql.append(tmp);
	sql+=",\'";
	addr.s_addr = msgNode->srcIpv4;
	sql+=inet_ntoa(addr);	//CLIENTIP
	sql+="\',\'";

	if(msgNode->affixFlag==9000){
		ParseMac(msgNode->destMac, srcMac);
	}
	else{
		ParseMac(msgNode->srcMac, srcMac);
	}
	sql+=srcMac;	//CLIENTMAC
	sql+="\',";
	sprintf(tmp, "%d", msgNode->srcPort);
	sql+=tmp; 		//CLIENTPORT
	sql+=",\'";
	addr.s_addr = msgNode->destIpv4;
	sql+=inet_ntoa(addr);	//serverip
	sql+="\',";
	sprintf(tmp, "%d",  msgNode->destPort);
	sql+=tmp;		//SERVERPORT
	sql+=",";
	sql+="now()";		//capturetime record currenttime
	sql+=",";
	switch (msgNode->msgType) {
		case Login:
			sprintf(tmp, "%d", 1);
			sql.append(tmp); 
			sql+=",";
			break;
		case Logout:
			sprintf(tmp, "%d", 2);
			sql.append(tmp); 
			sql+=",";
			break;
		case Text:
		case Qun:
		case Dis:
			sprintf(tmp, "%d", 3);
			sql.append(tmp); 
			sql+=",";
			break;
	}
	if (msgNode->text != NULL)
	{
		sql+="\'";
		sql+=msgNode->text; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	if (msgNode->from != NULL)
	{
		sql+="\'";
		sql+= msgNode->from; 	
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->fromId != NULL)
	{
		sql+="\'";
		sql+= msgNode->fromId; 	
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->to != NULL)
	{
		sql+="\'";
		sql+= msgNode->to; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	if (msgNode->toId != NULL)
	{
		sql+="\'";
		sql+= msgNode->toId; 	
		sql+="\',";
	}
	else
	{
		sql+="\' \',";
	}
	switch (msgNode->contentType) {
		case Rests:
			sprintf(tmp, "%d", 0);
			sql.append(tmp);
			sql+=",";
			break;
		case Msg:
			sprintf(tmp, "%d", 1);
			sql.append(tmp); 
			sql+=",";
			break;
		case News:
			sprintf(tmp, "%d", 2);
			sql.append(tmp); 
			sql+=",";
			break;
		case Status:
			sprintf(tmp, "%d", 3);
			sql.append(tmp); 
			sql+=",";
			break;
	}
	sprintf(tmp, "%lu", msgNode->protocolType);//TYPE
	sql+=tmp;
	sql+=",";
	if (msgNode->attchmentname != NULL)
	{
		sql+="\'";
		sql+= msgNode->attchmentname;
		sql+="\',";
	}
	else 
	{
		sql+="\' \',";
	}
	if (msgNode->attchmentpath != NULL)
	{
		sql+="\'";
		sql+= msgNode->attchmentpath;
		sql+="\'";
	}
	else 
	{
		sql+="\' \'";
	}
	sql+=")";
	//cout<<"SQL : "<<sql<<endl;
	sqlConn_->Insert(&sql);

//	AddObjectId (msgNode->clueId,srcMac);

// #ifndef VPDNLZ
// 	AddObjectId (msgNode->clueId,srcMac);
// 
// #endif
#endif

	xmlStore_.ClearNode(msgNode);
			
	cout<<"[WEBFACEBOOK] Data insert into DB!"<<endl;	
}

char *WebFACEBOOKExtractor::memfind(char *str, char *substr, size_t n)
{
	size_t i, len;
	char *p = str;
	char *p1 = NULL;
	char *p2 = NULL;

	if (str == NULL || substr == NULL)
		return NULL;
        if (n<strlen(substr)) return NULL;
	len = n - strlen(substr) + 1;
	for (i = 0; i < len; i++) {
		if (*p != *substr) {
			p++;
			continue;
		}

		p1 = substr;
		p2 = p;
		while (*p1 != 0) {
			if (*(++p2) != *(++p1))
				break;
		}
		if (*p1 == 0) {
			return p;
		}
		p++;
	}
	return NULL;
}

int WebFACEBOOKExtractor::create_dir(char *path, char *sns_name)
{
	time_t timeval;
	struct tm *tm_ptr = NULL;
	char tmp_name[MAX_UN_LEN+1];
	char dir_str[MAX_UN_LEN + TIME_LEN + 2];
	mode_t dir_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	int result;
	int len;
	len=strlen(sns_name);
	if(len>MAX_UN_LEN){
		strncpy(tmp_name,sns_name,MAX_UN_LEN);
		tmp_name[MAX_UN_LEN]='\0';
	} else {
		strcpy(tmp_name,sns_name);
	}

	mkdir(ATTCHPATH, dir_mode);
	timeval = time(NULL);
	tm_ptr = localtime(&timeval);

	sprintf(path, "%s/%d-%02d-%02d", ATTCHPATH, tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday );
	mkdir(path, dir_mode);

	sprintf(dir_str, "/%s_%02d_%02d_%02d", tmp_name, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
	strcat(path, dir_str);
	int ilen = strlen(path);
	char * i, * j;
	i = strstr(path, "&#64;");
	if(i)
	{
		*i = '@';
		j = i + 5;
		strcpy(i + 1, j);
		*(path + ilen - 1 - 4 ) = '\0';
	}
	//printf("path : %s\n", path);
	mkdir(path, dir_mode);
}

int WebFACEBOOKExtractor::del_attach_node(Attach_info *temp)
{
	//printf("del_attach_node ...\n");
	if (temp->next == NULL) 
	{
		attach_list.tail=temp->prev;
		temp->prev->next = NULL;
	} 
	else 
	{
		temp->prev->next = temp->next;
		temp->next->prev = temp->prev;
	}
	attach_list.count--;
	//printf("del_attach_node complete ...\n");
}

// End of file

