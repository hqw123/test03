//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 baihong Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     PopSession.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file defines the class for POP session catching
//
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 100227 wu zhonghua Initial
//
//------------------------------------------------------------------------

#include "PopSession.h"
#include "PopExtractor.h"
#include "XmlStorer.h"
#include "clue_c.h"

const u_short MIN_STATUS_LEN = 5;
const u_int QUIT_TAG = 0x54495551;   // "QUIT"
const u_int STAT_TAG = 0x204b4f2b;   // "+OK "
const u_int LIST_TAG = 0x5453494c;   // "LIST"
const u_int RETR_TAG = 0x52544552; //retr
const u_int TOP_TAG  =	0x20504f54;  //top
const u_int POP_END_TAG = 0x0a0d2e0a;
const u_int MIN_POP_HEAD = 32;
const u_short POP_PORT = 110;
const u_short FILE_NAME_LEN = 256;

PopSession::PopSession(void* obj,
                       const char* filePath,
                       boost::regex** statusRule,
					   boost::regex* dateRule,
					   boost::regex* fromRule,
					   boost::regex* toRule,
					   boost::regex* ccRule,
					   boost::regex* subjectRule,
					   boost::regex* contentTypeRule,
					   boost::regex* mailAddressRule,
                       const char* user,
					   u_int maxSize) : popStatus_(POP_LOGIN_STAT),
                                         obj_(obj),
                                         fileName_(NULL),
                                         validMail_(false),
                                         filePath_(filePath),
                                         emailList_(NULL),
                                         emailSum_(0),
                                         emailNum_(0),
                                         maxSize_(maxSize),
                                         user_(user),
                                         pass_(NULL),
										 date_(NULL),
                                         from_(NULL),
                                         to_(NULL),
										 cc_(NULL),
                                         subject_(NULL),
										 contentType_(NULL),
										 boundary_(NULL),
										 dateRule_(dateRule),
										 fromRule_(fromRule),
										 toRule_(toRule),
										 ccRule_(ccRule),
										 subjectRule_(subjectRule),
										 contentTypeRule_(contentTypeRule),
										 mailAddressRule_(mailAddressRule)
{
	emlBuf_=NULL;
    memcpy(statusRule_, statusRule, POP_STATUS_NUM * sizeof(boost::regex*));


	//strLocalIP_=localIp;
	//strLocalIP_=new char[16];
	//memset(strLocalIP_,0,16);
	//memcpy(strLocalIP_,localIp,strlen(localIp));
	baseSeq_=0;


}

PopSession::~PopSession()
{
//	cout << __FILE__ << ":" << __FUNCTION__ << endl;
	if (fileName_)
	{
			//::remove(fileName_);
			delete fileName_;
			fileName_=NULL;
	}
	if (emailList_) {
		delete emailList_;
	}
	if (fileStream_) {
		delete fileStream_;
		fileStream_ = NULL;
	}
	if (user_) {
		delete user_;
		user_ = NULL;
	}
	if (pass_) {
		delete pass_;
		pass_=NULL;
	}

//	cout << __FILE__ << ":" << __FUNCTION__ <<"end "<< endl;
// 	if(strLocalIP_)
// 	{
// 		delete strLocalIP_;
// 	}
}

bool PopSession::AddPacket(PacketInfo* packetInfo)
{
    packetInfo_ = packetInfo;
    switch (popStatus_)
	{
		case POP_LOGIN_STAT:
			//cout<<"pop POP_LOGIN_STAT!";
			OnLoginStat();
			break;
		case POP_RETRIEVE:
			//cout<<"pop POP_RETRIEVE!";
            OnRetr();
            break;
        case POP_QUIT:
        default:
			//cout<<"pop quit!111111111111111111\n";
            return false;
    }
    if (popStatus_ == POP_QUIT)
	{
		//cout<<"pop quit!22222222222222222222222\n";
		LOG_INFO("pop quit!22222222222222222222222\n");
        return false;
    }
    return true;
}

void PopSession::OnLoginStat()
{
	if (packetInfo_->bodyLen < MIN_STATUS_LEN)
	{
        return;
    }
	const char* first = packetInfo_->body;
	const char* last = packetInfo_->body + packetInfo_->bodyLen;
	boost::cmatch matchedStr;
	if (packetInfo_->srcPort == POP_PORT)   //server to cleint
	{
		if (boost::regex_search(first, last, matchedStr, *statusRule_[2]))
		{ 
			emailSum_ = atol(matchedStr[1].first);
			//cout << " [POP3] Loging get email TotalSum :::" << emailSum_<< endl;
		}
    }
	else if(packetInfo_->destPort == POP_PORT)  //cleint to server
	{
		if (IsQuit())
		{
			popStatus_ = POP_QUIT;
		}
		else if((*reinterpret_cast<const u_int*>(packetInfo_->body) == LIST_TAG)
			  ||(*reinterpret_cast<const u_int*>(packetInfo_->body) == RETR_TAG))
		{
			popStatus_=POP_RETRIEVE;
		}
		else if (boost::regex_search(first,last,matchedStr,*statusRule_[0])) //user_
		{
			if(user_)
			{
				delete user_;
				user_=NULL;
			}
			u_short userLen = matchedStr[1].length();
			char * user = new char[userLen + 1];
			user[userLen] = 0;
			memcpy(user, matchedStr[1].first, userLen);
			user_=(const char *)user;
			//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "pop3 user :" <<user_<< endl;
		}
		else if (boost::regex_search(first, last, matchedStr, *statusRule_[1])) //rule pass
		{
			if(pass_)
			{
				delete pass_;
				pass_= NULL;
			}
			u_int passLen = matchedStr[1].length();
			pass_ = new char[passLen + 1];
			memcpy(pass_, matchedStr[1].first, passLen);
			pass_[passLen] = 0;
			//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "pop3 Pass :" <<pass_<< endl;
		}

	}
    return;
}


void PopSession::OnRetr()
{
	
	if (packetInfo_->bodyLen < MIN_STATUS_LEN)
	{
		return;
	}
	const char* first = packetInfo_->body;
	const char* last = packetInfo_->body + packetInfo_->bodyLen;
	boost::cmatch matchedStr;
	if (packetInfo_->srcPort == POP_PORT)      //  server to c
	{
		if(emailSum_==0
				 &&boost::regex_search(first, last, matchedStr, *statusRule_[2]))
		{
			//在第一阶段 没 获取到邮件总数
			emailSum_ = atol(matchedStr[1].first);
//			cout << __FILE__ << ":" << __FUNCTION__ << "[POP3] Got email valid  TotalSum :::" << emailSum_<< endl;
		}
		if (emailSum_!=0
				  && emailList_==NULL
				  &&*reinterpret_cast<const u_int*>(packetInfo_->body + packetInfo_->bodyLen - 4) == POP_END_TAG)
		{
//			cout<<"start get maillist"<<endl;			
			emailList_ = new u_int[emailSum_ + 1];
			memset(emailList_, 0, (emailSum_ + 1) * sizeof(u_int));
		
			while (boost::regex_search(first, last, matchedStr, *statusRule_[3]))
			{
				u_int size = atol(matchedStr[2].first);
				emailList_[atol(matchedStr[1].first)] = size;
//				cout << __FILE__ << ":" << __FUNCTION__ << ":" <<"number"<<atol(matchedStr[1].first)<< "List a mail: " << size  << endl;
				first = matchedStr[2].second;
			}
		}
		
		if (ntohl(packetInfo_->tcp->seq)==baseSeq_)  //create  emlbuf
		{
			if(boost::regex_search(first, last, matchedStr, *statusRule_[5]))//+ok ＊＊ octets
			{
				retrMailSize_ = atol(matchedStr[1].first);
				baseSeq_=ntohl(packetInfo_->tcp->seq)+packetInfo_->bodyLen;
				if(retrMailSize_<=maxSize_)
				{
					emlBufSize=retrMailSize_;
				}
				else
				{
					emlBufSize=maxSize_;  // 邮件 大于最大值不保存 附件
				}
				emlBuf_=new char[emlBufSize+1];
				memset(emlBuf_,0,emlBufSize+1);
				fistBodyLen_=0;
			}
			else if(boost::regex_search(first, last, matchedStr, *statusRule_[6]))//+ok ＊＊ octets follow.
			{
				u_short matchLen = matchedStr[0].length();
				retrMailSize_ = atol(matchedStr[1].first);
				//cout << __FILE__ << ":" << __FUNCTION__ << ":" << " +ok ＊＊ octets follow RETR MailSize:   " <<retrMailSize_<< endl;
				baseSeq_=ntohl(packetInfo_->tcp->seq)+packetInfo_->bodyLen;
				if(retrMailSize_<=maxSize_)
				{
					emlBufSize=retrMailSize_;
				}
				else
				{
					emlBufSize=maxSize_;  // 邮件 大于最大值不保存 附件
				}
				emlBuf_=new char[emlBufSize+1];
				memset(emlBuf_,0,emlBufSize+1);
				fistBodyLen_=packetInfo_->bodyLen-matchLen;
				memcpy(emlBuf_,packetInfo_->body+matchLen,fistBodyLen_);
//				cout << __FILE__ << ":" << __FUNCTION__ << ":" << " sucessful malloc emlbuf  " << endl;

			}
			else if(emlBuf_==NULL&&emailList_!=NULL&&emailList_[emailNum_]!=0
							 &&*reinterpret_cast<const u_int*>(packetInfo_->body) == STAT_TAG)//+ok
			{
				retrMailSize_=emailList_[emailNum_];
				//cout << __FILE__ << ":" << __FUNCTION__ << ":" << " +ok   RETR MailSize:   " <<retrMailSize_<< endl;
				
				baseSeq_=ntohl(packetInfo_->tcp->seq)+packetInfo_->bodyLen;
				if(retrMailSize_<=maxSize_)
				{
					emlBufSize=retrMailSize_;
				}
				else
				{
					emlBufSize=maxSize_;  // 邮件 大于最大值不保存 附件
				}
				emlBuf_=new char[emlBufSize+1];
				memset(emlBuf_,0,emlBufSize+1);
				fistBodyLen_=0;
			}

			if(emlBuf_==NULL)
			{
				//cout<<"[POP3] initial buf error ,dorp email!";
				LOG_WARN("[POP3] initial buf error ,dorp email!\n");
			}
		}
	
		if( emlBuf_!=NULL
				  &&ntohl(packetInfo_->tcp->seq)>=baseSeq_
				  &&ntohl(packetInfo_->tcp->seq)<=baseSeq_+emlBufSize)
		{
			u_int writeOffset=fistBodyLen_+ntohl(packetInfo_->tcp->seq)-baseSeq_;
			u_int endoffset=fistBodyLen_+(ntohl(packetInfo_->tcp->seq)+packetInfo_->bodyLen)-baseSeq_;
			if(endoffset<emlBufSize)
			{
				memcpy(emlBuf_+writeOffset,packetInfo_->body,packetInfo_->bodyLen);
			}
			else
			{
				u_int tmp=endoffset-emlBufSize;
				memcpy(emlBuf_+writeOffset,packetInfo_->body,packetInfo_->bodyLen-tmp);
			}

		}
		
		
	}
	else if (packetInfo_->destPort == POP_PORT) //client to s
	{
		if (IsQuit()) //store last retr mail
		{
			if(emlBuf_!=NULL)
			{
				AnalysisEmlBuf();
			}
			popStatus_ = POP_QUIT;
		}
		if((*reinterpret_cast<const u_int*>(packetInfo_->body) == TOP_TAG))
		{
//			cout<<"top";
			if(emlBuf_!=NULL)
			{
				AnalysisEmlBuf();
			}
		}
		if (boost::regex_search(first, last, matchedStr, *statusRule_[4]))  //macth cleint RETR Rule
		{
			//store last retr mail //clear session data //Clear()
			if(emlBuf_!=NULL)
			{
				AnalysisEmlBuf();
			}
			emailNum_ = atol(matchedStr[1].first);
			//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "         RETR  " << emailNum_ << endl;
			if (emailSum_!=0&&emailNum_ > emailSum_)
			{
				popStatus_ = POP_QUIT;
				return;
			}
			else
			{
				baseSeq_=ntohl(packetInfo_->tcp->ack_seq);
			}
		}
	}
	return;
}

void PopSession::AnalysisEmlBuf()
{
//	cout<<"[POP3] AnalysisEmlBuf";
	const char* first = emlBuf_;
	GetTag(date_, dateRule_,0);
	GetTag(from_, fromRule_,0);
	GetTag(to_, toRule_,1);
	GetTag(cc_, ccRule_,1);
//	cout<<"[POP3] AnalysisEmlBuf222222";
	GetTag(subject_, subjectRule_,0);
	boost::cmatch matchedStr;
	if (boost::regex_search((const char*) emlBuf_,matchedStr,*contentTypeRule_)) //匹配邮件头
	{
		u_short ctLen = matchedStr[1].length();
		contentType_ = new char[ctLen + 1];
		contentType_[ctLen] = 0;
		memcpy(contentType_, matchedStr[1].first, ctLen);
//		cout<<contentType_<<endl;
		u_short boundaryLen = matchedStr[2].length();
		boundary_ = new char[boundaryLen + 1];
		boundary_[boundaryLen] = 0;
		memcpy(boundary_, matchedStr[2].first, boundaryLen);
		first=matchedStr[2].second;
//		cout<<boundary_<<endl;
	}
//	cout<<"[POP3] AnalysisEmlBuf3333333";
	if(CreateFile())
	{
		PushMsg();
	}
	Clear();
//	cout<<"[POP3] AnalysisEmlBufend end ";
}

bool PopSession::CreateFile()
{
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "CreateFile!" << endl;
	if(strlen(emlBuf_)<=0)
	{
		return false;
	}
	time_t currentTime;
	time(&currentTime);
	fileName_ = new char[FILE_NAME_LEN];
	sprintf(fileName_,
			"%s/%lu_%lu_%lu.eml\0",
			filePath_,
			emailSum_,
			emailNum_,
			currentTime);
	std::ofstream* pfile;
	pfile= new ofstream(fileName_, ios::ate);
	if (!pfile)
	{
//		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "pop3 Create file failed." << endl;
		return false;
	}
	pfile->write(emlBuf_, emlBufSize);
	pfile->close();
	delete pfile;
	return true;
}


void PopSession::PushMsg()
{

//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg msgNode" << endl;
	MsgNode* msgNode = new MsgNode;
	memset(msgNode, 0, sizeof(MsgNode));
	//memcpy(msgNode, packetInfo_, COPY_BYTES);
	memcpy(msgNode->srcMac,packetInfo_->destMac,6); //服务器mac
	memcpy(msgNode->destMac,packetInfo_->srcMac,6);
	msgNode->srcIpv4=packetInfo_->destIpv4;  //服务器
	msgNode->destIpv4=packetInfo_->srcIpv4;
	msgNode->srcPort=packetInfo_->destPort;  //服务器
	msgNode->path =fileName_;// 
//	cout << "[POP3] Raw filepath:" << fileName_<< endl;
	LOG_INFO("[POP3] Raw filepath: %s\n",fileName_);
	fileName_=NULL;
	
	msgNode->from = from_;
    from_ = NULL;
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg 00" << endl;
	msgNode->to = to_;
	to_ = NULL;
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg 1" << endl;
	msgNode->subject = subject_;
	subject_ = NULL;
	msgNode->cc=cc_;
	cc_=NULL;

//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg 2" << endl;
	if(contentType_!=NULL&&strcmp(contentType_,"multipart/mixed")==0)
	{
		msgNode->affixFlag=1;
	}
	else
	{
		msgNode->affixFlag=0;
	}
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg 3" << endl;
	if(user_!=NULL)
	{
		
		msgNode->user = new char[strlen(user_) + 1];
		memcpy(msgNode->user, user_, strlen(user_) + 1);
//		cout<<"user: "<<msgNode->user<<endl;
	}
	else
	{
		msgNode->user =NULL;
	}

	if(pass_!=NULL)
	{
		msgNode->pass = new char[strlen(pass_) + 1];
		memcpy(msgNode->pass, pass_, strlen(pass_) + 1);
	}
	else
	{
		msgNode->pass =NULL;
	}

	msgNode->protocolType = 401;//PROTOCOL_ID_POP3;
 	char strmac[20] = {0};
	ParseMac(packetInfo_->srcMac, strmac);
	int clueId = 0;
#ifdef VPDNLZ
	clueId = GetObjectId2(msgNode->srcIpv4,msgNode->pppoe);
#else
	//clueId = GetObjectId(strmac);
	struct in_addr addr;
	addr.s_addr = msgNode->srcIpv4;
	clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
 	msgNode->clueId = clueId;
	time(&msgNode->timeVal);
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg 4" << endl;
	msgNode->fileName=NULL;
	msgNode->time=NULL;
	msgNode->text=NULL;
	msgNode->groupSign=0;
	msgNode->groupNum = NULL;
	reinterpret_cast<PopExtractor*>(obj_)->StoreMsg2DB(msgNode);
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << "PushMsg PushMsg end" << endl;
}

// FIXME: what's the fuck freak here mixed usage with char * and std::string
void PopSession::GetTag(char*& tag, boost::regex* tagRule,bool loop)
{
	if (tag)
	{
		return;
	}
	if(loop)
	{
		boost::cmatch matchedStr;
		//char tmpTag[1024]={0};

		std::string tmpTag;
		if (boost::regex_search((const char*) emlBuf_, matchedStr, *tagRule))
		{
			const char* first = matchedStr[0].first;
			const char* last = matchedStr[0].second;
			boost::cmatch submatchedStr;
			while (boost::regex_search(first, last, submatchedStr, *mailAddressRule_))
			{
//				cout<<"to or cc match"<<endl;
				u_short tmplen=submatchedStr[1].length();
				char *tmp= new char[tmplen+1];
				tmp[tmplen]=0;
				memcpy(tmp, submatchedStr[1].first, tmplen);
				//strcat(tmpTag,tmp);
				//strcat(tmpTag,"|");

				tmpTag += tmp;
				tmpTag += "|";

				if(tmp!=NULL)
					delete tmp;

				if(submatchedStr[1].second!=NULL&&submatchedStr[1].second<last)
				{
					first=submatchedStr[1].second;
				}
			}
			//tmpTag[strlen(tmpTag)-1]=0;
//			cout<<"tmpTag"<<tmpTag<<endl;
			//u_short tagLen = strlen(tmpTag);
			u_short tagLen = tmpTag.length();
			tag = new char[tagLen + 1];
			tag[tagLen] = 0;
			strcpy(tag, tmpTag.c_str());
			//cout<<"tag"<<tag<<endl;
		}
	}
	else
	{
		boost::cmatch matchedStr;
		if (boost::regex_search((const char*) emlBuf_,
			matchedStr,
			*tagRule))
		{
			//u_short tagLen = matchedStr[1].length();
			size_t tagLen = matchedStr[1].length();
			tag = new char[tagLen + 1];
			tag[tagLen] = 0;
			memcpy(tag, matchedStr[1].first, tagLen);
			//cout<<"tag"<<tag<<endl;
		}
	}

}


bool PopSession::IsQuit()
{
    if (*reinterpret_cast<const u_int*>(packetInfo_->body) == QUIT_TAG)
	{
        return true;
    }
    return false;
}

void PopSession::Clear()
{
	emlBufSize=0;
	retrMailSize_=0;
	baseSeq_=0;
	if(fileName_)
	{
		delete fileName_;
		fileName_=NULL;
	}

	//for mail head
	if(date_)
	{
		delete date_;
		date_=NULL;
	}
	if (from_) {
		delete from_;
		from_ = NULL;
	}
	if (to_) {
		delete to_;
		to_ = NULL;
	}
	if(cc_)
	{
		delete cc_;
		cc_=NULL;
	}
	if (subject_) {
		delete subject_;
		subject_ = NULL;
	}
	if(contentType_)
	{
		delete contentType_;
		contentType_ = NULL;
	}
	if(boundary_)
	{
		delete boundary_;
		boundary_=NULL;
		
	}
	if(emlBuf_)
	{
		delete emlBuf_;
		emlBuf_=NULL;
	}
}

// End of file
