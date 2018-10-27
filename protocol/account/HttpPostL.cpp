
#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#include "HttpPostL.h"
#include "accountL.h"
#include "accountGeterL.h"
#include "Analyzer_log.h"

using namespace std;
HttpPost::HttpPost()
{
	packetC = 0;
	flag = -1;
	attrFlag = 0;
	memset(srcMac, 0, 7);
	memset(destMac, 0, 7);
	srcIp = 0;
	destIp = 0;
	srcPort = 0;
	destPort = 0;
	timevalCapture = 0;
	memset(userName, 0, USER_NAME_SIZE_M+1);
	memset(userPasswd, 0, USER_PASS_SIZE+1);
	loginType = 301;
	loginFileId = "";
	objectId = 0;
	#ifdef VPDNLZ
	memset(pppoe,0,60);
	#endif
	deviceNum = 0;
	//deviceNum=3;
	refererUrl = "";
	hostUrl = "";
	requestUrl = "";
	siteFlag = "";
	contentType = -1;
	siteId = -1;
	charSet = -1;
	boundary = "";
	content = NULL;
	contentLength = 0;
	recContentLen = 0;

	comment = "";
	subject = "";
	commentType = -1;
	commentXmlFileId = "";
	p_luntan = NULL;
	p_kaixin = NULL;
	p_http_proxy = NULL;
	attachType = -1;
	attachUrl = "";
	attachFileId = "";

	next = NULL;
}

int HttpPost::pushData2(char *buf,int first,int offset,int dataLen,unsigned int seq,int bodyLen)
{
	packetC++;
	char *tmpbuf = buf+offset;

    if ((attrFlag&CONTENT_LENGTH_MASK) != CONTENT_LENGTH_MASK)
	{
        return -301;
	}
    
	if(content == NULL)
	{
		content = new HttpPostContent();
		if(content == NULL)
		{
			//cout<<"new httpcontent error"<<endl;
			LOG_ERROR("new httpcontent error\n");
			return RELEASE_MEM;
		}
        
		content->seqFirst = seq;
		content->seqNext = seq + bodyLen;

        content->content.reserve(contentLength);
		if(dataLen < 1 || dataLen > bodyLen)
		{
			//cout<<"dataLen > bodyLen "<<dataLen<<" "<<bodyLen<<endl;
			return -301;
		}
        
		content->content.append(tmpbuf, dataLen);	
		content->index = content->index+dataLen;
		recContentLen = dataLen;
		//cout<<"first packet: recContentLen:"<<recContentLen<<endl;   
		if(recContentLen == contentLength && (attrFlag&CONTENT_LENGTH_MASK) == CONTENT_LENGTH_MASK)
		{
			set_content();
			
			if(set_http_proxy() >= 0)
			{
				return RELEASE_MEM;
			}
			else if(setluntan() > 0)
			{
				return RELEASE_MEM;
			}
			else if(set_kaixin() >= 0)
			{
				return RELEASE_MEM;
			}
			else if (setBlogInfo() >= 0)
			{
				return RELEASE_MEM;
			}
			else if (setP2PInfo() >= 0)
			{
				return RELEASE_MEM;
			}
				
			setLoginInfo();
			return RELEASE_MEM;
		}
		//cout<<"get out off push data2"<<endl;
		return 300;			   
	}
/*	
	if(dataLen < 1 || dataLen > bodyLen)
	{
		//cout<<"dataLen > bodyLen "<<dataLen<<" "<<bodyLen<<endl;
		// Bug. we may have a fragmented http post request, so we should update the seq, nextseq here.
		// we found that mostly http client attempt to pack a longly http post request header in several fragmented packets(WITH NO CONTENT FIELD)
		// so we can do this
		// added by jacky Mon Feb 13 18:14:36 PST 2017
		content->seqFirst = seq;
		content->seqNext = seq + bodyLen;
		return -301;
	}
*/		
	HttpPostContent* tmpcontent = content;
	if(seq == tmpcontent->seqNext)
	{
		tmpcontent->content.append(tmpbuf, dataLen);
		tmpcontent->seqNext = seq+(unsigned int)bodyLen;
		tmpcontent->index += dataLen;
		recContentLen += dataLen;
	}
	else
	{  
		if(tmpcontent->next == NULL)
		{
			tmpcontent->next = new HttpPostContent();
			if(tmpcontent->next == NULL)
			{
				LOG_ERROR("new httpcontent error\n");
				return RELEASE_MEM;
			}
			tmpcontent->next->content.append(tmpbuf,dataLen);
			tmpcontent->next->seqFirst=seq;
			tmpcontent->next->seqNext=seq+(unsigned int)bodyLen;
			tmpcontent->next->index+=dataLen;
			recContentLen+=dataLen;	
		}
		else
		{ 
			int tmpflag=0;
			HttpPostContent* tmpcontentB=NULL;
			while(tmpflag==0 && tmpcontent !=NULL)
			{
				if(seq>tmpcontent->seqFirst && seq <tmpcontent->seqNext)
					return -302;
				
				else if(seq==tmpcontent->seqNext)
				{
					tmpflag=1;
					tmpcontent->content.append(tmpbuf,dataLen);
					tmpcontent->seqNext=seq+(unsigned int)bodyLen;
					tmpcontent->index+=dataLen;
					recContentLen+=dataLen;
	
					if(tmpcontent->next!=NULL && tmpcontent->next->seqFirst==tmpcontent->seqNext)
					{
						tmpcontent->content.append(tmpcontent->next->content);
						tmpcontent->index+=tmpcontent->next->index;
						tmpcontent->seqNext=tmpcontent->next->seqNext;
						tmpcontentB=tmpcontent->next;
						tmpcontent->next=tmpcontent->next->next;
						delete tmpcontentB;
						tmpcontentB=NULL;
					}
	
				}
				else if(seq > tmpcontent->seqNext && tmpcontent->next==NULL)
				{
					tmpflag=1;
					tmpcontent->next=new HttpPostContent();
					if(tmpcontent->next==NULL){
						//cout<<"new httpcontent error"<<endl;
						LOG_ERROR("new httpcontent error\n");
						return RELEASE_MEM;
					}
					tmpcontent->next->content.append(tmpbuf,dataLen);
					tmpcontent->next->seqFirst=seq;
					tmpcontent->next->seqNext=seq+(unsigned int)bodyLen;
					tmpcontent->next->index+=dataLen;
					recContentLen+=dataLen;	
				}
				else if(seq > tmpcontent->seqNext &&tmpcontent->next!=NULL&& seq < tmpcontent->next->seqFirst)
				{
					tmpflag=1;
					tmpcontentB=tmpcontent->next;
					tmpcontent->next=new HttpPostContent();
					if(tmpcontent->next==NULL)
					{
						//cout<<"new httpcontent error"<<endl;
						LOG_ERROR("new httpcontent error\n");
						return RELEASE_MEM;
					}
					tmpcontent->next->content.append(tmpbuf,dataLen);
					tmpcontent->next->seqFirst=seq;
					tmpcontent->next->seqNext=seq+(unsigned int)bodyLen;
					tmpcontent->next->index+=dataLen;
					recContentLen+=dataLen;	
					tmpcontent->next=tmpcontentB;
				}
				else if(seq > tmpcontent->seqNext &&tmpcontent->next!=NULL&& seq > tmpcontent->next->seqNext)
				{
					tmpcontent=tmpcontent->next;
				}
				else
				{
					tmpflag=-1;
					return -302;
				}
			}//end while			
		}  //end_else_aaaaaaaaaaaaaaaaaaa	
	}  //end_else_bbbbbbbbbbbbbbbbbb
	
	if(recContentLen >= contentLength && (attrFlag&CONTENT_LENGTH_MASK) == CONTENT_LENGTH_MASK)
	{
		set_content();
		
		if(set_http_proxy() >= 0)
		{
			return RELEASE_MEM;
		}
		else if(setluntan() > 0)
		{
			return RELEASE_MEM;
		}
		else if(set_kaixin() >= 0)
		{
			return RELEASE_MEM;
		}
		else if (setBlogInfo() >= 0)
		{
			return RELEASE_MEM;
		}
		else if (setP2PInfo() >= 0)
		{
			return RELEASE_MEM;
		}
			
		setLoginInfo();
		return RELEASE_MEM;
	}
	
	return 300;
}

int HttpPost::set_content()
{
	HttpPostContent* tmpcontent = content->next;
	while(tmpcontent)
	{
		content->content.append(tmpcontent->content);
		tmpcontent = tmpcontent->next;
	}
	return 0;
}

int HttpPost::setP2PInfo()
{
	p2p::up_info_t  ut;
	ut.ep.srcip = this->srcIp;
	ut.ep.srcport = this->srcPort;
	ut.ep.dstip = this->destIp;
	ut.ep.dstport = this->destPort;
	memcpy(ut.ep.srcmac, this->srcMac, 6);

	ut.rqi.host = this->hostUrl;
	ut.rqi.uri = this->reqUri;
    ut.clueid = objectId;
    ut.captime = this->timevalCapture;
    
	return p2p::instance()->push(&ut);
}

int HttpPost::setBlogInfo()
{
	// push
	blog::up_info_t  ut;
	ut.ep.srcip = this->srcIp;
	ut.ep.srcport = this->srcPort;
	ut.ep.dstip = this->destIp;
	ut.ep.dstport = this->destPort;
	memcpy(ut.ep.srcmac, this->srcMac, 6);

	ut.rqi.host = this->hostUrl;
	ut.rqi.uri = this->reqUri;
	ut.rqi.cookie = this->cookie;
	//ut.rqi.cookie = "XXX";
	ut.rqi.d = const_cast<char *>(this->content->content.c_str());
	ut.rqi.dlen = this->content->content.length();
    ut.clueid = objectId;
    ut.captime = this->timevalCapture;
    
	return blog::instance()->push(&ut);
}

int HttpPost::setLoginInfo()
{
	//cout<<"content:"<< contentLength<<"  recLen:"<<recContentLen<<" packetC "<<packetC<<endl;
	char* data = (char*)content->content.c_str();
	const char* hosturl_ = hostUrl.c_str();
	//printf("hosturl: %s\n",hosturl_);
#ifdef VPDNLZ
	GetAccount(srcIp,destIp,srcPort,destPort,(short)objectId,srcMac,hosturl_,data,timevalCapture,pppoe);
#else
	GetAccount(srcIp,destIp,srcPort,destPort,(short)objectId,srcMac,hosturl_,data,timevalCapture);
#endif
	//cout<<"store account info into mysql "<<endl;
	return 0;
}

int HttpPost::setluntan()
{	
	char* data=(char*)content->content.c_str();
	common_tcp tcp_;
	common_http http_;
	tcp_.destIp = this->destIp;
	tcp_.srcIp = this->srcIp;
	tcp_.destPort = this->destPort;
	tcp_.srcPort = this->srcPort;
	//memcpy(tcp_.destMac, this->destMac, 6);
	memcpy(tcp_.srcMac, this->srcMac, 6);
	tcp_.timevalCapture = this->timevalCapture;

	http_.hostUrl = this->hostUrl.c_str();
	http_.reqUri = this->reqUri.c_str();
	http_.cookie = this->cookie.c_str();
	http_.http_content = data;

	return p_luntan->analyse_luntan(&tcp_, &http_, objectId);
}

int HttpPost::set_kaixin()
{
	if(!strcmp(hostUrl.c_str(), "www.kaixin001.com") || !strcmp(hostUrl.c_str(), "api.kaixin001.com"))
	{
		char* data = (char*)content->content.c_str();
		common_tcp tcp_;
		common_http http_;
		tcp_.destIp = this->destIp;
		tcp_.srcIp = this->srcIp;
		tcp_.destPort = this->destPort;
		tcp_.srcPort = this->srcPort;
		//memcpy(tcp_.destMac, this->destMac, 6);
		memcpy(tcp_.srcMac, this->srcMac, 6);
		tcp_.timevalCapture = this->timevalCapture;
		
		http_.hostUrl = this->hostUrl.c_str();
		http_.reqUri = this->reqUri.c_str();
		http_.cookie = this->cookie.c_str();
		http_.http_content = data;
			
		p_kaixin->analyse_kaixin(&tcp_, &http_, objectId);	
		return 0;
	}
	
	return -1;
}

int HttpPost::set_http_proxy()
{
	const char* uri = reqUri.c_str();
	if (!strncmp(uri,"/includes/process.php?action=update HTTP",40))
	{
		char* data=(char*)content->content.c_str();
		const char* hosturl_ = hostUrl.c_str();
		common_tcp tcp_;
		common_http http_;
		tcp_.destIp = this->destIp;
		tcp_.srcIp = this->srcIp;
		tcp_.destPort = this->destPort;
		tcp_.srcPort = this->srcPort;
		//memcpy(tcp_.destMac, this->destMac, 6);
		memcpy(tcp_.srcMac, this->srcMac, 6);
		tcp_.timevalCapture = this->timevalCapture;
	
		http_.hostUrl = this->hostUrl.c_str();
		http_.reqUri = this->reqUri.c_str();
		http_.cookie = this->cookie.c_str();
		http_.http_content = data;
		p_http_proxy->get_http_proxy(&tcp_, &http_, objectId);
		return 0;
	}
	
	return -1;
}


