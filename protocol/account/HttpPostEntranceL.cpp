
#include <string.h>
#include <string>
//#include <pcre.h>
//#include <dirent.h>

#include "HttpPostL.h"
//#include "patterninfo.h"
#include "HttpPostEntranceL.h"
//#include "filter.h"
#include "Analyzer_log.h"

#ifndef E_POST_MATCH
#define E_POST_COMPILE -1
#define E_POST_MATCH -2
#endif

#ifndef RELEASE_MEM
#define RELEASE_MEM 303
#endif
#define netToHost(p) (p>>24&0xff)|(p>>8&0xff00)|(p<<8&0xff0000)|(p<<24&0xff000000)

using namespace std;

/*
#######################
*/
HttpPostEntrance::HttpPostEntrance()
{
	counter = 0;
	httpPost = NULL;
	timeMark = time(NULL);
	
	lunTan = new Luntan();
	kaiXin = new Kaixin();
	http_Proxy = new Http_proxy();
}

HttpPostEntrance::~HttpPostEntrance()
{
	delete lunTan;
	delete kaiXin;
	delete http_Proxy;
}

int HttpPostEntrance::isPostData(struct PacketInfo *packinfo)
{
	//cout<<"get into entrance: ispostdata"<<endl;
	if(memcmp(packinfo->body, "POST", 4) == 0)
	{
// 		cout<<"get outof entrance: ispostdata"<<endl;
		return HTTP_POST_FIRST_PACKET;
	}
	tmpPost = getHttpPost(packinfo->srcIpv4, packinfo->srcPort, packinfo->destIpv4, packinfo->destPort);
	//cout<<"get outof entrance: ispostdata"<<endl;
	if(tmpPost == NULL)
		return HTTP_POST_GARBAGE;
	else 
		return HTTP_POST_PACKET;
}

int HttpPostEntrance::setHost(const char* data, int datalen, HttpPost *httppost)
{
	if (data == NULL)
		return -1;

	char *hostPattern = "Host:";
	char* addr = strstr((char *)data, hostPattern);
	if(!addr)
		return 0;
	int index = 0;
	index = addr - data + strlen(hostPattern);
	index++;
	while(index<datalen && data[index] !='\r')
	{
		httppost->hostUrl.append(1, data[index]);
		index++;
	}
	
	return 1;
}

int HttpPostEntrance::setContentLength(const char* data, int datalen, HttpPost *httppost)
{
	if (data == NULL)
		return -1;

	char *contentLenPattern = "Content-Length:";
	char *addr = NULL;
	addr = strcasestr((char *)data, contentLenPattern);
	if(!addr)
    {   
		return RELEASE_MEM;
    }
	
	int index = 0;
    unsigned int contentLen = 0;
    
	index = addr - data;
	index += strlen(contentLenPattern);
    
	while(index<datalen && data[index]==' ')
		index++;
    
	httppost->attrFlag = httppost->attrFlag|CONTENT_LENGTH_MASK;
	
	while(index<datalen && data[index] >='0' && data[index]<='9')
	{
		contentLen = contentLen*10 + (data[index]-'0');
		index++;
	}
    
	httppost->contentLength = contentLen;
	
	return 1;
}

int HttpPostEntrance::setCookie(const char* data, int datalen, HttpPost *httppost)
{
	if (data == NULL)
		return -1;
	
	char *cookiePattern = "Cookie:";
	char *addr = strstr((char *)data, cookiePattern);
	if (!addr)
		return 0;
    
	int index = 0;
	index = addr - data + strlen(cookiePattern);
	index++;
	while(index<datalen && data[index] !='\r')
	{
		httppost->cookie.append(1,data[index]);
		index++;
	}
	
	return 1;
}

int HttpPostEntrance::setUri(const char* data, int datalen, HttpPost *httppost)
{
	if (data == NULL)
		return -1;
	
	char *uriPattern = "POST";
	char* addr = strstr((char *)data,uriPattern);
	if(!addr)
		return 0;
    
	int index = 0;
	index = addr-data + strlen(uriPattern);
	index++;
	while(index<datalen && data[index] !='\r')
	{
		httppost->reqUri.append(1,data[index]);
		index++;
	}
	
	return 1;
}

HttpPost* HttpPostEntrance::getHttpPost(unsigned int ipsrc,unsigned short portsrc,unsigned int ipdest,unsigned short portdest)
{
	HttpPost* tmphttpPost = httpPost;

	while(tmphttpPost != NULL)
	{
		if(tmphttpPost->srcIp==ipsrc && tmphttpPost->srcPort==portsrc && tmphttpPost->destIp==ipdest && tmphttpPost->destPort==portdest)
		{
			return tmphttpPost;
		}
		tmphttpPost=tmphttpPost->next;
	} 

	return NULL;
}

int HttpPostEntrance::pushData(struct PacketInfo *packinfo, int flag, int objId_)
{
    int releaseFlag = 0;

	if(flag == HTTP_POST_FIRST_PACKET)
	{
		HttpPost* tmphttpPost = NULL;
		if(NULL == httpPost)
		{
			httpPost = new HttpPost();
			if(httpPost == NULL)
			{
				//cout<<" new httpPost error 1"<<endl;
				LOG_ERROR(" new httpPost error 1\n");
				if(timeMark+60 < (unsigned int)time(NULL))
					checkTimeOut(60);
				return E_NEW_HTTPPOST;
			}
			counter++;
			httpPost->next = NULL;				
			tmphttpPost = httpPost;
		}
		else
		{
			tmphttpPost = httpPost;
			while(tmphttpPost->next != NULL)
			{
				tmphttpPost = tmphttpPost->next;
			}
			tmphttpPost->next = new HttpPost();
			if(tmphttpPost->next == NULL)
			{
				//cout<<"new httpPost error 2"<<endl;
				LOG_ERROR(" new httpPost error 2\n");
				if(timeMark+60 < (unsigned int)time(NULL))
					checkTimeOut(60);
				return E_NEW_HTTPPOST;
			}				
			tmphttpPost = tmphttpPost->next;
			tmphttpPost->next = NULL;
			//cout<<"entrance: first packet: 1"<<endl;
		}
	
		tmphttpPost->timevalCapture = packinfo->pkt->ts.tv_sec;
		tmphttpPost->srcIp = packinfo->srcIpv4;
		tmphttpPost->srcPort = packinfo->srcPort;
		tmphttpPost->destIp = packinfo->destIpv4;
		tmphttpPost->destPort = packinfo->destPort;
		tmphttpPost->objectId = objId_;
		tmphttpPost->p_luntan = lunTan;
		tmphttpPost->p_kaixin = kaiXin;
		tmphttpPost->p_http_proxy = http_Proxy;
		memcpy(tmphttpPost->srcMac, packinfo->srcMac, 6);
		memcpy(tmphttpPost->destMac, packinfo->destMac, 6);
		tmphttpPost->flag = 1;

		int effectiveBodyLen = 0;
		int index = getContentOffset(packinfo, tmphttpPost, tmphttpPost->siteId);
		if((index > 0) && (index <= packinfo->bodyLen))
		{	
			effectiveBodyLen = packinfo->bodyLen - index;
			setCookie(packinfo->body, packinfo->bodyLen, tmphttpPost);
			setHost(packinfo->body, packinfo->bodyLen, tmphttpPost);
			setUri(packinfo->body, packinfo->bodyLen, tmphttpPost);
			releaseFlag = setContentLength(packinfo->body, packinfo->bodyLen, tmphttpPost);
		}
		else
		{
			tmphttpPost->buffer.assign(packinfo->body, packinfo->bodyLen);
		}

		if (releaseFlag != RELEASE_MEM)
		    releaseFlag = tmphttpPost->pushData2(packinfo->body, 1, index, effectiveBodyLen, netToHost(packinfo->tcp->seq), packinfo->bodyLen);
		if(releaseFlag == RELEASE_MEM)
		{
			releaseMem(tmphttpPost);
		}			
	}
	else if(flag == HTTP_POST_PACKET)
	{
		tmpPost->flag++;
		
		int effectiveBodyLen = packinfo->bodyLen;
		int index = 0;
		// FIXME: there is a problem in this logic
		if((tmpPost->attrFlag & TURNOFF_CONTEN_STAR_MASK) == 0)
		{
			effectiveBodyLen = 0;
			tmpPost->buffer.append(packinfo->body, packinfo->bodyLen);
            index = getContentOffset(packinfo, tmpPost, tmpPost->siteId);
			if (index > 0)
			{
				effectiveBodyLen = packinfo->bodyLen - index;
				setCookie(tmpPost->buffer.c_str(), tmpPost->buffer.length(), tmpPost);
				setHost(tmpPost->buffer.c_str(), tmpPost->buffer.length(), tmpPost);
				setUri(tmpPost->buffer.c_str(), tmpPost->buffer.length(), tmpPost);
				releaseFlag = setContentLength(tmpPost->buffer.c_str(), tmpPost->buffer.length(), tmpPost); 
			}
		}
		
		if (releaseFlag != RELEASE_MEM)
		    releaseFlag = tmpPost->pushData2(packinfo->body, 0, index, effectiveBodyLen, netToHost(packinfo->tcp->seq), packinfo->bodyLen);
		if(releaseFlag == RELEASE_MEM)
		{
			releaseMem(tmpPost);
		}
        
		tmpPost == NULL;
	}
	
	if((timeMark + 60) < (unsigned int)time(NULL))
		checkTimeOut(60);
	
	return 1;
}

int HttpPostEntrance::releaseMem(HttpPost* httppost)
{
	if(httppost == NULL)
	{
		return 0;
	}
	
	HttpPost* tmppost = httpPost;
	if(tmppost == NULL)
	{
		return 0;
	}
	
	if(tmppost == httppost)
	{
		httpPost=httpPost->next;
	}
	else
	{
		int i = 0;
		while(tmppost != NULL && tmppost->next != httppost)
			tmppost = tmppost->next;
		if(tmppost == NULL)
		{
			return -1;
		}
		else
		{
			tmppost->next=httppost->next;
		}
	}
	
	HttpPostContent* tmpcontent = NULL;
	tmpcontent = httppost->content;
	while(tmpcontent != NULL)
	{
		httppost->content = tmpcontent->next;
		delete tmpcontent;
		tmpcontent = httppost->content;
	}
	counter--;
	delete httppost;
	httppost = NULL;

	return 1;
}

int HttpPostEntrance::getContentOffset(struct PacketInfo* packinfo,HttpPost* httppost,int siteID)
{
    int i = 0;
    while((i+3) < packinfo->bodyLen)
    {
        if(packinfo->body[i]==(char)0x0d && packinfo->body[i+1]==(char)0x0a && packinfo->body[i+2]==(char)0x0d && packinfo->body[i+3]==(char)0x0a)
        {
            httppost->attrFlag = httppost->attrFlag|TURNOFF_CONTEN_STAR_MASK;

#if 0  //closed by zhangzm
            if((httppost->attrFlag&CONTENT_LENGTH_MASK) == 0)
            {
                int j = i;
                unsigned int len = 0;

                while(j-1>=0 && packinfo->body[j-1]>='0' && packinfo->body[j-1]<='9')
                    j--;

                while(j < i)
                {
                    len = len*10 + (packinfo->body[j]-'0');
                    j++;
                }

                httppost->attrFlag = httppost->attrFlag|CONTENT_LENGTH_MASK;
                httppost->contentLength = len;
            }
#endif
            return i+4;
        }
        i++;  
    }

    return -1;
}

int HttpPostEntrance::checkTimeOut(unsigned int out)
{
	//cout<<"get into checktimeout"<<endl;
	int i = 0;
	int j = 0;
	unsigned int tm;
	tm = (unsigned int)time(NULL);
	if(tm < 0)
	{
		//cout<<"TIME <0"<<endl;
		LOG_WARN("TIME <0\n");
		timeMark+=60;	
		//return -1;
	}
	HttpPost* tmppost = httpPost;
	if(tmppost == NULL)
	{
		counter = 0;
		//cout<<" checktimeout 1"<<endl;
		timeMark = tm;	
		return 0;
	}
		
	HttpPost* tmppostB = NULL;
	while(tmppost != NULL)
	{
		//cout<<"CHECK: "<<(tmppost->timevalCapture+out)<<" < "<<tm<<" "<<(tmppost->timevalCapture+out < tm)<<endl;
		//cout<<"Refer :"<<tmppost->refererUrl<<endl;
		if((tmppost->timevalCapture + out) <= tm)
		{
			tmppostB = tmppost->next;
			//cout<<" checktimeout 2.1: "<<tmppost->hostUrl<<endl;
			LOG_INFO(" checktimeout 2.1: %s\n",tmppost->hostUrl.c_str());
			releaseMem(tmppost);
			i++;
			//cout<<" checktimeout 2.2"<<endl;
			tmppost = tmppostB;
		}else{
			tmppost = tmppost->next;
			//cout<<" checktimeout 3"<<endl;
		}		
	}
	timeMark = tm;
	//cout<<"get outof checktimeout"<<endl;
	return i;
}


