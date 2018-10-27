
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <iostream>

#include "../talkspace/common.h"
#include "../talkspace/kaixin.h"
#include "../talkspace/luntan.h"
#include "../onlineproxy/httpproxy.h"
#include "../blog/blog.h"
#include "../p2p/p2p.h"

#ifndef E_POST_MATCH
#define E_POST_COMPILE -1
#define E_POST_MATCH -2
#endif

#ifndef MAX_DIR_NODE 
#define MAX_DIR_NODE 32000
#endif

#ifndef MAC_MAXSIZE 
#define MAC_MAXSIZE 7
#endif

#ifndef USER_NAME_SIZE	
#define USER_NAME_SIZE 40
#endif
#ifndef USER_NAME_SIZE_M
#define USER_NAME_SIZE_M 60
#endif

#ifndef USER_PASS_SIZE
#define USER_PASS_SIZE 40
#endif


#define PROTOCOL_WEBACCOUNTINFO 2
#define PROTOCOL_BBSANDBLOG     3
#define PROTOCOL_ID_POSTPWD 301


#define E_NEW_HTTPPOST 0x80000001

#define HTTP_POST_GARBAGE 0

#ifndef HTTP_POST_FIRST_PACKET
#define HTTP_POST_FIRST_PACKET 2
#endif
#ifndef HTTP_POST_PACKET
#define HTTP_POST_PACKET 3
#endif

#ifndef RELEASE_MEM
#define RELEASE_MEM 303
#endif

#define H_P_CONTENT_TYPE_APPLICATION_WWW_URLENCODE 1
#define H_P_CONTENT_TYPE_MULTIPART_FORMDATA 2 

#define UTF_8 1
#define GB2312 2

#define LOGIN_NAME_MASK 0x00000001
#define LOGIN_PASSWD_MASK 0x00000002
#define HOST_URL_MASK 0x00000004
#define REFERER_URL_MASK 0x00000008
#define REQUEST_URL_MASK 0x00000010
#define CONTENT_LENGTH_MASK 0x00000020
#define CONTENT_TYPE_MASK 0x00000040

#define TURNOFF_CONTEN_STAR_MASK 0x00000080
#define COMMENT_READY_MASK 0x00000100
#define WWW_URLENCODE_MASK 0x00000200
#define MULTIPART_FORM_MASK 0x00000400
#define MULTIPART_BOUNDARY_MASK 0x00000800
#define ATTACH_READY_MASK 0x00001000
#define SUBJECT_READY_MASK 0x00002000

#define COOKIE_MASK 0x00004000

#define SID_BAIDU_TIEBA 101
#define SID_BAIDU_I 102     
#define SID_DISCUZ 201
#define SID_DVBBS 301  
#define SID_TIANYA 401
#define SID_163 501
#define SID_163_NEWS 502
#define SID_MOP SID_DISCUZ
#define SID_I_MOP SID_MOP

#define SID_NULL 0

#define SID_PHPWIND  4101
#define SID_BCCN 4201

#define DEVICE_NUM 3

#define TYPE_DISCUZ 401
#define TYPE_PHPWIND 402
#define TYPE_DVBBS 403
#define TYPE_BAIDU 404
#define TYPE_TIANYA 405
#define TYPE_MOP 406
#define TYPE_OTHER 407


///////////////////////////
//#define
///////////////////////////

#define XML_DIR "/home/nodeData/"
#define ATTACH_DIR "/home/nodeData/moduleData/http_post_accessary/"
#define COMMENT_DIR "/home/nodeData/moduleData/http_post_comment/"

using namespace std;

#ifndef HTTP_POST_CONTENT
#define HTTP_POST_CONTENT
class HttpPostContent
{
	private:
		//string comment;
		
	public:
	
		string content;
		unsigned int seqFirst; //0
		unsigned int seqNext; //0
		int index; //0
		HttpPostContent* next;
		HttpPostContent(){
			seqFirst=0;
			seqNext=0;
			index=-1;
			next=NULL;
			content="";
			//next=NULL;
		}
	//	int getDataLength();
};
/*
HttpPostContent::HttpPostContent(){
	seqFirst=0;
	seqNext=0;
	index=-1;
	next=NULL;
	content="";			
}*/
#endif

#ifndef HTTP_POST
#define HTTP_POST
class HttpPost
{
	public:
	    int flag;
		int attrFlag;
		int packetC;
		//address and time
		char srcMac[MAC_MAXSIZE];
		char destMac[MAC_MAXSIZE];
		unsigned int srcIp;
		unsigned int destIp;
		unsigned short srcPort;
		unsigned short destPort;
		unsigned int timevalCapture;
		
		// login
		char userName[USER_NAME_SIZE_M+1];
		char userPasswd[USER_PASS_SIZE+1];
		int loginType;
		string loginFileId;  // ip + .xml struct http_pu_node http_xml_path
		int deviceNum;
		int objectId;
		char pppoe[60];
		//site information
		string refererUrl;     // struct http_post_comment url
		string hostUrl;
		string requestUrl;
		string siteFlag;
		string cookie;
		string reqUri;
		string buffer;     //cache
		
		//content information
		int contentType;  //-1     
		int siteId;      //SITE CLASS
		int charSet;     //-1
		string boundary;
		HttpPostContent* content;
		unsigned int contentLength;
		unsigned int recContentLen;
		
		//comment
		int commentType;     //mark which site the post will go to
        string comment;
		string subject;
		string commentXmlFileId;        //fiteFlag+time.xml // struct http_post_comment http_xml_path
		// attachment
	    int attachType;
		string attachUrl;//the site which the data will be sent to  /struct http_comment_accessary url
		string attachFileId;//the path of stored file /struct http_comment_accessary http_file_path

		Luntan *p_luntan;
		Kaixin* p_kaixin;
		Http_proxy* p_http_proxy;
		// DATA LIST
		HttpPost* next;
		
		HttpPost();	
		int pushData2(char *buf,int first,int offset,int dataLen,unsigned int seq,int bodyLen);
		
	private:
	   int transData();
	   int set_content();
	   int setLoginInfo();
	   int setluntan();
	   int set_kaixin();
	   int set_http_proxy();
	   int setBlogInfo();
	   int setP2PInfo();
};
#endif


