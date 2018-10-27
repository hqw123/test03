
#include "HttpPostL.h"
#include <netinet/tcp.h>
#include "../PacketParser.h"

#ifndef HTTP_POST_FIRST_PACKET
#define HTTP_POST_FIRST_PACKET 2
#endif
#ifndef HTTP_POST_PACKET
#define HTTP_POST_PACKET 3
#endif

using namespace std;

class HttpPostEntrance{
	public:
		HttpPostEntrance();
		~HttpPostEntrance();
		HttpPost* tmpPost;
		Luntan *lunTan;
		Kaixin* kaiXin;
		Http_proxy* http_Proxy;
		int isPostData(struct PacketInfo *packinfo);

		int pushData(struct PacketInfo *packinfo, int flag, int objId_);
		int releaseMem(HttpPost* httpPost);
		HttpPost* httpPost;
		int counter;
		time_t timeMark;

	private:
		HttpPost* getHttpPost(unsigned int ipsrc,unsigned short portsrc,unsigned int ipdest,unsigned short portdest);
		int setContentLength(const char* data, int datalen, HttpPost *httppost);
		int setHost(const char* data, int datalen, HttpPost *httppost);
		int setUri(const char* data, int datalen, HttpPost *httppost);
		int setCookie(const char* data, int datalen, HttpPost *httppost);
		int getContentOffset(struct PacketInfo* packinfo,HttpPost* httpPost,int siteID);
		int checkTimeOut(unsigned int out);
};

/*
class HttpPostEntrance{
	public:
		int isPostDataHeader(struct PacketInfo packinfo);
		int pushData(struct PacketInfo packinfo);
		HttpPost* httpPost;
	private:

		HttpPost* getHttpPost(unsigned int ipsrc,unsigned short protsrc,unsigned int ipdest,unsigned short portdest);
};*/
