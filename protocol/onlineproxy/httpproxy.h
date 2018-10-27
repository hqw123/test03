#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

#include "../talkspace/common.h"
#include <string>

using namespace std;

class Http_proxy
{
private:
	common_tcp* m_tcp;
	common_http* m_http;
	string real_url;
	string proxy_url;
	int objectid;
	
public:
	Http_proxy();
	~Http_proxy();
	
	int get_http_proxy(common_tcp* tcp, common_http* http, int id);
	int get_realurl();
	void storedb();
};

#endif


