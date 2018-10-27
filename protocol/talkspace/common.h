#ifndef COMMON_TALKSPACE_H
#define COMMON_TALKSPACE_H

#define MAC_LEN 7

#define PASSIVE_USERID "(otheruid=)|(uids=)"
#define PATTERN_TITLE "(&title=)|(params.title=)|(titleText=)|(topic=)|(subject=)|(&doc_title=)"
#define PATTERN_CONTENT "(content=)|(message=)|(body=)|(quickContent=)|(my_text)|(subjectContent=)|(&replys=)|(&doc_text=)"

typedef struct luntan_tcp
{
	char srcMac[MAC_LEN];
	char destMac[MAC_LEN];
	unsigned int srcIp;
	unsigned int destIp;
	unsigned short srcPort;
	unsigned short destPort;
	unsigned int timevalCapture;
}common_tcp;

typedef struct luntan_http
{
	const char* hostUrl;
	const char* reqUri;
	const char* cookie;
	char* http_content;
}common_http;

#endif
