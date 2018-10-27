#ifndef WEBWW_EXTRACTOR
#define WEBWW_EXTRACTOR

#include "BaseWebIMExtractor.h"

#include <boost/regex.hpp>
#include <string>
#include <map>

using namespace std;

//#define MAX_QQNUMBER 15
#define MAX_CONT_LEN 1500

class WebWWExtractor : public BaseWebIMExtractor
{
	public:
		WebWWExtractor();
		virtual ~WebWWExtractor();
    
		bool IsWebIMText(PacketInfo* pktInfo);
	private:
		int clear_tag(char *str);
		int htmldecode_full(char *src,char *dest);
		int str_to_int(char * chr);
		int char_to_int(char  chr);
		int transferMean(char *str);
		int code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen , char *outbuf, size_t outlen);
		void StoreMsg2DB(Node* msgNode);
	private:
		boost::regex* loginRule_;
		boost::regex* loginRule2_;
		boost::regex* recvMsgRule_;
		boost::regex* recvPostRule_;
		boost::regex* sendRule_;
		boost::regex* recvRule_;
		boost::regex* logoutRule_;
		char DIRECTORY[255];
		map<uint64_t,char*> keyMap;
		
};

#endif
// End of file
