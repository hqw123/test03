#ifndef WEBQQ_EXTRACTOR
#define WEBQQ_EXTRACTOR

#include "BaseWebIMExtractor.h"

#include <boost/regex.hpp>
#include <string>
#include <map>


#define MAX_QQNUMBER 15
#define MAX_CONT_LEN 1500


using namespace std;



struct WebChatKeyNode
{
	unsigned int srcIpv4;
	unsigned int destIpv4;
	unsigned short srcPort;
	unsigned short destPort;
};

class WebQQExtractor : public BaseWebIMExtractor
{
	public:
		WebQQExtractor();
		virtual ~WebQQExtractor();
    
		bool IsWebIMText(PacketInfo* pktInfo);
	private:
		int clear_tag(char *str);
		int htmldecode_full(char *src,char *dest);
		int str_to_int(char * chr);
		int char_to_int(char  chr);
		int str_to_UCS4(char *str,u_int *ucs);
		int transferMean(char *str);
		int decomp_gzip(char *src, unsigned int len, char **dest);
		void StoreMsg2DB(Node* msgNode);
	private:
		boost::regex* loginRule_;
		boost::regex* onlineRule_;
		//boost::regex* logoutRule_;
		boost::regex* recvMsgRule_;
		boost::regex* sendPostRule_;
		boost::regex* sendRule_;
		boost::regex* sendQunRule_;
		boost::regex* sendDisRule_;
		boost::regex* senddRule_;
		boost::regex* senddQunRule_;
		boost::regex* senddDisRule_;
		boost::regex* recvQunMsgRule_;
		boost::regex* recvDisMsgRule_;
		boost::regex* recvRule_;
		boost::regex* minilogoutRule_;
		boost::regex* offlineRule_;
		char DIRECTORY[255];
		map<uint64_t,char*> keyMap;
		unsigned int sendSrcIpv4_;
		u_int32_t sendSeq_;
		char* sendBody_;
		unsigned short int sendBodyLen_;
		unsigned short int isWebqq_;
};

#endif
// End of file
