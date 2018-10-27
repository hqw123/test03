#ifndef WEBTWITTER_EXTRACTOR
#define WEBTWITTER_EXTRACTOR

#include "BaseWebSNSExtractor.h"

#include <boost/regex.hpp>
#include <string>
#include <map>
#include <fcntl.h>


using namespace std;

class WebTwitterExtractor : public BaseWebSNSExtractor
{
	public:
		WebTwitterExtractor();
		virtual ~WebTwitterExtractor();

		bool IsWebSNSText(PacketInfo* pktInfo);
	private:
		int htmldecode_full(char *src,char *dest);
		void StoreMsg2DB(Node* msgNode);
	private:
		boost::regex* sendRule_;
		boost::regex* senddRule_;
		boost::regex* sendStatusesRule_;
		boost::regex* senddStatusesRule_;
		boost::regex* sendStatuses2Rule_;
		boost::regex* senddStatuses2Rule_;
		u_int32_t sendSeq_;
		char* sendBody_;
		unsigned int sendBodyLen_;
		char DIRECTORY[255];
};

#endif
// End of file
