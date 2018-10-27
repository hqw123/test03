#ifndef WEBSEARCH_EXTRACTOR
#define WEBSEARCH_EXTRACTOR

#include "BaseWebIMExtractor.h"

#include <boost/regex.hpp>
#include <string>


#define  MAX_CONT_LEN 1500

using namespace std;

class WebSearchExtractor : public BaseWebIMExtractor
{
	public:
		WebSearchExtractor();
		virtual ~WebSearchExtractor();
    
		bool IsWebIMText(PacketInfo* pktInfo);
	
	private:
		int htmldecode_full(char *src,char *dest);
		void StoreMsg2DB(Node* msgNode);
	private:
		boost::regex* baiduRule_;
		boost::regex* bingRule_;
		boost::regex* sosoRule_;
		char DIRECTORY[255];
};

#endif
// End of file
