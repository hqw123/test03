#ifndef WEBFACEBOOK_EXTRACTOR
#define WEBFACEBOOK_EXTRACTOR

#include "BaseWebSNSExtractor.h"

#include <boost/regex.hpp>
#include <string>
#include <map>
#include <fcntl.h>

#define MAX_PATH_LEN 260
#define MAX_ID_LEN 4096
#define MAX_FN_LEN 260
#define MAX_UN_LEN 60
#define TIME_LEN 8

using namespace std;

typedef struct attach_info {
	char ID_str[MAX_ID_LEN + 1];
	//char *path_of_sender;
	char path_of_here[MAX_PATH_LEN + 1];
	char attach_name[MAX_PATH_LEN + 1];
	//char attname[MAX_PATH_LEN + 1];
	int attch_length;
	struct attach_info *prev;
	struct attach_info *next;
} Attach_info;

typedef struct attach_table {
	Attach_info *head;
	Attach_info *tail;
	int count;
} AttachTable;

//AttachTable attach_list;

class WebFACEBOOKExtractor : public BaseWebSNSExtractor
{
	public:
		WebFACEBOOKExtractor();
		virtual ~WebFACEBOOKExtractor();

		bool IsWebSNSText(PacketInfo* pktInfo);
	private:
		int htmldecode_full(char *src,char *dest);
		void StoreMsg2DB(Node* msgNode);
		char *memfind(char *str, char *substr, size_t n);
		int create_dir(char *path, char *sns_name);
		int del_attach_node(Attach_info *temp);
	private:
		boost::regex* sendRule_;
		boost::regex* senddRule_;
		boost::regex* sendNewsRule_;
		boost::regex* senddNews1Rule_;
		boost::regex* senddNews2Rule_;
		boost::regex* uploadRule_;
		boost::regex* uploaddRule_;
		boost::regex* sendStatusRule_;
		boost::regex* senddStatusRule_;
		boost::regex* replyStatusRule_;
		boost::regex* replyyStatusRule_;
		boost::regex* recvStatusRule_;
		boost::regex* recvRule_;
		u_int32_t sendSeq_;
		char* sendBody_;
		unsigned  int sendBodyLen_;
		Attach_info *attach_info;
		char DIRECTORY[255];
		char ATTCHPATH[255];
		char ATTCHTEMP[255];
};

#endif
// End of file
