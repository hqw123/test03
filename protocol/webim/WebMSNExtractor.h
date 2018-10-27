#ifndef WEBMSN_EXTRACTOR
#define WEBMSN_EXTRACTOR

#include "BaseWebIMExtractor.h"

#include <boost/regex.hpp>
#include <string>
#include <map>

#define  MAX_CONT_LEN 1500

using namespace std;
/*
enum WebMsnPacketType
{
  // Signin = 1,
   Session = 2,
   Ok,
   Signout,
   NotWebMsn
};
struct WebMsnContNode
{
     unsigned char srcMac[6];
     unsigned char destMac[6];
     unsigned int srcIpv4;
     unsigned int destIpv4;
     unsigned short srcPort;
     unsigned short destPort;
     unsigned short bodylen;
     char * post_content;
     char * reciv_content;
     unsigned int recive_length;
     unsigned int start_seq;
     unsigned int ok_start_seq;
     WebMsnPacketType  packetType;
     const char* from;
     const char* to;
     bool  done;
     bool ok_start;
   
};*/
struct Chat{
	string sender;
	string recver;
};
class WebMSNExtractor : public BaseWebIMExtractor
{
	public:
		WebMSNExtractor();
		virtual ~WebMSNExtractor();
    
		bool IsWebIMText(PacketInfo* pktInfo);
	/*private:
		void Type_judge(PacketInfo* pktInfo,WebMsnPacketType & pkType);
              	//void  Signin_analyse(PacketInfo* pktInfo);
              	void  Session_analyse(PacketInfo* pktInfo);
              	
              	void Del_MapNode(map<string,WebMsnContNode *>::iterator iter);
              	void WriteNode(char *textstr,map<string,WebMsnContNode*>::iterator iter,int sign);
              	//void WriteNodeSignin(char *fromstr, map<string,WebMsnContNode*>::iterator iter);
    
	private:
		//boost::regex* loginRule_;
		//boost::regex* logoutRule_;
		boost::regex* loginRule_;
               	boost::regex* telnameRule_;
               	boost::regex* contentRule_;
               	boost::regex* recivContentRule_;*/
	private:
		void StoreMsg2DB(Node* msgNode);
	private:
	/*	boost::regex* loginRule_;
		boost::regex* logoutRule_;
		boost::regex* senderRule_;
		boost::regex* recverRule_;
		boost::regex* sendMsgRule_;
		boost::regex* recvMsgRule_;*/
		map<uint64_t,Chat>keyMap;
		char DIRECTORY[255];
		
};

#endif
// End of file
