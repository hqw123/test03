
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
#include <arpa/inet.h>

#include "GambleAccountExtractor.h"
#include "Public.h"
#include "clue_c.h"
#include "db_data.h"
#include "Analyzer_log.h"
#include "util.h"

#define SUNCITY_RULE "rtmp://www.cr298.com:1931/.*pageUrl.*objectEncoding.*\x09\x02..(.*?)\x02..(.*?)\x02.*Suncity.*Member.*tc$"
//.*\x09\x02..(.*?)\x02..(.*?)\x02

//-----------------------------------------------------------------------
// Func Name   : GambleAccountExtractor
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
GambleAccountExtractor::GambleAccountExtractor()
{
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/GambleAccount");
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	suncityRule_ = new boost::regex(SUNCITY_RULE);
	memcpy(tableName_, "GambleAccount", 14);
	sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

//-----------------------------------------------------------------------
// Func Name   : ~FetionTextExtractor
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
GambleAccountExtractor::~GambleAccountExtractor()
{
	delete suncityRule_;
}

//-----------------------------------------------------------------------
// Func Name   : IsImText
// Description : The interface of base class.
// Parameter   : pktInfo: the network packet after parsing.
// Return      : bool
//-----------------------------------------------------------------------
bool GambleAccountExtractor::IsImText(PacketInfo* pktInfo)
{
	bool isGambleAccount = false;
	//assert(pktInfo != NULL);
	pktInfo_ = pktInfo;

	if (pktInfo_->pktType != TCP || pktInfo_->bodyLen <= 0)
		return isGambleAccount;
	
    // Filter the port and packet lenth at the first.
	if(pktInfo_->destPort == 1931) 
	{
		//cout<<"Suncity Game"<<endl;
		isGambleAccount = MatchSuncity();
	}
	else if(pktInfo_->destPort == 11600) 
	{
		//cout<<"Suncity Game"<<endl;
		isGambleAccount = MatchBjl();
	}
	
	return isGambleAccount;
}

//-----------------------------------------------------------------------
// Func Name   : MatchSuncity
// Description : The function matches the packet if is belong to Suncity Game.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool GambleAccountExtractor::MatchSuncity()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	unsigned int clueId = 0;
    // Get the packet body on TCP layer.
//www.cr298.com

	if (boost::regex_search(first, last, matchedStr, *suncityRule_))
	{
		int len = matchedStr[1].length();
		char* user = new char[len + 1];
		user[len] = 0;
		memcpy(user, matchedStr[1].first, len);
		
		len = matchedStr[2].length();
		char* pass = new char[len + 1];
		pass[len] = 0;
		memcpy(pass, matchedStr[2].first, len);
		
		struct in_addr addr;	
		char tmp[256] = {0};
		char srcMac[20] = {0};

		ParseMac(pktInfo_->srcMac, srcMac);
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(srcMac, inet_ntoa(addr));

		/*write webaccount data to shared memory, by zhangzm*/
		WEBACCOUNT_T tmp_data;
		memset(&tmp_data, 0, sizeof(tmp_data));
		
		tmp_data.p_data.clueid = clueId;
		tmp_data.p_data.readed = 0;
		strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
		strncpy(tmp_data.p_data.clientMac, srcMac, 17);
		sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
		addr.s_addr = pktInfo_->destIpv4;
		strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
		sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
		
		tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;
		strcpy(tmp_data.url, "www.cr298.com:1931");
		strncpy(tmp_data.username, user, 64);
		strncpy(tmp_data.password, pass, 64);
		
		tmp_data.p_data.proType = 201;
		tmp_data.p_data.deleted = 0;
		msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
		
		delete user;
		delete pass;
		matched = true;
	} 
   
	return matched;
}

//-----------------------------------------------------------------------
// Func Name   : MatchBjl
// Description : The function matches the packet if is belong to Bjl.
//               If so, process it.
// Parameter   : void
// Return      : bool
//-----------------------------------------------------------------------
bool GambleAccountExtractor::MatchBjl()
{
//lmm6199.com
	bool matched = false;
	unsigned int clueId = 0;
	uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
	map<uint64_t,BjlCrypt>::iterator it;
	it=keyMap.find(key);
	if(*reinterpret_cast<const unsigned int*>(pktInfo_->body) == 0x00000014 && pktInfo_->bodyLen == 20)
	{
		u_char* mkey=new u_char[16];
		memset(mkey,0,16);
		memcpy(mkey,pktInfo_->body+4,16);
		//cout<<"mkey: "<<bytesToHexString(mkey,16)<<endl;
		string s_key=bytesToHexString(mkey,16);
		string s_key1;
		for(int i=0;i<48;i+=3)
		{
			s_key1+="\\\\x";
			s_key1+=s_key[i];
			s_key1+=s_key[i+1];
		}
		
		BjlCrypt bjlCrypt;
		bjlCrypt.mkey=s_key1;
		keyMap.insert(map<uint64_t,BjlCrypt>::value_type(key,bjlCrypt));
	
		delete mkey;
		matched = true;
	}
	if(it != keyMap.end() && *reinterpret_cast<const unsigned int*>(pktInfo_->body) == 0x00000034 && pktInfo_->bodyLen == 52)
	{
		u_char* crypt=new u_char[48];
		memset(crypt,0,48);
		memcpy(crypt,pktInfo_->body+4,48);
		//cout<<"mkey: "<<it->second.mkey<<endl;
		//cout<<"mkey_Len: "<<it->second.mkey.length()<<endl;
		//cout<<"crypt: "<<bytesToHexString(crypt,48)<<endl;
		//cout<<"crypt_Len: "<<bytesToHexString(crypt,48).length()<<endl;
		string s= bytesToHexString(crypt,48);
		string s1;
		
		for(int i=0;i<144;i+=3)
		{
			s1+="\\\\x";
			s1+=s[i];
			s1+=s[i+1];
		}
		//cout<<"s1: "<<s1<<endl;
		
		struct in_addr addr;
		char srcMac[20] = {0};

		ParseMac(pktInfo_->srcMac, srcMac);
		addr.s_addr = pktInfo_->srcIpv4;
		clueId = get_clue_id(srcMac, inet_ntoa(addr));

		/*write webaccount data to shared memory, by zhangzm*/
		WEBACCOUNT_T tmp_data;
		memset(&tmp_data, 0, sizeof(tmp_data));
		
		tmp_data.p_data.clueid = clueId;
		tmp_data.p_data.readed = 0;
		strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
		strncpy(tmp_data.p_data.clientMac, srcMac, 17);
		sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
		addr.s_addr = pktInfo_->destIpv4;
		strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
		sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
		
		tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;
		strcpy(tmp_data.url, "lmm6199.com");
		strncpy(tmp_data.username, it->second.mkey.c_str(), 64);
		strncpy(tmp_data.password, s1.c_str(), 64);
		
		tmp_data.p_data.proType = 201;
		tmp_data.p_data.deleted = 0;
		msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));

		delete crypt;
		keyMap.erase(key);
		matched=true;
	}
	return matched;
}


// End of file
