#include "GameExtractor.h"
#include "Public.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir().
#include <netinet/in.h>
//#include "../clue/Clue.h"
#define WOW_TAG  0xed0a0040
#define TLBB_TAG 0x00370163
#define YOU_TAG  0x77015713
#define LTSJ_TAG 0x2920d700
#define RXJH_TAG 0x8000
#define RXJH_TAG2 0x28
//#define WMSJ_TAG 0x02
#define WMSJ_TAG 0x02
#define WMSJ_TAG2 0x10
//#define WMSJ_TAG3 0x0b
#define XQJSJ_TAG 0x03330051
//#define ZX2_TAG  0x03
#define ZX2_TAG  0x03
#define ZX2_TAG2  0x10
//#define ZX2_TAG3  0x0b
#define CGA_HEADLEN 40
#define CGA_TAG  0x000001b0
#define CGA_TAG2 0x00030001
#define CGA_TAG3 0x00000007
//#define CGA_TAG4 0x656d6167
#define VS_USER_RULE  "^<iq\\s.*<username>(\\w+)</username></query></iq>"
#define VS_TAG  0x2071693c
#define VS_TAG2  0x273d6f74
#define VS_TAG3  0x31646975
#define OURGAME_HEADLEN 20
#define OURGAME_TAG 0x0000007d
#define OURGAME_TAG2 0x00000178
#define OURGAME_TAG3 0x02080501
#define CHINAGAME_USER_RULE "^GET\\s/node_3637.htm\\sHTTP/1.1\r\n.*LoginName=(\\w+);.*"
#define CHINAGAME_TAG 0x20544547
#define CHINAGAME_TAG2 0x65646f6e
#define CHINAGAME_TAG3 0x37333633
#define GAME4399_USER_RULE "^POST\\s/(www4399_)?do.php.*loginuser=(\\w+).*"
#define GAME4399_TAG 0x54534f50
#define GAME4399_TAG2 0x2e6f642f
#define GAME4399_TAG3 0x3f706870
#define GAME4399_TAG4 0x39393334
#define GAME4399_TAG5 0x7777772f
#define QQGAME_TAG 0x0b024000
#define QQGAME_TAG2 0x00820000
#define POPKART_RULE "^GET\\s/kartclient/kartlogin.aspx\\sHTTP/1.1\r\n.*"
#define POPKART_TAG  0x20544547 
#define POPKART_TAG2	0x7472616b

GameExtractor::GameExtractor()
{   
	sprintf(DIRECTORY,"%s%s",LzDataPath,"/spyData/moduleData/Game");
	isRunning_ = true;
	isDeepParsing_ = false;
    protoType_ = PROTOCOL_GAME;
    // Create a directory to store the Game message files.
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);

	vsUserRule_ = new boost::regex(VS_USER_RULE);
	chinaGameUserRule_ = new boost::regex(CHINAGAME_USER_RULE);
	game4399UserRule_ = new boost::regex(GAME4399_USER_RULE);
	popkartRule_ = new boost::regex(POPKART_RULE);
    memcpy(tableName_, "GAME", 5);
    sprintf(dataFile_, "%s/%s\0", DIRECTORY, tableName_);
}

GameExtractor::~GameExtractor()
{
	delete vsUserRule_;
	delete chinaGameUserRule_;
	delete game4399UserRule_;
	delete popkartRule_;
}

bool GameExtractor::IsImText(PacketInfo* pktInfo)
{
    bool isGame = false;
    //assert(pktInfo != NULL);
    pktInfo_ = pktInfo;
  
    if (*reinterpret_cast<const unsigned int*>(pktInfo_->body) == WOW_TAG) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"WOW Login!!!"<<endl;
        isGame = MatchWOW();
    }
     else if (*reinterpret_cast<const unsigned int*>(pktInfo_->body) == TLBB_TAG &&
			   pktInfo_->destPort==3733) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"TLBB Login!!!"<<endl;
        isGame = MatchTLBB();
    }
    else if (*reinterpret_cast<const unsigned int*>(pktInfo_->body) == YOU_TAG) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"YOU Online Login!!!"<<endl;
        isGame = MatchYOU();
    }
    else if (*reinterpret_cast<const unsigned int*>(pktInfo_->body) == LTSJ_TAG) {
       // cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"LTSJ Login!!!"<<endl;
        isGame = MatchLTSJ();
    }
    else if (*reinterpret_cast<const u_short*>(pktInfo_->body) == RXJH_TAG && 
     *(pktInfo_->body + pktInfo_->bodyLen - 58)==RXJH_TAG2) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"RXJH Login!!!"<<endl;
        isGame = MatchRXJH();
    }
    else if (*(pktInfo_->body) == WMSJ_TAG &&
     pktInfo_->destPort==29000 &&
     *(pktInfo_->body + pktInfo_->bodyLen - 17)==WMSJ_TAG2) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"WMSJ Login!!!"<<endl;
        isGame = MatchWMSJ();
    }
    else if (*reinterpret_cast<const unsigned int*>(pktInfo_->body) == XQJSJ_TAG) {
        //cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"XQJSJ Login!!!"<<endl;
        isGame = MatchXQJSJ();
    }
    else if (*(pktInfo_->body) == ZX2_TAG &&
     pktInfo_->destPort==29000 &&
     *(pktInfo_->body + pktInfo_->bodyLen - 17)==ZX2_TAG2) {
       // cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"Zhu Xian 2 Login!!!"<<endl;
        isGame = MatchZX2();
    }
	else if (pktInfo_->bodyLen > CGA_HEADLEN &&
				pktInfo_->destPort==1201 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body)==CGA_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+4)==CGA_TAG2 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+8)==CGA_TAG3){
				 //&& *reinterpret_cast<const u_int*>(pktInfo_->body+112)==CGA_TAG4){
		isGame = MatchCGA();
	}
	else if(*reinterpret_cast<const u_int*>(pktInfo_->body)==VS_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+14)==VS_TAG2 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+8)==VS_TAG3){
		isGame = MatchVS();
	}
	else if (pktInfo_->bodyLen > OURGAME_HEADLEN &&
				*reinterpret_cast<const u_int*>(pktInfo_->body)==OURGAME_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+4)==OURGAME_TAG2 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+8)==OURGAME_TAG3){
		isGame = MatchOurGame();
	}
	else if(*reinterpret_cast<const u_int*>(pktInfo_->body)==CHINAGAME_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+5)==CHINAGAME_TAG2 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+10)==CHINAGAME_TAG3){
		isGame = MatchChinaGame();
	}
	else if((*reinterpret_cast<const u_int*>(pktInfo_->body)==GAME4399_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+5)==GAME4399_TAG2 &&
				 *reinterpret_cast<const u_int*>(pktInfo_->body+9)==GAME4399_TAG3)||(*reinterpret_cast<const u_int*>(pktInfo_->body)==GAME4399_TAG &&
				 *reinterpret_cast<const u_int*>(pktInfo_->body+5)==GAME4399_TAG5 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+9)==GAME4399_TAG4 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+17)==GAME4399_TAG3)){
		
		isGame = MatchGame4399();
	}
	else if(*reinterpret_cast<const u_int*>(pktInfo_->body)==QQGAME_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+4)==QQGAME_TAG2){
	
		isGame = MatchQQGame();
	}
	else if(*reinterpret_cast<const u_int*>(pktInfo_->body)==POPKART_TAG &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+5)==POPKART_TAG2 &&
				*reinterpret_cast<const u_int*>(pktInfo_->body+16)==POPKART_TAG2){
		isGame = MatchPOPKART();
	}		
    return isGame;
}


bool GameExtractor::MatchWOW()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-88;
	if(len<1||len>100)
	{
		return matched;
	}
    char* user=new char[len+1];
    sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+88));
 
   char* passwd =NULL;
   protoId_ = PROTOCOL_ID_WOW;
               PushNode(CreateLoginNode(user, passwd,protoId_));
               
               if(user){
               user=NULL;
               }
             //cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
   
    return matched;
}

bool GameExtractor::MatchTLBB()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-11;
	if(len<5||len>50)
	{
		return matched;
	}
    char* user=new char[len+1];
   
    sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+11));

                char* passwd =NULL;
                protoId_ = PROTOCOL_ID_TLBB;
               PushNode(CreateLoginNode(user, passwd,protoId_));
               
               if(user){
               user=NULL;
               }
//               cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
  
   
    return matched;
}
bool GameExtractor::MatchYOU()
{
    bool matched = false;
   
    int userlen=pktInfo_->bodyLen-7-90;
	if(userlen<1||userlen>26)
	{
		return matched;
	}
    char* user=new char[userlen+1];
   
    sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+7));
   
    int passwdlen=pktInfo_->bodyLen-33;
	if(passwdlen<1||passwdlen>90)
	{
		return matched;
	}
    char* passwd=new char[passwdlen+1];
  
   sprintf(passwd,"%s\0",reinterpret_cast<char*>(pktInfo_->body+33));
 
                protoId_ = PROTOCOL_ID_YOUOL;
               PushNode(CreateLoginNode(user, passwd,protoId_));
               if(passwd){
                passwd=NULL;
               }
               if(user){
               user=NULL;
               }
//               cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
    
   
    return matched;
}

bool GameExtractor::MatchLTSJ()
{
    bool matched = false;
   
    const u_short* ucs2 = reinterpret_cast<const u_short*>(pktInfo_->body + 12);
    char* user = ::UCS2ToUTF8(ucs2);
             
    

               char* passwd =NULL;
               protoId_ = PROTOCOL_ID_LTWORLD;
               PushNode(CreateLoginNode(user, passwd,protoId_));
               
               if(user){
               user=NULL;
               }
//               cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
  
    return matched;
}

bool GameExtractor::MatchRXJH()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-6-58;
	if(len<5||len>14)
	{
		return matched;
	}
    char* usr=new char[len+1];
    memset(usr,0,len+1);
    memcpy(usr,pktInfo_->body + 6,len);
  
                char* passwd =NULL;
                protoId_ = PROTOCOL_ID_RXJH;
               PushNode(CreateLoginNode(usr, passwd,protoId_));
              
               if(usr){
               usr=NULL;
               }
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
   
   
    return matched;
}

bool GameExtractor::MatchWMSJ()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-3-17;
	if(len<6||len>16)
	{
		return matched;
	}
    char* usr=new char[len+1];
    memset(usr,0,len+1);
    memcpy(usr,pktInfo_->body + 3,len);
   
   
                char* passwd =NULL;
                protoId_ = PROTOCOL_ID_WMWORLD;
               PushNode(CreateLoginNode(usr, passwd,protoId_));
               
               if(usr){
               usr=NULL;
               }
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
    
   
    return matched;
}
bool GameExtractor::MatchXQJSJ()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-8-64;
	if(len<6||len>20)
	{
		return matched;
	}
    char* user=new char[len+1];
  
    sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+8));
    
                char* passwd =NULL;
                protoId_ = PROTOCOL_ID_SUNWE;
               PushNode(CreateLoginNode(user, passwd,protoId_));
               
               if(user){
               user=NULL;
               }
//               cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
   
   
    return matched;
}

bool GameExtractor::MatchZX2()
{
    bool matched = false;
   
    int len=pktInfo_->bodyLen-3-17;
	if(len<6||len>16)
	{
		return matched;
	}
    char* usr=new char[len+1];
    memset(usr,0,len+1);
    memcpy(usr,pktInfo_->body + 3,len);
   
                char* passwd =NULL;
               protoId_ = PROTOCOL_ID_WMZHUXIAN;
               PushNode(CreateLoginNode(usr, passwd,protoId_));
                
               if(usr){
               usr=NULL;
               }
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
               matched = true;
  
   
    return matched;
}

bool GameExtractor::MatchCGA()
{
	bool matched = false;
   
	
	char* user=new char[32];
	sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+40));
   
	char* passwd =new char[32];
	sprintf(passwd,"%s\0",reinterpret_cast<char*>(pktInfo_->body+72));
	protoId_ = PROTOCOL_ID_CGA;
	PushNode(CreateLoginNode(user, passwd,protoId_));
	if(passwd){
		passwd=NULL;
	}
	if(user){
		user=NULL;
	}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
	matched = true;
  
   
	return matched;
}

bool GameExtractor::MatchVS()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	
	if(boost::regex_search(first, last, matchedStr, *vsUserRule_)){
	int len = matchedStr[1].length();
	char* str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[1].first, len);
	
	char* user=str;
	
   
	char* passwd =NULL;
	
	protoId_ = PROTOCOL_ID_VS;
	PushNode(CreateLoginNode(user, passwd,protoId_));
	
	
	if(user){
		user=NULL;
	}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
	matched = true;
	
	}
	return matched;
}

bool GameExtractor::MatchOurGame()
{
	bool matched = false;
   
	
	char* user=new char[21];
	sprintf(user,"%s\0",reinterpret_cast<char*>(pktInfo_->body+20));
   
	char* passwd = NULL;
	protoId_ = PROTOCOL_ID_OURGAME;
	PushNode(CreateLoginNode(user, passwd,protoId_));
	
	if(user){
		user=NULL;
	}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
	matched = true;
  
   
	return matched;
}

bool GameExtractor::MatchChinaGame()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	
	if(boost::regex_search(first, last, matchedStr, *chinaGameUserRule_)){
	int len = matchedStr[1].length();
	char* str = new char[len + 1];
	str[len] = 0;
	memcpy(str, matchedStr[1].first, len);
	
	char* user=str;

   
	char* passwd =NULL;
	
	protoId_ = PROTOCOL_ID_CHINAGAMES;
	PushNode(CreateLoginNode(user, passwd,protoId_));
	
	
	if(user){
		user=NULL;
	}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
	matched = true;
	
	}
	return matched;
}
	
bool GameExtractor::MatchGame4399()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	
	if(boost::regex_search(first, last, matchedStr, *game4399UserRule_)){
		int len = matchedStr[2].length();
		char* str = new char[len + 1];
		str[len] = 0;
		memcpy(str, matchedStr[2].first, len);
		
		char* user=str;
		
		char* passwd=NULL;
		protoId_ = PROTOCOL_ID_4399;
		PushNode(CreateLoginNode(user, passwd,protoId_));
	
		
		if(user){
			user=NULL;
		}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
		matched = true;
	
	}
	return matched;
}

bool GameExtractor::MatchQQGame()
{
	bool matched = false;
   
	
	char* user=new char[11];
	sprintf(user,"%d\0",ntohl(*reinterpret_cast<u_int*>(pktInfo_->body+9)));
	
	char* passwd = NULL;
	protoId_ = PROTOCOL_ID_QQGAME;
	PushNode(CreateLoginNode(user, passwd,protoId_));
	
	if(user){
		user=NULL;
	}
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
	matched = true;
  
   
	return matched;
}

bool GameExtractor::MatchPOPKART()
{
	bool matched = false;
	boost::cmatch matchedStr;
	const char* first = pktInfo_->body;
	const char* last = pktInfo_->body + pktInfo_->bodyLen;
	
	if(boost::regex_search(first, last, matchedStr, *popkartRule_)){
		
		
		char* user=NULL;
		
		char* passwd=NULL;
		protoId_ = PROTOCOL_ID_POPKART;
		PushNode(CreateLoginNode(user, passwd,protoId_));
	
		
              // cout<< __FILE__ << ":" << __FUNCTION__ << ":" <<"PushNode over!!!"<<endl;
		matched = true;
	
	}
	return matched;
}


MsgNode* GameExtractor::CreateLoginNode(char* user ,char* passwd ,u_int type)
{   
    
    u_int clueId=0;
    // Create the message node.
    MsgNode* loginNode = new MsgNode;
    memset(loginNode, 0, sizeof(MsgNode));
    
 
    loginNode->user = user;
    user=NULL;
    loginNode->pass = passwd;
    passwd=NULL;
    loginNode->protocolType = type;
    // Get the current time.
    loginNode->time = NULL;
    time(&loginNode->timeVal);
    // Copy basic data to message node
    memcpy(loginNode, pktInfo_, COPY_BYTES);
     char strmac[20];
    memset(strmac,0,20);
    ParseMac(pktInfo_->srcMac,strmac);
    clueId = GetClueId(protoType_, strmac ,pktInfo_->srcIpv4,loginNode->user);
    loginNode->clueId = clueId;
    loginNode->fileName = NULL;
    
    loginNode->msgType = Login;
    loginNode->from = NULL;
    loginNode->to = NULL;
    loginNode->text = NULL;
    loginNode->subject=NULL;
    loginNode->affixFlag=0;
    loginNode->cc=NULL;
    loginNode->path=NULL;
    pktInfo_ = NULL;
    return loginNode;
}


// End of file

