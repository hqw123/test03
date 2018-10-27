
#include <string>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <pthread.h>

#include "PacketParser.h"
#include "analyse_smtp.h"
#include "analyse_FTP.h"
#include "Public.h"
#include "PublicDb.h"
#include "im/IsIm.h"
#include "PenetrationTool/IsTools.h"
#include "webim/IsWebIM.h"
#include "websns/IsWebSNS.h"
#include "research/Research.h"
#include "research_m/Research_m.h"
#include "clue_c.h"
#include "http_get.h"
#include "account/HttpPostEntranceL.h"
#include "SentinelKeysLicense.h"

#include "DNSSpoof.h"
#include "DNSserver.h"
#include "DNSutil.h"
#include "siteSwitch.h"
#include "pptp/vpn.h"
//#include "Analyzer_log.h"

using namespace std;

#define IS_MOVE 1
#define LZ_DNS_PORT 53

//DNS
char serverIp[16];
char senddev[DEV_LENTH];
//MacIpPair* array=NULL;
char* g_hostL=NULL;
char* g_userL=NULL;
char* g_passL=NULL;
char* g_databaseL=NULL;

char path[20];

//for getting the ip of the special domain
struct ServerIP serverIP;
struct DnsPkt  dnsPkt;

extern "C" {
#include "webmail.h"
#include "weibo.h"
}

PublicDb * g_db_conn = NULL;
pcap_t * pt;

static char errbuf[256];
void sigproc( int sig );
int getlocalip(char ip[16], char* card);
int initServerIp();
bool Check();
void* writeServerIp(void*);
void* detectPPPOE(void*);

/* 打印程序信息 */
static void print_program_info(const char *);

/* 对象相关变量和函数 */
static string g_object_mac;
static string g_object_ip;
static void *watch_file_thread(void *arg);
static void set_object_mac(const char *file);
static void set_object_ip(const char *file);
static inline bool is_object_mac(const unsigned char *mac);
static inline bool is_object_ip(const unsigned int ip);
char *GetIpList(xmlChar *account);

void * DoMapList( void * )
{
	while(true)
	{
		GetObjectMacList();
		UpdateObjectMacList();
//		ShowMapList();
		sleep(30);
	}
}

int main( int argc, char* argv[] )
{
	/* 打印程序信息 */
#ifdef VPDNLZ
	print_program_info("GLZProject VPDNLZ Analyzer");
#else
	print_program_info("GLZProject Analyzer");
#endif

	/* 检查加密狗 */
#ifdef CHECK
	if (!Check())
	{
		fprintf(stderr, "check failed\n");
		return -1;
	}
#endif
	memset(path,0,20);
	memcpy(path,"a.txt",5);
	int idns=0;
	//public
	Public * pub = new Public;
	pub->CreateDir();
	pub->ReadConfig();
	
	//cout<<"start ..."<<endl;
	LOG_DEBUG("start ...\n");
	g_db_conn = PublicDb::get_instance("127.0.0.1", "127.0.0.1");
	SMTP smtp(g_db_conn);
	FTP ftp(g_db_conn);
	PacketParser pktParser;
	OnImSysInit(g_db_conn);
	OnToolsSysInit(g_db_conn);
	OnWebIMSysInit(g_db_conn);
	OnWebSNSSysInit(g_db_conn);
	//httpget
	HttpGet httpget;
	
	DNSserver* dnsServer=NULL;
	
	if(strcmp("remoteip",SSL_PROXY_MODE)==0)
	{
		int tip=inet_aton(SSL_DOMAIN_NAME, (in_addr *)serverIP.ip);
		LOG_INFO(".................severip: %08x\n",serverIP.ip[0]);
	}			
	else if(strcmp("local",SSL_PROXY_MODE)){ 
		LOG_INFO("Proxy mode: %s\n",SSL_PROXY_MODE);
		dnsServer=new DNSserver();
		dnsServer->setDomain(SSL_DOMAIN_NAME,0);
		dnsServer->setDev(A_OUT_ETH,1);
		dnsServer->run(0);
	}
	else
	{
		LOG_INFO("Proxy mode: %s\n",SSL_PROXY_MODE);
		if(getlocalip(serverIp,(char*)C_PROXY_ETH)!=1)
		{
			LOG_DEBUG("BAD NEWS : INVALID PROXY NET DEVICE !!!\n");
			if(!strcmp(SSL_RUN,"1"))
			{
				LOG_FATAL("BAD NEWS : SYSTEM WILL EXIT \n");
				exit(-2);
			}
				
		}
	}
	pthread_t tidchck;
	int rt2=pthread_create(&tidchck,0,checkSwitch,NULL);
	if(rt2){
		LOG_ERROR("OH,NO GOOD NEWS: SOMETHING WRONG HAPPENDED WHEN \
					CREATE NEW THREAD FOR CHECK STATUS !!!\n");
		return -2;
	}	



	/* write server ip into file dns.ini */
	pthread_t wpid;
	int wps=pthread_create(&wpid,0,writeServerIp,0);
	if(!wps)
		LOG_INFO("OK WRITE SERVERIP THREAD IS RUNNING !!!\n");
	else{
		LOG_ERROR("OH BAD NEWS ,SOMETHING WRONG HAPPEND WHEN CREATE THREAD FOR WRITING SERVERIP INTO DNS.INI !!!\n");
		exit(3);
	}
	/*end write server ip into file dns.ini */
	
    /* regise signal ctrl+c stop capture */
    signal( SIGINT, sigproc ) ;
    char * capDev;

	//init DNSSpoof
	g_hostL=(char*)server;
	g_userL=(char*)user;
	g_passL=(char*)password;
	g_databaseL=(char*)database;
	strcpy(senddev,(char*)B_IN_ETH);	
	//strcpy(senddev,(char*)C_PROXY_ETH);
	memset(serverIp,0,16);
	DNSSpoof dnsSpoof;
	
	//init postEntrance
	HttpPostEntrance httpPostEntrance;
	
    //init libpcap
	capDev = (char *)B_IN_ETH;
	LOG_INFO("capDev is : '%s'  \n", capDev );
	
	//maplist thread
	LOG_INFO("create a maplist thread ...\n");
	pthread_t pid;

	int status = pthread_create( &pid, NULL, DoMapList, NULL );
	if(status != 0)
	{
		LOG_ERROR("pthread_maplist faile...\n");
		exit(0);
	}
	
	LOG_INFO("pcap_open_live ...\n");
	pt = pcap_open_live( capDev, 8000, 1, 500, errbuf );
	if( pt == NULL )
	{
		LOG_FATAL("pcap_open_live:%s \n", errbuf );
		exit(0);
	}

#ifdef VPDNLZ
	/* 设置对象的IP */
	set_object_ip("/spy/config/Config.xml");
	//cout << "object_ip: " << g_object_ip << endl;
	LOG_INFO("object_ip: %s\n",g_object_ip.c_str());
#else
	/* 设置对象的MAC */
	set_object_mac("/spy/config/Config.xml");
	//cout << "object_mac: " << g_object_mac << endl;
	LOG_INFO("object_mac: %s\n",g_object_mac.c_str());
#endif

	/* 监视配置文件线程 */
	pthread_t pt_watch;
	pthread_create(&pt_watch, NULL, watch_file_thread, NULL);

	while(true)
	{
		const u_char * pkt;
		struct pcap_pkthdr_n * hdr;
		if (pcap_next_ex(pt, &hdr, &pkt) != 1)
			continue;

		pktParser.GetPktInfo((const char *)pkt,hdr);
		//////////////////////////////////////////////////////////////////////////////

		//ftp.IsFTP(&g_packetinfo);
		smtp.analyse_smtp(&g_packetinfo);
		if(g_packetinfo.pktType == TCP || g_packetinfo.pktType == UDP)
		{
#ifndef VPDNLZ
			if(IS_MOVE)
				research_m(&g_packetinfo, g_db_conn);
#endif
			research(&g_packetinfo, g_db_conn);
			if (IsIm(&g_packetinfo))
			{
				continue;
			}
			if ((g_packetinfo.pktType == TCP || g_packetinfo.destPort==53) && IsTools(&g_packetinfo))
			{
				continue;
			}
			if (IsWebIM(&g_packetinfo))
			{
				continue;
			}
		}
		//  if (IsWebSNS(&g_packetinfo))
		//	{
		//		continue;
		//	}
		if(g_packetinfo.pktType == TCP)
		{
			if(analyse_webmail(&g_packetinfo) == 1)
			{
				continue;
			}
			if (analyse_wb(&g_packetinfo) == 1)
			{
				continue;
			}

			//smtp.analyse_smtp(&g_packetinfo);

			//ftp.analyse_ftp(&g_packetinfo);
			
			ftp.IsFTP(&g_packetinfo);
			httpget.analyse_get_pkt(&g_packetinfo);
			
		}

		//////////////////////////////////////////////////////////////////////////////////
		if(!strcmp("1",SSL_RUN) && g_packetinfo.pktType==UDP&&g_packetinfo.destPort==LZ_DNS_PORT)
		{//printf("OK COMING INTO DNS ANALYZER\n");	//no clueid
		//printf("FUCK THE DNS STATUS IN MAIN THREAD: %s\n",SSL_RUN);
#ifdef VPDNLZ
			if (is_object_ip(g_packetinfo.srcIpv4))
			{
				dnsSpoof.ParseDNSQueries(&g_packetinfo);
			}
#else
			if (is_object_mac(g_packetinfo.srcMac))
			{
				dnsSpoof.ParseDNSQueries(&g_packetinfo);
			}
#endif
		}

		if(g_packetinfo.pktType==TCP)
		{
			int iPostFlag=0;
			iPostFlag=httpPostEntrance.isPostData(g_packetinfo);
			if(iPostFlag==HTTP_POST_FIRST_PACKET || iPostFlag==HTTP_POST_PACKET)
			{
#ifdef VPDNLZ
				int iObjectId=0;
				char pppoe[60];
				if(iPostFlag==HTTP_POST_FIRST_PACKET)
				{
					iObjectId=GetObjectId2(g_packetinfo.srcIpv4,pppoe);
				}
				httpPostEntrance.pushData(g_packetinfo,iPostFlag,iObjectId,pppoe);
#else
				char chMac[18];
				chMac[17]=0;
				int iObjectId=0;
				if(iPostFlag==HTTP_POST_FIRST_PACKET)
				{
					unsigned char* chpMac=g_packetinfo.srcMac;
					sprintf(chMac,"%02x-%02x-%02x-%02x-%02x-%02x",chpMac[0]&0xff,
					chpMac[1]&0xff,chpMac[2]&0xff,chpMac[3]&0xff,chpMac[4]&0xff,
					chpMac[5]&0xff);
					iObjectId=GetObjectId(chMac);
				}
				httpPostEntrance.pushData(g_packetinfo,iPostFlag,iObjectId);
#endif
			}
		}
		//////////////////////////////////////////////////////

			parse_vpn((void*)pkt,hdr->caplen);

		//////////////////////////////////////////////////////
        }

    return 0;
}

/*
	print_program_info - 打印程序信息
*/
static void print_program_info(const char *s)
{
	struct tm *tm;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);;

	LOG_INFO("%s\n", s);
	LOG_INFO("Complied Time: %s %s\n", __DATE__, __TIME__);
	LOG_INFO("Running Time: %04d-%02d-%02d %02d:%02d:%02d.%lu\n",
		tm->tm_year + 1900,
		tm->tm_mon + 1,
		tm->tm_mday,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec,
		tv.tv_usec);
	LOG_INFO("\n");
}

// single processing function 
void sigproc( int sig )
{
    pcap_close(pt);
    LOG_DEBUG("Analyzer is exited!\n");
    exit(0);
}

// get ip by ether-card name
int getlocalip(char ip[16], char* card)
{	
	memset(ip,0,16);
	int sockfd; 
	if (-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0))) 
	{
		perror( "socket" );
		return -1;
	}
  
	struct ifreq req;
	struct sockaddr_in *host;
  
	bzero(&req, sizeof(struct ifreq));
	strcpy(req.ifr_name, card);
	if(ioctl(sockfd, SIOCGIFADDR, &req))
		return -1;
	host = (struct sockaddr_in*)&req.ifr_addr;
	strcpy(ip, inet_ntoa(host->sin_addr));
	close(sockfd);
	serverIP.ip[0]=(unsigned int)host->sin_addr.s_addr;	
	LOG_INFO("PROXY SERVER IP: %d.%d.%d.%d\n",
		   serverIP.ip[0]>>24&0xff,serverIP.ip[0]>>16&0xff,
		   serverIP.ip[0]>>8&0xff,serverIP.ip[0]&0xff);
	return 1;
}

int initServerIp()
{
	system("ifconfig ppp0 |grep inet|awk \'{print $2}\' >/tmp/dns.lock");
	FILE *fp=fopen("/tmp/dns.lock","r");
	if(!fp)
	{
		LOG_FATAL("can't find ip of server\n");
		exit(1);
	}
	int iRead=0;
	char chtmp[200];
	memset(chtmp,0,200);
	iRead=fread(chtmp,1,199,fp);
	if(iRead<12)
	{
		LOG_FATAL("can't find ip of server\n");
		exit(1);
	}
	char* addr=strstr(chtmp,"addr:");
	int j=0;
	addr+=5;
	char* addrEnd=addr;
	while(*addrEnd && j<16)
	{
		j++;
		addrEnd++;
	}
	int iplen=(int)addrEnd-(int)addr;
	if(iplen>=7)
	{
		memset(serverIp,0,16);
		memcpy(serverIp,addr,iplen);
		return 1;
	}
	return 0;
}

void* detectPPPOE(void*)
{
	int flag=0;
	while(1)
	{
		flag=0;
		system("ifconfig ppp0 |grep inet|awk \'{print $2}\' >/tmp/dns.lock.detect");
		FILE *fp=fopen("/tmp/dns.lock.detect","r");
		char ipnow[200];
		memset(ipnow,0,200);
		int readnow=0;
		if(fp)
		{
			readnow=fread(ipnow,1,199,fp);
			fclose(fp);
		}
		fp=fopen("/tmp/dns.lock","r");
		char ipformer[200];
		memset(ipformer,0,200);
		int readformer=0;
		if(fp)
		{
			readformer=fread(ipformer,1,199,fp);
		}
	
		if(readnow==readformer && readnow>0 && strcmp(ipnow,ipformer)==0)
		{
			/*char* addr=ipformer;
			int j=0;
			while(j<5){
				if(memcmp(addr,"addr:")==0)
					break;
				j++;
				addr++;
			}
			*/
			char* addr=strstr(ipformer,"addr:");
			if(addr)
			{
				addr+=5;
				char inaddr[16];
				memset(inaddr,0,16);
				int i=0;
				while((int)addr<(int)readformer+200 && i<15 && ((*addr>='0' && *addr<='9')|| *addr=='.'))
				{
					inaddr[i]=*addr;
					i++;
					addr++;
				}
				flag=inet_addr(inaddr);
			}
		}
		if(flag==-1 || flag==0)
			initServerIp();
		sleep(3000);
	}
	return 0;
}

bool Check()
{
	SP_HANDLE license;
	SP_STATUS status = SP_FAIL;
	status = SFNTGetLicense(DEVELOPERID,
				SOFTWARE_KEY,
				LICENSEID,
				SP_STANDALONE_MODE | SP_ENABLE_TERMINAL_CLIENT,
				&license);
	if (status == SP_SUCCESS)
	{
		return true;
	} 
	else 
	{
		//cout << "Fail to verify the license, please make sure you got the licence !" << endl;
		//cout << "System is closed ..." << endl;
		LOG_ERROR("Fail to verify the license, please make sure you got the licence !\nSystem is closed ...\n");
	}
	return false;
}

void* writeServerIp(void*){
	int r=1;
	int r2=1;
	while(r){
		r2=1;
		while(r2){
			if(serverIP.ip[0]){
				//write file here
				int fd=open("dns.ini",O_RDWR|O_CREAT|O_TRUNC,S_IRWXU);
				if(fd==-1){
					LOG_FATAL("OH BAD NEWS,CREATE FILE FAIL!!!\n");
					exit(2);
				}
				int ri=write(fd,serverIP.ip,4);
				close(fd);
				if(ri!=4){
					LOG_FATAL("OH BAD NEWS ,WRITE FIAL FAIL !!!\n");
					exit(3);
				}
				LOG_INFO("OK,THE SERVER IP HAS BEEN WRITEN INTO FILE DNS.INI !!!\n");
				r2=0;
				// maybe there is no needing to loop
				r=0;
				continue;
			}
			sleep(30);
		}
		sleep(60*60);
	}

}

/*
	watch_file_thread - 监视配置文件
*/
static void *watch_file_thread(void *arg)
{
	const char *path = "/spy/config/Config.xml";
	while (1)
	{
#ifdef VPDNLZ
		set_object_ip(path);
#else
		set_object_mac(path);
#endif
		sleep(10);
	}
	return NULL;
}

/*
	set_object_mac - 设置监控对象的MAC
*/
static void set_object_mac(const char *file)
{
	xmlDocPtr  doc      = NULL;
	xmlNodePtr curNode  = NULL;
	xmlNodePtr itemNode = NULL;
	
	if ((doc = xmlReadFile(file, "UTF-8", XML_PARSE_RECOVER)) == NULL)
	{
		fprintf(stderr, "xmlReadFile failed: %s\n", file);
		return;
	}

	if ((curNode = xmlDocGetRootElement(doc)) == NULL)
	{
		fprintf(stderr, "xmlDocGetRootElement failed\n");
		xmlFreeDoc(doc);
		return;
	}

	if (xmlStrcmp(curNode->name, BAD_CAST "config"))
	{
		fprintf(stderr, "can't find config in %s\n", file);
		xmlFreeDoc(doc);
		return;
	}

	for (itemNode = curNode->xmlChildrenNode; itemNode; itemNode = itemNode->next)
	{
		if (itemNode->type != XML_ELEMENT_NODE)
		{
			continue;
		}

		if (!xmlStrcmp(itemNode->name, BAD_CAST "objectMac")) 
		{
			g_object_mac = (const char *)xmlNodeGetContent(itemNode);
			break;
		} 
	}
	xmlFreeDoc(doc);
}

/*
	set_object_ip - 设置监控对象的ip
*/
static void set_object_ip(const char *file)
{
	xmlDocPtr  doc      = NULL;
	xmlNodePtr curNode  = NULL;
	xmlNodePtr itemNode = NULL;
	
	if ((doc = xmlReadFile(file, "UTF-8", XML_PARSE_RECOVER)) == NULL)
	{
		fprintf(stderr, "xmlReadFile failed: %s\n", file);
		return;
	}

	if ((curNode = xmlDocGetRootElement(doc)) == NULL)
	{
		fprintf(stderr, "xmlDocGetRootElement failed\n");
		xmlFreeDoc(doc);
		return;
	}

	if (xmlStrcmp(curNode->name, BAD_CAST "config"))
	{
		fprintf(stderr, "can't find config in %s\n", file);
		xmlFreeDoc(doc);
		return;
	}

	string object_account;
	for (itemNode = curNode->xmlChildrenNode; itemNode; itemNode = itemNode->next)
	{
		if (itemNode->type != XML_ELEMENT_NODE)
		{
			continue;
		}

		if (!xmlStrcmp(itemNode->name, BAD_CAST "objectAccount")) 
		{
			object_account = (const char *)xmlNodeGetContent(itemNode);
		}
	}
	xmlFreeDoc(doc);
	
	/* 通过pppoe帐号得到ip */
	char *p = GetIpList((xmlChar *)object_account.c_str());
	if (p != NULL)
		g_object_ip = p;
}

/*
	is_object_mac - 判断是否是监控对象的MAC
*/
static inline bool is_object_mac(const unsigned char *mac)
{
	char strmac[20];
	memset(strmac,0,20);

	ParseMac(mac, strmac);
	if(g_object_mac.find(strmac) != string::npos)
		return true;
	return false;
}

/*
	is_object_ip - 判断是否是监控对象的ip
*/
static inline bool is_object_ip(const unsigned int ip)
{
	char ip_str[16];
	struct in_addr addr;
	addr.s_addr = ip;

	memcpy(ip_str, inet_ntoa(addr), sizeof(ip_str));
	if (g_object_ip.find(ip_str) != string::npos)
		return true;
	return false;

}

/*
	GetIpList - 得到一列ip
*/
char *GetIpList(xmlChar *account)
{
	if (account == NULL)
		return NULL;

	char *pppoe;
	if ((pppoe = strtok((char *)account, "_")) == NULL)
		return NULL;

	string sql = "select ip from object where ";
	sql = sql + "pppoe = \"" + pppoe + "\"";
	while ((pppoe = strtok(NULL, "_")) != NULL)
		sql = sql + "or pppoe = \"" + pppoe + "\"";

	MYSQL *conn = mysql_init(NULL);
	if (mysql_real_connect(conn,server,user,password,database, 0, NULL, 0) == NULL)
	{ 
		fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
		return NULL;
	}
	mysql_query(conn,"SET NAMES utf8");

	if (mysql_query(conn, sql.c_str()) != 0)
	{
		fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(conn));
		return NULL;
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	if ((result = mysql_store_result(conn)) == NULL)
	{
		fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
		return NULL;
	}

	string ip;
	while((row = mysql_fetch_row(result)))
		ip = ip + row[0] + "_";

	mysql_free_result(result);
	mysql_close(conn);

	return (char *)ip.c_str();
}
