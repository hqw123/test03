
#include <signal.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <pthread.h>

#include "PacketParser.h"
#include "analyse_smtp.h"
#include "analyse_FTP.h"
#include "analyse_pppoe.h"
#include "analyse_telnet.h"
#include "analyse_domain.h"
#include "Public.h"
#include "PublicDb.h"
#include "im/IsIm.h"
#include "PenetrationTool/IsTools.h"
#include "webim/IsWebIM.h"
#include "websns/IsWebSNS.h"
#include "research/Research.h"
#ifndef VPDNLZ
#include "research_m/Research_m.h"
#endif
#include "clue_c.h"
#include "http_get.h"
#include "account/HttpPostEntranceL.h"
#include "webmail-LZ/webmail.h"
#include "SentinelKeysLicense.h"
#include "weibo/weibo.h"
#include "rmcontrol/rmcontrol.h"
#include "pptp/vpn.h"
#include "db_data.h"
#include "website/data_shunt.h"
//#include "cellphone/app_statistics.h"
#include "cellphone/imei.h"
#include "md5/analyse_md5.h"
#ifndef VPDNLZ
#define IS_MOVE 1
#endif
#define LZ_DNS_PORT 53
#define DAYS 30
//DNS
char serverIp[16] = {0};

PublicDb *g_db_conn = NULL;

//void sigproc( int sig );
int getlocalip(char ip[16], char* card);
#ifdef CHECK
bool Check();
#endif
void* writeServerIp(void*);
bool CheckTime();

#if 0
/* 打印程序信息 */
static void print_program_info(const char *);
#endif

void * DoMapList( void * )
{
    while(true)
    {
        GetClueList();
        UpdateClueList();
        sleep(30);
    }

    return NULL;
}

static Public *pub = NULL;
static SMTP *smtp = NULL;
static FTP *ftp = NULL;
static Telnet* telnet = NULL; 
static ParsePPPOE *parse_pppoe = NULL;
static PacketParser *pktParser = NULL;
static HttpGet *httpget = NULL;
static rmcontrol* rmc = NULL;
static ANALYSEDOMAIN *analyse_domain = NULL;

static HttpPostEntrance *httpPostEntrance = NULL;
static data_shunt *tcp_shunt = NULL;

#include  <com_log.h>

extern "C" int analyzer_init(int num)
{
#ifdef CHECK
    if (!Check())
    {
        fprintf(stderr, "check failed\n");
        return -1;
    }
#endif

/*
11111111111111111111111111111
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
*****************************
*/
    com_log_int("/spy/file/protocol.log", COM_LOG_LEVEL_WARN);

    //public
    pub = new Public;
    pub->CreateDir();
    pub->read_config();

    com_log_int("/spy/file/protocol.log", (COM_LOG_LEVEL)pub->get_log_level());

    if (msg_queue_init(num) < 0)
        return -1;
		
    LOG_DEBUG("analyzer_init start ...\n");
    g_db_conn = PublicDb::get_instance(pub->get_flood_server_ip(), pub->get_special_server_ip());
    bool con_state = g_db_conn->get_special_conn_state();
    if (con_state == false)
        return -1;
	
    smtp = new SMTP();
    ftp = new FTP();
    telnet = new Telnet();
    parse_pppoe = new ParsePPPOE();
    pktParser = new PacketParser;
	
    OnImSysInit();
    OnToolsSysInit();
    OnWebIMSysInit();
    //app_statistics_map_init();
    imei_map_init();
    md5_fun_init();
    //OnWebSNSSysInit();
	
    //httpget
    httpget = new HttpGet();
	
    // remote control
    rmc = new rmcontrol();
    //init postEntrance
    httpPostEntrance = new HttpPostEntrance;

    tcp_shunt = new data_shunt;
    analyse_domain = new ANALYSEDOMAIN;

    /*webmail init*/
    useragent_init();
    webmail_init();
		
    //maplist thread
    LOG_INFO("create a maplist thread ...\n");

    /*must update once before creating pthread*/
    GetClueList();
    UpdateClueList();
	
    pthread_t pid;
    int status = pthread_create(&pid, NULL, DoMapList, NULL);
    if (status != 0)
    {
        LOG_FATAL("pthread_maplist failed...\n");
        exit(0);
    }
	
    return 0;
}

extern "C" int analyzer_cleanup(void)
{
    if (pub)
    {
        delete pub;
        pub = NULL;
    }

    if (smtp)
    {
        delete smtp;
        smtp = NULL;
    }
	
    if (ftp)
    {
        delete ftp;
        ftp = NULL;
    }

    if(telnet)
    {
        delete telnet;
        telnet = NULL;
    }
	
    if (parse_pppoe)
    {
        delete parse_pppoe;
        parse_pppoe = NULL;
    }
	
    if (httpget)
    {
        delete httpget;
        httpget = NULL;
    }
	
    if (httpPostEntrance)
    {
        delete httpPostEntrance;
        httpPostEntrance = NULL;
    }

    if (tcp_shunt)
    {
        delete tcp_shunt;
        tcp_shunt = NULL;
    }

    if (analyse_domain)
    {
        delete analyse_domain;
        analyse_domain = NULL;
    }

    if (pktParser)
    {
        delete pktParser;
        pktParser = NULL;
    }

    if (g_db_conn)
    {
        delete g_db_conn;
        g_db_conn = NULL;
    }

    //msg_queue_cleanup();
    useragent_cleanup();

    return 0;
}

extern "C" int analyzer_main(const char *packet, const struct pcap_pkthdr_n *pkt_hdr)
{
    /*analyse packet*/
    if (NULL == pktParser->GetPktInfo(packet, pkt_hdr))
        return -1;

    /*analyse HTTP POST*/
    if (g_packetinfo.pktType == TCP)
    {
        int iPostFlag = 0;
        iPostFlag = httpPostEntrance->isPostData(&g_packetinfo);
        if (iPostFlag == HTTP_POST_FIRST_PACKET || iPostFlag == HTTP_POST_PACKET)
        {
            char chMac[18] = {0};
            int iObjectId = 0;
            if (iPostFlag == HTTP_POST_FIRST_PACKET)
            {
                unsigned char* chpMac = g_packetinfo.srcMac;
                sprintf(chMac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x", chpMac[0],
                chpMac[1], chpMac[2], chpMac[3], chpMac[4], chpMac[5]);

                struct in_addr addr;
                addr.s_addr = g_packetinfo.srcIpv4;
                iObjectId = get_clue_id(chMac, inet_ntoa(addr));
            }

            httpPostEntrance->pushData(&g_packetinfo, iPostFlag, iObjectId);
        }
    }

    if (g_packetinfo.pktType == TCP)
    {
        //if(!analyse_app_statistics(&g_packetinfo))
        //    return 0;

        if (!analyse_imei(&g_packetinfo))
            return 0;

        if (!analyse_filemd5(&g_packetinfo))
            return 0;
    }
    
    /*analyse IM*/
    if (g_packetinfo.pktType == TCP || g_packetinfo.pktType == UDP)
    {
        if (IsIm(&g_packetinfo))
        {
            return 0;
        }

        if ((g_packetinfo.pktType == TCP || g_packetinfo.destPort == 53) && IsTools(&g_packetinfo))
        {
            return 0;
        }
		
        if (IsWebIM(&g_packetinfo))
        {
            return 0;
        }
    }

#if 0  // only be used for DNS-LZ or WIFI-SYSTEM
    if(g_packetinfo.pktType == UDP && g_packetinfo.destPort==53)
    {
       analyse_domain->IsDomain(&g_packetinfo);
       return 0;
    }
#endif
	
    /*analyse webmail, smtp, ftp*/
    if (g_packetinfo.pktType == TCP)
    {
        if (research(&g_packetinfo))
            return 0;

        if (analyse_webmail(&g_packetinfo) == 1)
        {
            return 0;
        }

        if (analyse_wb(&g_packetinfo) >= 0)
        {
            return 0;
        }

        if (true == smtp->analyse_smtp(&g_packetinfo))
            return 0;
        
        if (true == telnet->analyse_telnet(&g_packetinfo))
            return 0;

        if (rmc->push(&g_packetinfo))
            return 0;

        if (ftp->IsFTP(&g_packetinfo))
            return 0;

        if (-1 != tcp_shunt->data_shunt_main(&g_packetinfo))
            return 0;
            
        httpget->analyse_get_pkt(&g_packetinfo);
    }

    if (g_packetinfo.pktType == ETH)
    {
        parse_pppoe->analyse_pppoe(&g_packetinfo);
    }

    /*analyse vpn*/
    if (g_packetinfo.pktType == UDP || g_packetinfo.pktType == GRE)
	    parse_vpn(&g_packetinfo);

    return 0;
}

extern "C" int analyzer_http_get(nic_url_record_t *url_data, unsigned int cap_time)
{
    /*write http data to shared memory, by zhangzm*/
    HTTP_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));

    sprintf(tmp_data.p_data.clientMac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x", url_data->smac[2], url_data->smac[3],
            url_data->smac[4], url_data->smac[5], url_data->smac[6], url_data->smac[7]);
	
    //printf("dst MAC-%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", url_data->dmac[2], url_data->dmac[3], url_data->dmac[4],
    //		url_data->dmac[5],url_data->dmac[6],url_data->dmac[7]);

    if (url_data->ip_ver == 4)
    { 			
        strcpy(tmp_data.p_data.clientIp, inet_ntoa(url_data->src_ip.v4));
        strcpy(tmp_data.p_data.serverIp, inet_ntoa(url_data->dst_ip.v4));
    }

    sprintf(tmp_data.p_data.clientPort, "%d", ntohs(url_data->sport));
    sprintf(tmp_data.p_data.serverPort, "%d", ntohs(url_data->dport));

    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);
    tmp_data.p_data.readed = 0;
    tmp_data.p_data.captureTime = cap_time;

    int url_len = ntohs(url_data->url_len);
    if (url_len > 2047)
        url_len = 2047;

    strcpy(tmp_data.environment, "");
    strncpy(tmp_data.url, url_data->url, url_len);
    strcpy(tmp_data.title, "");

    tmp_data.p_data.proType = 101;
    tmp_data.p_data.deleted = 0;
    msg_queue_send_data(HTTP, (void *)&tmp_data, sizeof(tmp_data));

    return 0;
}

extern "C" int record_flux_info(struct flux_statistic_t *flux_info)
{
    /*write flux statistic data to shared memory, by zhangzm*/
#if 0

    FLUX_STATISTIC_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));
    
    tmp_data.rxq = flux_info->rxq;
    tmp_data.packets = flux_info->packets;
    tmp_data.octets = flux_info->octets;
    tmp_data.dropped_packets = flux_info->dropped_packets;
    tmp_data.dropped_octets = flux_info->dropped_octets;
    tmp_data.total_packets = flux_info->total_packets;
    tmp_data.total_octets = flux_info->total_octets;
    strncpy(tmp_data.inc_octets, flux_info->inc_octets, 16);
    strncpy(tmp_data.inc_rate, flux_info->inc_rate, 16);
#endif
    msg_queue_send_data(FLUX_STATISTIC, (void *)flux_info, sizeof(struct flux_statistic_t));

    return 0;
}

#if 0
//print_program_info - 打印程序信息
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
#endif

// single processing function 
void sigproc( int sig )
{
    LOG_DEBUG("Analyzer is exited!\n");
    exit(0);
}

#ifdef CHECK
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
#endif

//END

