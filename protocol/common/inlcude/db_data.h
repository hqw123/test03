#ifndef _DB_DATA_H
#define _DB_DATA_H

#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

#define SHM_KEY   1234
#define MSG_KEY   12345

#define BUFF_SIZE 4096

typedef enum db_data_type
{
    HTTP = 0x0001,
    WEBACCOUNT,
    WEBMAIL,
    EMAIL,
    IMINFO,
    RESEARCH_HOST,
    FILETRANSLATE,
    OVERWALL,
    NETPROXY,
    PERSONAL_INFO,
    APP_BEHAVIOR,
    FORUM,
    SOCIAL_NETWORK,
    BLOG,
    WEIBO,
    REMOTE_CONTROL,
    P2P_INFO,
    FLUX_STATISTIC,
    ONLINESHOP,
	COMMON_UPDATE,
    AIRLINE,
    EXPRESSAGE,
    HOTEL,
    SEARCH_ENGINE,
    APPUSED,
    APPLOCATION,
    CELLPHONE_IMEI,
    FILEMD5,
    MAX_TYPE
}DB_DATA_TYPE;

typedef struct msg_t
{
    unsigned short msg_type;
    char data[BUFF_SIZE];
}MSG_T;

typedef struct db_data_t
{
    unsigned short type;
    void *data;
}__attribute__ ((__packed__)) DB_DATA_T;

typedef struct pub_data_t
{
    unsigned int clueid;
    int readed;
    char clientIp[16];
    char clientMac[18];
    char clientPort[6];
    char serverIp[16];
    char serverPort[6];
    unsigned int captureTime;
    int proType;
    int deleted;
}PUB_DATA_T;

typedef struct http_t
{
    PUB_DATA_T p_data;
    char environment[512];
    char url[2048];
    char title[512];
	char file_path[260];
}HTTP_T;

typedef struct webaccount_t
{
    PUB_DATA_T p_data;
    char url[2048];
    char username[64];
    char password[64];
}WEBACCOUNT_T;

typedef struct webmail_t
{
    PUB_DATA_T p_data;
    int optype;
    char username[64];
    char password[64];
    unsigned int sendTime;
    char sendAddr[260];
    char recvAddr[260];
    char ccAddr[260];
    char bccAddr[260];
    char subject[260];
    char datafile[260];
    char attachment[260];
    int affixflag;
    char mid[1024];
}WEBMAIL_T;

typedef struct email_t
{
    PUB_DATA_T p_data;
    char username[64];
    char password[64];
    unsigned int sendTime;
    char sendAddr[260];
    char recvAddr[260];
    char ccAddr[260];
    char bccAddr[260];
    char subject[260];
    char datafile[260];
}EMAIL_T;

typedef struct iminfo_t
{
    PUB_DATA_T p_data;
    int optype;
    char content[500];
    char sendNum[200];
    char recvNum[200];
}IMINFO_T;

typedef struct research_host_t
{
    PUB_DATA_T p_data;
    char osinfo[2000];
}RESEARCH_HOST_T;

typedef struct filetranslate_t
{
    PUB_DATA_T p_data;
    char username[50];
    char password[50];
    char filename[512];
    int optype;
    int filesize;
}FILETRANSLATE_T;

typedef struct overwall_t
{
    PUB_DATA_T p_data;
}OVERWALL_T;

typedef struct netproxy_t
{
    PUB_DATA_T p_data;
    char username[50];
    char proxy_url[256];
    char real_url[256];
}NETPROXY_T;

typedef struct personal_info_t
{
    PUB_DATA_T p_data;
    char name[256];
    char phone[64];
    char address[512];
    char correlative[512];
}PERSONAL_INFO_T;

//app_behavior, remote_control and p2p_info use the same structure
typedef struct app_behavior_t
{
    PUB_DATA_T p_data;
    int optype;
}APP_BEHAVIOR_T;

typedef struct forum_t
{
    PUB_DATA_T p_data;
    char username[50];
    char title[200];
    char content_path[256];
}FORUM_T;

typedef struct social_network_t
{
    PUB_DATA_T p_data;
    char username[50];
    char userid[20];
    char articleid[20];
    char title[200];
    char content_path[256];
}SOCIAL_NETWORK_T;

typedef struct blog_t
{
    PUB_DATA_T p_data;
    char username[50];
    char userid[20];
    char articleid[20];
    char title[200];
    char content_path[256];
}BLOG_T;

typedef struct weibo_t
{
    PUB_DATA_T p_data;
    char username[64];
    char password[64];
    char nickname[64];
    char peeraccount[64];
    char content[2400];
    char comment[1024];
    char datafile[256];
    int  optype;
}WEIBO_T;

typedef struct airline_t
{
    PUB_DATA_T p_data;
    char origin_city[40];
    char dest_city[40];
    char origin_airport[40];
    char dest_airport[40];
    char begin_time[20];
    char end_time[20];
    char flightNO[20];
    char passengerName[20];
    char passengerCertNO[30];
    char contactName[20];
    char contactMobilephone[20];
    char contactTelephone[20];
    char contactMail[40];
    char orderID[40];
    unsigned int order_time;
}AIRLINE_T;

typedef struct flux_statistic_t
{
    unsigned int date;
    unsigned int rxq; //receive queue
    char packets[32];
    char octets[32];
    char dropped_packets[32];
    char dropped_octets[32];
    char total_packets[32];
    char total_octets[32];
    char inc_octets[32];
    char inc_rate[32];
}FLUX_STATISTIC_T;

typedef struct onlineshop_t
{
    PUB_DATA_T p_data;
    char order_number[30];
    char telephone_number[20];
    char shopping_account[128];
    char shopper[128];
    char shop_addr[1024];
    char sign_id[40];
}ONLINESHOP_T;

typedef struct expressage_t
{
    PUB_DATA_T p_data;
    char send_number[20];
    char recv_number[20];
    char send_name[50];
    char recv_name[50];
    char send_addr[500];
    char recv_addr[500];
}EXPRESSAGE_T;

typedef struct hotel_t
{
    PUB_DATA_T p_data;
    char name[30];
    char number[20];
    char email[40];
    char hotel_addr[500];
    char hotel_name[100];
    long intime;
    long outtime;
}HOTEL_T;

typedef struct search_engine_t
{
    PUB_DATA_T p_data;
    char content[1024];
}SEARCH_ENGINE_T;

typedef struct common_update_t
{
    unsigned int clueid;
    char update_sql[2048];
}COMMON_UPDATE_T;

typedef struct app_used_t
{
    PUB_DATA_T p_data;
    unsigned short pc_mb;
}APPUSED_T;

typedef struct app_location_t
{
    PUB_DATA_T p_data;
    char lon[20];
    char lat[20];
}APPLOCATION_T;

typedef struct imei_t
{
    PUB_DATA_T p_data;
    char imei[16];
}IMEI_T;

typedef struct md5_t
{
    PUB_DATA_T p_data;
    char md5_value[50];
}MD5_T;

/** IP Addr Definition, applied for both v4 and v6 */
typedef union 
{    
	struct in_addr  v4;
	struct in6_addr v6;
} __attribute__ ((__packed__)) nic_ip_addr_t;

typedef struct _nic_url_record 
{   
	uint8_t        smac[8]; /**< Source MAC(the lower 6 bytes). */    
	uint8_t        dmac[8]; /**< Destination MAC(the lower 6 bytes). */    
	nic_ip_addr_t  src_ip;  /**< Source IP address. */    
	nic_ip_addr_t  dst_ip;  /**< Destination IP address. */    
	uint16_t       sport;   /**< Source TCP port. */    
	uint16_t       dport;   /**< Destination TCP port. */    
	uint8_t        ip_ver;  /**< 4 for IPv4, 6 for IPv6, others are illegle. */    
	uint8_t        rsv0;    /**< Reserved */    
	uint16_t       url_len; /**< Total URL length. */    
	char           url[0];
} __attribute__ ((__packed__)) nic_url_record_t;

/*db_data*/
int share_memory_init(int num);
void share_memory_cleanup(void);
int db_write_data(DB_DATA_TYPE type, void *data, size_t len);

/*msg_queue*/
int msg_queue_init(int num);
void msg_queue_cleanup(void);
int msg_queue_recv_data(struct msg_t *data);
int msg_queue_send_data(DB_DATA_TYPE type, void *data, size_t len);

#endif  /*_DB_DATA_H*/


