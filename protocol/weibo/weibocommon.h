//#include<netinet/ip.h>
//#include<linux/tcp.h>
//#include<linux/udp.h>
//#include<stdlib.h>

#ifndef WEIBO_H_
#define WEIBO_H_

//#ifdef __cplusplus
//extern "C" {
//#endif

#include "weibo_common.h"
#include <string.h>
#include "ofo_cope.h"

#define FREE(data) do{if (data) {free(data); data=NULL;}}while(0)

#define MAX_FROM_LEN 260
#define MAX_TO_LEN 260
#define MAX_CC_LEN 2048
#define MAX_BCC_LEN 2048
#define MAX_FN_LEN 260
#define MAX_PATH_LEN 260
#define MAX_SUBJ_LEN 1000
#define MAX_PPPOE_LEN 60
//char file_temp_path[MAX_PATH_LEN+1];

enum
{
	STATUS_IDLE = 0,
	FULL_HTTP_HEAD,
	INIT_BODY_CONTENT,
	FULL_BODY_CONTENT
};

typedef enum WbType
{
	Unknow = 0,
    Login = 1,
    Logout = 2,
    Guangbo,
    Zhuanfa,
    Pinglun,
    Sixin,
    File
}WbType;

// Define the presentation of a message node in a message list.
typedef struct WbNode
{
    unsigned  char srcMac[6];
    unsigned  char destMac[6];
    unsigned int srcIpv4;     // 4 bytes
    unsigned int destIpv4;    // 4 bytes
    unsigned short int srcPort;    // 2 bytes
    unsigned short int destPort;   // 2 bytes
    unsigned char client_mac[MAC_LEN + 1];
    char * data;
    int dataLen;
    int dataTotal;
    unsigned short int type;
    unsigned short int urltype;
    // Keep above data sync with PakectInfo struct 26 Bytes
    WbType wbType;
    char username[MAX_UN_LEN + 1];
    char passwd[MAX_PW_LEN + 1];
    char fileName[MAX_PATH_LEN+1]; // IP and port of soure address are used to name a session.
    char save_path[MAX_PATH_LEN + 1]; 
    int fileLen;
    int fileNum;
    char from[MAX_FROM_LEN + 1];
    char to[MAX_TO_LEN + 1];
    char sent_time[MAX_TIME_LEN + 1];

	// user agent string
	char agent[MAX_AGENT_LEN+1];
	// follow type: 1 follow, 2 unfollow
	int  follow;

    char *friends;
    time_t time;
    char Id[MAX_ID_LEN+1];
    char *content;
    char *reason;
    int is_complished;
    int count; 
    char url[256];
    char * header;
	unsigned int headerLen;
	char * body;
	unsigned int bodyLen;
	unsigned int bodyTotal;
	unsigned int head_status;
	unsigned int body_status;    
    struct WbNode *prev;
    struct WbNode *next;
}WbNode;

typedef struct g_weibo_entryList
{
    WbNode * head;
    WbNode * tail;
    int count;
};

WbNode * insert_WbNode(PacketInfo * packetInfo);
WbNode * find_WbNode(PacketInfo * packetInfo, int * is_cons);
void del_WbNode(WbNode * Node);

int wb_init(void);
int wb_type(PacketInfo *packetinfo);

int write_weibo_attach(char path[MAX_PATH_LEN+1], char *type, char name[MAX_PATH_LEN+1], char *data, int len, int up_or_down);
int analyse_file_1(char *data, int dataLen, char save_path[MAX_PATH_LEN+1],char fileName[MAX_PATH_LEN+1], char *type);
int write_wb_sql(WbNode *node);
void free_node(WbNode *node);
int attc_node(WbNode *node, int flag);

int analyse_SinaWb(WbNode *node, PacketInfo *packetinfo, int is_to_s);
int analyse_QQWb(WbNode *node, PacketInfo *packetinfo, int is_to_s);
int analyse_M163Wb(WbNode *node, PacketInfo *packetinfo, int is_to_s);

char *clear_wbcontent_symbol(char *source);
int ofo_func_2(OFOC_t tofo, PIRS_t trset, void * node, PacketInfo * packetInfo, int is_to_s, int(* callback)(void * node, PacketInfo * packetInfo, int is_to_s));
int http_recive(WbNode * entry, char *data, int dataLen);
//extern OFOC_t ofo;
//extern PIRS_t rset;
extern struct g_weibo_entryList g_entryList;

//#ifdef __cplusplus
//}
//#endif

#endif

