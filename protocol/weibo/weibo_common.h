#ifndef _COMMON_H_
#define _COMMON_H_

//#ifdef __cplusplus
//extern "C" {
//#endif

#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
//#include <linux/ip.h>
//#include <linux/udp.h>
//#include <linux/tcp.h>
#include <pcap.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <zlib.h>
#include <dirent.h>
#include <assert.h>
#include <iconv.h>
#include <regex.h>
#include <pcre.h>

#include "../PacketParser.h"
//#include "../PublicDb.h"
#include "Analyzer_log.h"

#define BUFSIZE 2048
#define MAX_UN_LEN 60 
#define MAX_PW_LEN 40

#define MAX_ID_LEN 4096
#define MAX_BOUN_LEN 200
#define MAX_TIME_LEN 64
#define	MAX_AGENT_LEN 1024
#define MAX_HTTP_HEAD_LEN 5000
#define MAX_ATTA_PATH_LEN 2600
#define DATE_LEN 10
#define TIME_LEN 8
#define MAC_LEN 6
#define MAX_MAC_STR_LEN 17
#define SUBSLEN 10 
#define EBUFLEN 128
#define BUFLEN 1024
#define MTU 2000
#define DEFAULT_OK_LEN 100 * 1024
#define MAX_CLUE_CONTENT_LEN 1024
#define MAX_LENGTH 256
#define MAX_COOKIE_LEN 4096
#ifndef OUT_PUT
#define OUT_PUT (printf("__%s__%s__%d__\n",__FILE__,__FUNCTION__,__LINE__))
#endif

/*------------------regcompile Function----------------*/
regmatch_t *regcompile(char *src,char *pattern);

typedef struct _reg_rtn_struct {
	int rtn;
	int pstart;
	int pend;
} reg_rtn_struct;

reg_rtn_struct wb_cns_reg(const char * src, const char * pattern);
int wb_cns_str_ereplace(char * * src, const char * pattern, const char * newsubstr);

/*------------------string Function----------------*/
char *strnstr(char * str, char * substr, size_t n);
char * wb_strstr_2(char * s, char * sub);// 不分大小写的查找
//memnfind 和kmpnfind均严格按照长度来，可以匹配空字符,curlen当前查找的偏移量，不需要时默认为NULL
char *memnfind(char * src, size_t srcLen, char * pat, size_t patLen, int * curlen);
char *wb_arrcpy(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN);
char *wb_ptrcpy(char **pptr, char *src, char *startstr, char *endstr, int addlen);
char *wb_arrcpy_2(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN);
char *wb_ptrcpy_2(char **pptr, char *src, char *startstr, char *endstr, int addlen);

/*------------------code Function------------------*/
int wb_ulong_to_ipstr(unsigned int sip, char dip[16]);
void wb_clear_u(char *str, char ctag);
size_t wb_url_decode(const char *src,char *dest);
size_t url_encode(const char *src, char *dest);
    /*处理:
    %25u4E2D%25u6587%253Cbr%253E%2521%40
    */
char *wb_deal_point(char *src, int len);
char *wb_clear_html_tag(char *source);
char *wb_conv_to_xml_symbol(char *source);
void wb_makeStr(char * str);
char* base64_encode(const char* data, int data_len); 
char *base64_decode(const char* data, int data_len); 

/*---------------http Function----------------*/
int inflate_read_2(char * source, int len, char * * dest, int * dest_size, int gzip, int windowBits);
int decompress_2(char * * pbody, int * pbodyLen);

int write_file(char *filename, char *data, int len);
int wb_get_time(char *data, char *dest);


//#ifdef __cplusplus
//}
//#endif
#endif

