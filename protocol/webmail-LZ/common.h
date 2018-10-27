#ifndef COMMEN_H
#define COMMEN_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <sys/mman.h>
#include <iconv.h>
#include <regex.h>
#include <pcre.h>
#include <zlib.h>
#include <dirent.h>
#include <assert.h>
//#include <mysql.h>

#include "Analyzer_log.h"
#include "cJSON.h"
#include "PacketParser.h"
#include "ofo_cope.h"

#define MAX_UN_LEN 64 
#define MAX_PW_LEN 260
#define MAX_FROM_LEN 260
#define MAX_TO_LEN 2048
#define MAX_CC_LEN 2048
#define MAX_BCC_LEN 2048
#define MAX_FN_LEN 260
#define MAX_PATH_LEN 260
#define MAX_SUBJ_LEN 1000
#define MAX_ID_LEN 4096
#define MAX_BOUN_LEN 200
#define MAX_TIME_LEN 64
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
#define MAX_PPPOE_LEN 60

#define OK_DATA_LEN 5000

//#define PACKETS_BUFFER_SIZE 1600*1000
//#define WEBMAIL_BUFFER_SIZE 1600*100
//#define MAIL_DATA_PATH "./webmail_data"
//#define MAIL_TEMP_PATH "./webmail_data/temp"
//#define WEBMAIL_ERR_FD 5 
extern char mail_data_path[];
extern char mail_temp_path[];
extern char attach_down_path[];
extern char mail_password_path[];
//extern FILE *webm_err_fp;

typedef struct tmpfrom {
    unsigned int ip;
    char  from[MAX_UN_LEN + 1];
}Tmpfrom ;
extern Tmpfrom fromarray[];

typedef struct attachment {
	char loc_filename[MAX_FN_LEN + 1];
	char loc_name[MAX_FN_LEN + 1];
	char path_of_sender[MAX_PATH_LEN + 1];  
	struct attachment *next;
} Attachment;

typedef struct mail_info {
	unsigned int source_ip;
	unsigned int dest_ip;
	unsigned short int source_port;
	unsigned short int dest_port;
	unsigned int start_seq;
	unsigned char client_mac[MAC_LEN + 1];
	int mail_type;  //邮件类型
	unsigned int mail_length;  
	int count; 
	int is_complished;  //邮件是否处理完毕
	int is_proce_mail;
	char username[MAX_UN_LEN + 1];
	char passwd[MAX_PW_LEN + 1];
	char *mail_data;  //存放请求服务器的数据包的内容
	char *recive_data;//存放服务器响应的数据包的内容 即OK包的内容
	char cookie_data[MAX_COOKIE_LEN + 1];
	int is_ok_chunked; //是否分块
	char connect_id[MAX_ID_LEN + 1];
	char * mail_id;//用于与附件的连接
	
	unsigned int recive_length;  //真正的的数据长度
	unsigned int ok_length;  //整个OK包的长度
	unsigned int http_seq; //OK 包的开始确认号
	char from[MAX_FROM_LEN + 1];
	char to[MAX_TO_LEN + 1];
	char cc[MAX_CC_LEN + 1]; //抄送
	char bcc[MAX_BCC_LEN + 1];//秘密抄送
	char subject[MAX_SUBJ_LEN + 1];
	char url[256];
	char *content;//邮件内容
	char sent_time[MAX_TIME_LEN + 1];
	int num_of_attach;//该邮件的附件个数
	int mail_num;
	Attachment *attach; //连接附件
	char save_path[MAX_PATH_LEN + 1]; //邮件存放的路径
	char ID_str[MAX_ID_LEN + 1];
	char path_of_here[MAX_PATH_LEN + 1];
	char *attach_name;
	int is_writing;
	unsigned int source_seq;
	unsigned int ack_seq;
	int is_chunked;  //判断是否为chunked包
	int ok_gzip;
	int is_have_contentlength;
	unsigned int attach_len;
	char pppoe[MAX_PPPOE_LEN];
	struct mail_info *prev;
	struct mail_info *next;

	char * header;
	int headerLen;
	char * body;
	unsigned int bodyLen;
	unsigned int bodyTotal;
	unsigned int status;
	unsigned int cap_time;
} Mail_info;

typedef struct attach_info {
	int packet_type;// new
	unsigned int source_ip;
	unsigned int dest_ip;
	unsigned short int source_port; //发送端口号
	unsigned short int dest_port;  //目的端口号
	unsigned int start_seq;  //请求包开始的确认号
	unsigned int http_seq;  //附件OK包开始确认号
	unsigned int ok_start_seq;
	int attach_type; //附件类型
	char ID_str[MAX_ID_LEN + 1];  //附件ID 用于连接对应的邮件
	char *path_of_sender;
	char path_of_here[MAX_PATH_LEN + 1];//附件存放路径
	char attach_name[MAX_PATH_LEN + 1]; // 附件别名
	char attname[MAX_PATH_LEN + 1];  //附件的文件名字
	int ok_gzip;
	int is_ok_chunked;
	char *ok_data;
	unsigned int ok_len; 
	int is_complished;
	int is_writing;  //附件是否写完 初始为0
	int is_get_ok;
	int ok_pause;
	unsigned int recive_length; // OK 包中真正的数据长度
	unsigned int ok_length;  //整个OK包的长度 
	char *recive_data; //存放服务器响应的数据包的内容 即OK包的内容
	struct attach_info *prev;
	struct attach_info *next;

	char * header;
	int headerLen;
	char * body;
	unsigned int bodyLen;
	unsigned int bodyTotal;
	unsigned int status;
	unsigned int cap_time;
} Attach_info;

typedef struct mail_table {
	Mail_info *head;
	int count;
} MailTable;

typedef struct attach_table {
	Attach_info *head;
	Attach_info *tail;
	int count;
} AttachTable;

extern MailTable mail_tab;
extern AttachTable attach_tab;

typedef struct _reg_rtn_struct {
	int rtn;
	int pstart;
	int pend;
} reg_rtn_struct;

time_t convert_time_format(char *data);
int get_time(char *data, char *dest);
int write_xml(Mail_info *mail_info);
int clear_from(char *old_from);
void get_from(char *from,unsigned int sourceip);
int create_dir(char *path, char *mail_str, char *mail_name);
int write_to_okdata(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp);
int decomp_gzip_3(char *src, unsigned int len, char **dest);
int write_attach_down_2(Mail_info *mail_info,unsigned int length, int is_chunk);
int http_recive_mail(Mail_info * entry, char *data, int dataLen);
void equal_convert(char * src,int len,char * dest);
void makeStr(char * str);
int http_recive_attach(Attach_info * entry, char *data, int dataLen);
int write_to_attach_2(Attach_info *attach_info, char *data, unsigned int data_len, unsigned int seq);
int write_chunked_okdata(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp);
int cns_str_ereplace(char **src, const char *pattern, const char *newsubstr);
int insert_array(char *username, unsigned int source_ip);
int get_http_length_2(char *data, int  *is_chunk);
int write_attach_down_1(Mail_info *mail_info,unsigned int length, int is_chunk);
int attac_mail(Mail_info *mail_info, int flag);
void trim_attach2(char *filename, size_t len);
char *memnfind(char *src, size_t srcLen, char *pat, size_t patLen);
char *arrcpy(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN);
char * strstr_2(char * s, char * sub);
char *clear_html_symbol(char *source);
int analyse_recv(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s, int (*callback)(Mail_info *mail_info));
int analyse_downattach(void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(Attach_info *attach_info));
int ofo_func(OFOC_t ofo, PIRS_t rset, void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(void *node, PacketInfo *packetInfo, int is_to_s));
void write_to_file_m(Mail_info *mail_info);
void UpdateAttachNew_m(char * filename, char * name, char * mid);
int get_http_length_1(char *data);
int write_xml_m(Mail_info *mail_info);
int clear_unwanted_chars(char *str, size_t max_len);
int clear_tmp_file();
int get_downattach_name(char *data, char name[MAX_PATH_LEN+1]);
int write_attach(char path[], char name[], char *data, int len, int up_or_down);
void write_data(char *src, int srcLen, char **dest, unsigned int *destLen);

//not common
int get_data_len(char * data);
int clear_tag(char *str);
void get_21cn_from(char *data,char *from);
int reg (char *src, char *pattern, regmatch_t * pm, int n);
void base64Decode (char *input, int in_len, char *out_str);
int inflate_read (char *source, int len, char **dest, int *dest_size, int gzip);
int get_boundary(char *src, char *boundary);
int get_yeah_rcvid(Mail_info *mail_info);
int decompress(char **body, int bodyLen);
int write_mail_recive(Mail_info *mail_info);
int write_mail_body_recive(Mail_info *mail_info);
void write_hanmail_recive_file(Mail_info *mail_info);
char *conv_163_to_utf8(char *src);
char *conv_163_to_utf8(char *src);
int qq_str_convert(char *str, size_t max_len);
int qq_str_convert2(char *str, size_t max_len);
char *qq_conv_to_utf8(char *src);
int get_value(char str[4]);
char chartoint(char x);
int str_163_convert1(char *str, size_t max_len);
int drop_yahoo_tag(char *cc);
void get_21cn_subject(char *mail_data,char *mail_subject);
void sjs(char * data);
char *clear_kh2(char *source);
int str_to_num(char * size);
void writefileeyou(Mail_info *mail_info);
int get_263_boundary(char *src,char *boundary);
void getMailbox(char *str, char *first, char last);
int Get_Attach_Num_sogou();
int write_126_passwd(Mail_info *mail_info);
int write_188_passwd(Mail_info *mail_info);
void write_gmail_psword(Mail_info *mail_info);
char *str_in_node(char **pdest, int dest_len, char *source, const int source_len, const char *pattern1, const char *pattern2, const int len1, const int len2);
void htmldecode_fulll(char *src, char *dest);
int writefilehanmail(Mail_info *mail_info);
char *m139_conv_to_utf8(char *src);
int writefile163_m(Mail_info *mail_info);
int writefile_qq_m(Mail_info *mail_info);
int clear_u(char *str, char ctag);
int code_convert_2(char *from_charset, char *to_charset, char *inbuf, int inlen , char **outbuf, int *outlen);
int analyse_data(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *ptcp ,int is_b_s, 
                                  int (*Mycallbackfun_isend)(char *data, unsigned int datalen, struct tcphdr *tcp,Mail_info *mail_info),
                                  int (*Mycallbackfun_write)(Mail_info *mail_info),
                                  int fun_place);



int write_attach_down(Mail_info *mail_info,unsigned int length, int is_chunk);

int write_attach_down_3(Mail_info *mail_info,unsigned int length, int is_chunk);

Attach_info *find_attach_1(Mail_info *mail_info);

int delete_mail_info(Mail_info *mail_info);

int del_mail_node(Mail_info *temp);

int del_attach_node(Attach_info *temp);

int judge_chunk(char *data);

int get_http_length(char *data);

Attach_info * find_attach(char *ID);

int proce_attach_head(Attach_info *attach_info, char *data, unsigned int data_len, char **file_content);

int decomp_gzip(char *src, unsigned int len, char **dest);

int decomp_gzip_1(char *src, unsigned int len, char **dest);

int decomp_gzip_2(char *src, unsigned int len, char **dest);

void deleteNode(Mail_info **tmp1,Mail_info **tmp);

int code_convert(char *from_charset,char *to_charset,char *inbuf,int inlen ,char *outbuf,int outlen);

int htmldecode_full(char *src, char *dest);

int regcompile_1(char *src,char *pattern,char *matched,int length);

int regcompile_2(char *src,char *pattern,char **matched);

void trim_attach(char *filename, off_t n);

int get_file_name(char *path, char *filename);

int create_dir(char *path, char *mail_str, char *mail_name);

void write_to_file(Mail_info *mail_info);

char *memfind(char *str, char *substr, size_t n);

int delete_attach(Attach_info *attach_info);

char *clear_html_tag(char *source);

char *conv_to_xml_symbol(char *source);

char *conv_xml_symbol(char *source);

int write_to_attach(Attach_info *attach_info, char *data, unsigned int data_len, unsigned int seq);
int write_to_attach_3(Attach_info *attach_info);

int write_to_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp);

int write_xml_password(unsigned int clue_id,Mail_info *mail_info);

Mail_info *find_mail_head(char *connect_id, Mail_info *mail_head);

Mail_info *find_mail_head2(char *connect_id, Mail_info *mail_head, unsigned short type);

void DbgShow(char buf[],char file[]);

void UpdateAttach(char * filename, char * mid);

void UpdateAttachNew(char * filename, char * name, char * mid);

void write_oracle_db_password(int object_id, Mail_info *mail_info);

int write_to_okdata_chunked_gzip(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp);

void store_account_db(Mail_info* node);

int Chunked(Mail_info *mail_info);

void convert_contents(char * cont);

void down_contents(char * cont);

void convert_time_to_string(int time,char *Srctime);

void get_send_time(char *Srctime, char *Sendtime);

char* Base2UTF8_mail(const char* base64, size_t len);

void get_cookie(char *data, char *cookie);

void write_oracle_db_cookieinfo(Mail_info *mail_info);

char* GBK2UTF8_mail(char* gbk, size_t len);

int analyse_sina(void *tmp,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s,int mora);
void analyse_21cn(void *tmp,char *data ,unsigned int datalen,struct tcphdr *tcp , int is_b_s,int mora);
void analyse_sohu(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
int analyse_163(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_hotmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_yahoo(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_tom(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void  analyse_yeah(void *node,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s,int m_or_a);
void analyse_eyou(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int mora);
void analyse_263(void *tmp,char *data, unsigned int datalen,struct tcphdr *tcp, int is_b_s,int mora);
int analyse_qq(PacketInfo * packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void analyse_sogou(PacketInfo *packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
int analyse_126(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_188(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void analyse_gmail(void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
void analyse_mail(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a);
void analyse_aol(PacketInfo * packetInfo, void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a,char *destMAC);
int analyse_hanmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_139(PacketInfo *packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_2980(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_189(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_12306(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_m_163(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_m_qq(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void analyse_m_sohu(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
void analyse_m_sina(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
void analyse_m_189(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
int analyse_m_sina_upload(Attach_info *attach, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s);//lihan add 2017.3.18

//extern 
extern int analyse_163_rcvmail4(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s);
extern void clear_html_tag_2(char *content);
extern int url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen);
void store_webmail_db(Mail_info* node);

#endif
