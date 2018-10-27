#ifndef HTTP_GET
#define HTTP_GET

#include <stdio.h>
#include <stdlib.h>
#include <boost/regex.hpp>
#include <values.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iconv.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pcre.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <iostream>
#include <fcntl.h>
#include <fstream>
#include <string.h>
#include <map>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <algorithm>
#include <zlib.h>

#include "PacketParser.h"
//#include "comm.h"
//#include "global.h"
//#include "ProtocolID.h"
#include "clue_c.h"
#include "Public.h"

//#include "./webim/Occi.h"

#ifdef VPDNLZ
#define IS_GET_MOVE 0
#else
#define IS_GET_MOVE 1
#endif

#define URL_LEN 2048
#define MAX_PATH_LEN 1024
#define MAX_HOST_LEN 256    // host�������󳤶�
#define MAX_TIME_LEN 128
#define OVECCOUNT 12
#define EBUFLEN 128
#define FILEPATH_MAXSIZE 256
#define TITLE_MAXSIZE 1024
#define BODY_MAXSIZE 1600
#define PATTERN_GET "(GET)"
#define PATTERN_MESG "(message=)|(comment=)|(content=)"
#define PATTERN_NEWLINE "(\r\n\r\n)"
#define TK_HEAD 100
#define PATTERN_POST_URL "https?://([0-9a-zA-Z]+\.)+[0-9a-zA-Z]+(/[0-9a-zA-Z ./?%+&=-]*)?"

#define PATTERN_LEN "(Content-Length:)"
#define PATTERN_TYPE "(Content-Type:)"
#define PATTERN_OFFSET "(Referer:)"
#define PATTERN_HOST_OFFSET "(Host:)"
#define URL_HASH_POS 4096
#define MAX_LOST_POS 1024
#define URL_POS 30
#define PATTERN_URL "https?://.*$"
#define PATTERN_GET_HEAD "(GET).*(HTTP/1.)"
#define PATTERN_OK_HEAD "HTTP/1.\d 200 OK"

//#define PATTERN_FILTER //"(\\.jpg)|(\\.css)|(\\.gif)|(\\.ico)|(\\.swf)|(\\.png)|(\\.xml)|(\\.dll)|(\\.wav)|(\\.rar)|(\\.exe)|(\\.flv)|(z\\.alimama\\.com)"

#define HTML_DATA_PATH "/home/spyData/moduleData/httpGet/extCtrl/"
#define HTML_SEPCTRL_PATH "/home/spyData/moduleData/httpGet/sepCtrl/"

#define FILT "\\.jpg\\??$|\\.i(c|s)o$|\\.swf$|\\.png$|\\.(d|k)ll$|\\.wa(v|t)$|\\.rar$|\\.ex(e|b)$|\\.fl(a|v|g)?$|\\.cab$|\\.mp(3|4)$|\\.wm(a)?$|\\.crl$|\\.tsd$|\\.da(t)?$|\\.doc(x)?$|\\.(r|p|t)pt?$|\\.xls$|\\.txt$|\\.chm$|\\.jar$|\\.umd$|\\.ads$|\\.ver$|\\.nup$|\\.img$|\\.gif\\??$|\\.zip$|\\.xml$|\\.in(i|f|c)$|\\.p(s|d)f$|download|\\.jpeg$|\\.lrc$|\\.kdc$|\\.kvp$|(z\\.alimama\\.com)|\\.gzip$|\\.bmp$|\\.ani$|(suggestion\\.baidu\\.com)|\\.stm|logo$|\\.tr(t)?$|\\.c(u|d)r$|\\.mft$|\\.kfb$|((showxml|wpa)\\.qq\\.com)|\\.bin$|\\.rm(v)?$|\\.vpu$|\\.dtd$|\\.id$|\\.rmvb$|\\.rnd$|\\.ai$|\\.ba(t|k)$|\\.dbf$|\\.eps$|\\.hlv$|\\.lnk$|\\.(m|r)df$|\\.mts$|(mini\\.group\\.qq\\.com)|\\.vdb$|(mt.*?\\.google)|(fetch\\.im\\.baidu\\.com)|getfile|\\.?js\\??[^p]|list=|url=|\\.msp$|\\.xsl$|\\.vbs$|\\.mp(i|r)$|\\.t?gz$|\\.upd$|(api\\.money\\.163\\.com)|nc.(\\w+).*?\\.qq\\.com|\\.((gt)|h)img$|\\.conf$|\\.set$|guanggao|\\.mcs$|\\.gem$|\\.mpg$|\\.idx$|\\.kdz$|\\b[1-9]{1,2}\\b\\.(\\w+).*?\\.com/|\\.do\\?$|mc\\.qzone\\.qq\\.com|\\bg\\b\\.163\\.com|readmail|rwebqq[0-9]{1,2}\\.qq\\.com|\\.ad$|[0-9]{15}$|flash2-http\\.qq\\.com|\\.js$|\\.xmal$|messenger\\.sohu\\.com|action=\\w+.*?time=|\\.mar$|topic\\.csdn\\.net/u/t5/include/ad5\\.asp|static\\d{1,2}\\.photo\\.sina\\.com\\.cn|\\bg\\b\\.\\w+\\.com|\\.wmv$|\\.unp$|\\.vob$|\\.flv$|\\.pac$|qun\\.qq\\.com/cgi/svr/face/getface|safebrowsing-cache\\.google\\.com/safebrowsing/rd|\\.asf$|xy([0-9]?).store.qq.com|topic\\.csdn\\.net/u/t5/include/ad5\\.asp|trace\\.qq\\.com|w\\d\\.im\\.baidu\\.com|tipsimage(\\d)?.*?\\.qq\\.com|\\.avi$|tipsimage\\d\\.qq\\.com|qqshow\\d-item\\.qq\\.com|\\.msu$|im\\.baidu\\.com/nop\\?minibar|(\\bp\\b|hm)\\.\\bl\\b\\.qq\\.com|(\\bg\\b|\\bu\\b)\\.qzone\\.qq\\.com|\\.fcg$|\\.cgi$|&callback=|www\\.google\\.com\\.hk.*?&cp=$|(z|q)s\\d+\\.cnzz\\.com.*?&res=|size=|images$|\\.mkv$"


#define CHUNKRULE "\\r\\n[0-9a-fA-F]{1,4}(\\s+)?\\r\\n"


using namespace std;
const int MAPMAXSIZE = 512;

// 4Ԫ��
struct tuple {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
};

// �ؿ�����
struct hash_url
{
    hash_url()
    {
        memset(url_array, 0x00, sizeof(url_array));
        memset(html_title, 0x00, sizeof(html_title));
        memset(file_path, 0x00, sizeof(file_path));
        memset(host, 0x00, sizeof(host));
        memset(pppoe, 0x00, sizeof(pppoe));
        memset(srcMac, 0x00, sizeof(srcMac));
        memset(&addr, 0x00, sizeof(addr));

        nPos = tv_sec = hash = 0u;
        object_id = 0;
    }
    char url_array[URL_LEN];                // URL
    char html_title[TITLE_MAXSIZE];         // Title
    char file_path[FILEPATH_MAXSIZE];           // ����·�� 
    char host[MAX_HOST_LEN];                // ����
    char pppoe[60];                         // PPPOE
    unsigned char srcMac[32];               // ԴMac
    struct tuple addr;                      // ��Ԫ��
    unsigned int nPos;                      //position of the array
    unsigned int tv_sec;
    unsigned int hash;                      // ������Ԫ�����ɵ�Hash��ֵ
    int object_id;
};

// ��������
struct ext_url
{
    char url_array[URL_LEN];                // URL
    //char host[MAX_HOST_LEN];                // ����
    char pppoe[60];
    unsigned char srcMac[32];
    struct tuple addr;
    unsigned int hash;
    unsigned int tv_sec;
    int dev_id;
    int object_id;  // ����ID
};

/////////////////////////////////////////////////////
//!+ ������ ����ڵ����ʱ�ṹ
//   ������ 
//  
//   ���ߣ� 
//   ���� ���� 2017
/////////////////////////////////////////////////////
typedef struct temp_data
{
    temp_data()
    {
        hash = seq = 0u;
        bodyLen = fin = 0;
        memset(body, 0x00, sizeof(bodyLen));
    }
    unsigned int hash;  // ������Ԫ�����ɵ�Hash��ֵ
    unsigned int seq;
    char body[BODY_MAXSIZE];
    int bodyLen;
    int fin;
} tmpData;

typedef struct temp_pos
{
    temp_pos()
    {
        hash = seq = urlPos = contLen = lDataSize = 0u;
        lContentLen = 0;
        nGzipFlag = 2;
        nChunkedFlag = 2;
        nHCflag = 0;    // 0��ʾhtml��1��ʾcss
        nOkFlag = 1;
        nErrSeqFlag = 1;
        strBuildData = NULL;
        memset(strCd, 0, sizeof(strCd));
        memset(referrer, '\0', sizeof(referrer));
        memset(strCss, '\0', sizeof(strCss));
    }
    unsigned int hash;      // hashkey of the get packet
    unsigned int seq;       // ��һ�����ݰ������к�
    unsigned int urlPos;     // position of the url_stream[urlPos]
    char strCd[64];          // ����
    unsigned int contLen;   // ������ݳ��ȣ���ʾ�Ѿ�������ݳ��� // rebuilded data length
    int lContentLen;        // Content-Length
    int nGzipFlag;           // 1 means "gizp", 2 means "ungzip", 3 means "default"
    int nChunkedFlag;        // 1 means "chunked", 2 means "unchunked"
    char* strBuildData;      // ���ʱ��HTTP�������� //rebuild Content-length data
    string strData;          // ������ʱ�� Content-length������
    unsigned int lDataSize;
    char referrer[1024];    // referrer data
    char strCss[512];       // CSS�ļ���URL
    int nHCflag;            // 0��ʾhtml��1��ʾcss
    int nOkFlag;            // 0 means has ok data, 1 means has no ok data
    int nErrSeqFlag;        // 0 means has error sequence data,1 means has no
} tmpPos;

typedef struct repeat_data
{
    char srcMac[20];
    char strCookie[1024];
} reData;

typedef std::map<int, tmpPos> mapNode;
typedef std::map<int, tmpData> tempMap;
typedef std::map<int, reData> cookMap;

class HttpGet
{
public:
    HttpGet();
    virtual ~HttpGet();

    /**
     * ������: is_http
     * ȫ��: HttpGet::is_http
     * ��������: �ж����ݰ�pPkt�Ƿ�ΪHTTP���ݰ�
     * ���ʿ���: public 
     * @param: struct PacketInfo * pPkt
     * @return: ��HTTP���ݰ�����true�����򷵻�false
     */
    bool is_http(struct PacketInfo* pPkt);
    /**
     * ������: is_get_pkt
     * ȫ��: HttpGet::is_get_pkt
     * ��������: �ж��Ƿ�ΪHTTP��GET����
     * ���ʿ���: public 
     * @param: struct PacketInfo * pPkt
     * @return: �����GET���ݰ�������true�����򷵻�false
     */
    bool is_get_pkt( struct PacketInfo* pPkt );
    /**
     * ������: is_http_ok
     * ȫ��: HttpGet::is_http_ok
     * ��������: �ж����ݰ��Ƿ�Ϊ��HTTP 200 OK�����ݰ�
     * ���ʿ���: public 
     * @param: struct PacketInfo * pPkt
     * @return: void
     */
    void is_http_ok(struct PacketInfo* pPkt);
    /**
     * ������: analyse_get_pkt
     * ȫ��: HttpGet::analyse_get_pkt
     * ��������: ������
     * ���ʿ���: public 
     * @param: struct PacketInfo * pPkt
     * @return: �ɹ�����true��ʧ�ܷ���false
     */
    bool analyse_get_pkt( struct PacketInfo* pPkt );

private:
    /// <Summary>
    /// ��������
    /// </Summary>
    bool get_http_url(struct PacketInfo* pPkt);
    int get_hdr_length(struct PacketInfo* pPkt);
    int get_content_len(struct PacketInfo* pPkt);
    bool is_chunk(struct PacketInfo* pPkt);
    bool get_html_title(char* str, unsigned int lLen, char* strCode, unsigned int lHash);

    // HTTP����ѹ������
    bool is_gzip(struct PacketInfo* pPkt);
    bool is_deflate(struct PacketInfo* pPkt);
    int decomp_gzip(char* src, unsigned int len, char** dest, int flag);

    // ��httpͷ����ȡ��������
    int get_http_code(const char* header, unsigned int length);
    // ��html�л�ȡ��������
    bool get_charset(char* str, unsigned int lLen);

private:
    /// <Summary>
    /// �������
    /// </Summary>
    unsigned int mk_hash_index( struct tuple addr );
    void deal_ok_pkt( struct PacketInfo* pPkt );
    int analyse_rebuild_pkt( struct PacketInfo* pPkt );
    bool is_return_pkt( struct PacketInfo* pPkt );
    void release_node( unsigned int lHash, char* strFilePath );
    int delete_map( unsigned int lHash );
    void erase_hash( unsigned int lHash );
    bool filter_url( const char* url, int len );
    void write2db( int nPos, unsigned int clue_id);
    //void delete_fail_file(unsigned int lHash,char *url);
    int write_txt_file( unsigned int lHash );
    int get_position( char* str, int strLen );
    bool is_css( const char* url, int len );
    bool deal_get_css( unsigned int lHash, char* url, struct PacketInfo* pPkt, int nKey );
    bool is_html_ok( struct PacketInfo* pPkt );
	void regex_init();
#if 0
    void write_ext_xml( unsigned int lHash );
#endif
    int get_chunksize_len( char* str, int strLen );
    void deal_chunk_data( unsigned int lHash );
    int inflate_read( char* source, int len, char** dest );
    void analyse_UserAgent( struct PacketInfo* pPkt );

private:
    char userAgent_[1024];
    mapNode mapNd;          // ��õĻỰ
    tempMap tmpmap[MAX_LOST_POS];               // ���ʱ��map
    cookMap cookieMap;
   
    unsigned int nContentLen;                   // Content-Length��ֵ
    char strTitle[TITLE_MAXSIZE];               // ��ҳ����
    //char *strPktType;                         // the type of the OK packet
    char strCode[64];                           // HTTP���ݱ���
    //char *strDecompBuf;                       // need to decompress data
    char strCharset[64];                        // ��ҳ����
    struct hash_url* url_stream[URL_HASH_POS];  // �ؿ�����
    struct ext_url ext_url_stream;      // ��������
	
    boost::regex* FiltRule;
    boost::regex* ChunkRule;
    boost::regex* expression_useragent;
	boost::regex* expression_host;
	boost::regex* expression_url;
	boost::regex* expression_html1;
	boost::regex* expression_html2;
	boost::regex* expression_html3;
	boost::regex* expression_html_title;
	boost::regex* expression_css;
	boost::regex* expression_css2;
	boost::regex* expression_charset;
	boost::regex* expression_charset2;
	boost::regex* expression_content_length;
	boost::regex* expression_chunk;
	boost::regex* expression_gzip;
	boost::regex* expression_deflate;
};

#endif
