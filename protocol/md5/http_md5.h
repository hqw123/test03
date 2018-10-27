#ifndef  HTTP_MD5
#define  HTTP_MD5

enum
{
    WEIXIN_MD5 = 2801,
    TIANYI_NETWORK,
    WANGYI_YUN,
    TENCENT_VIDEO,
};

#include <iostream>
#include <zlib.h>
typedef struct packet_info
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    char src_mac[20];
    unsigned int capture_time;
    
    char *header;
    int  headerLen;
    char *body;
    unsigned int bodyLen;
    unsigned int bodyTotal;
    unsigned int status;
}packet_info_t;

class Http_md5
{
private:
    struct packet_info m_request_packet;
    struct packet_info m_response_packet;
    std::string m_md5value;
    int m_type;
    int rebuilt_packet(struct packet_info *entry, char* data, unsigned int dataLen);
    int set_packet_base_info(struct packet_info *pinfo, struct PacketInfo *pktinfo);
    int do_md5(bool is_from_server);
    int do_tianyiwangpanupload_md5(bool is_from_server);
    int do_tianyiwanpandownload_md5(bool is_from_server);
    int do_wangyiyun_md5(bool is_from_server);
    int do_tencent_video_upload_md5(bool is_from_server);
    void release_node();
    void store_db(int type);
    int decomp_gzip(char *src, unsigned int len, char **dest);
public:
    Http_md5(int type);
    ~Http_md5();
    int deal_process(struct PacketInfo* packet, bool is_from_server);
};

#endif