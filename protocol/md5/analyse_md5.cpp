
#include <iostream>
#include <boost/regex.hpp>
#include <arpa/inet.h>

#include "analyse_md5.h"
#include "http_md5.h"
#include "md5_action.h"
#include "db_data.h"
#include "clue_c.h"
#include "Analyzer_log.h"

std::map<std::string, Host_md5> md5_fun;
std::map<uint64_t, Http_md5*> md5_act;

Host_md5node md5_init_node[] = {
{"hn02.upload.cloud.189.cn",                      {1, tianyiyunpan_upload}},
{"cloud189-nj.oos-js.ctyunapi.cn",                {2, tianyiyunpan_download}},
{"wp.163.com",                                    {3, wangyiyun}},
{"c.v.qq.com",                                    {4, tencent_video_upload}},
};

/**************************************************************************************
Function Name:      makeHashkey
Input Parameters:   packet, reverse
    packet          ���ݰ����׵�ַ
    reverse         �ж��Ƿ��ǻ�Ӧ��
Output Parameters:  void
Return Code:        �������hashֵ
Description:        ������Ԫ�����hashֵ
***************************************************************************************/
inline uint64_t makeHashkey(PacketInfo *pkt, bool reverse)
{ 
    return reverse ? (((uint64_t)(pkt->srcIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->destPort << 16 | (uint32_t)pkt->srcPort)):\
        (((uint64_t)(pkt->destIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->srcPort << 16 | (uint32_t)pkt->destPort)); 
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   packet, data
Output Parameters:  void
Return Code:        void
Description:        md5ֵ���
***************************************************************************************/
static void store_db(struct PacketInfo* packet, char* data, unsigned int datalen)
{
    if(!packet || !data)
        return;
        
    struct in_addr addr;
    MD5_T tmp_data;

    memset(&tmp_data, 0, sizeof(tmp_data));
    tmp_data.p_data.readed = 0;
    addr.s_addr = packet->srcIpv4;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x\0", packet->srcMac[0]&0xff, packet->srcMac[1]&0xff, 
            packet->srcMac[2]&0xff, packet->srcMac[3]&0xff, packet->srcMac[4]&0xff, packet->srcMac[5]&0xff);
    
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientPort, "%d", packet->srcPort);
    addr.s_addr = packet->destIpv4;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", packet->destPort);
    tmp_data.p_data.captureTime = packet->pkt->ts.tv_sec;

    strncpy(tmp_data.md5_value, data, datalen);
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = WEIXIN_MD5;
    
    msg_queue_send_data(FILEMD5, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:          md5_fun_init
Input Parameters:       void
Output Parameters:      void
Return Code:            void
Description:            ��ʼ��map md5_fun�Ľڵ�
*************************************************************************************/
void md5_fun_init()
{
    for(int i = 0; i <sizeof(md5_init_node) / sizeof(Host_md5node); i++)
    {
        md5_fun.insert(pair<std::string, Host_md5>(md5_init_node[i].host, {md5_init_node[i].node.num, md5_init_node[i].node.function}));
    }
}

/**************************************************************************************
Function Name:          lookup_hosttype
Input Parameters:       data,len
    data:               ���������
    type:               �������ݵĳ���
Output Parameters:      void
Return Code:            -1:û�в��ҳ���Ӧ�Ľڵ�,0:û���ҵ�host��,>0����host�ڵ�ɹ�
Description:            ���ҽڵ�ɹ���ƥ��app��Ϊ�ɹ�
*************************************************************************************/
int lookup_hosttype(char* data, unsigned short len)
{
    if(!data || len == 0)
        return -1;
    
    char* p1 = NULL, *p2 = NULL;
    std::string hostname = "";
    int ret = -1;
    
    p1 = strcasestr(data, "Host:");
    if(!p1)
        return 0;

    p1 += strlen("Host: ");
    p2 = strstr(p1, "\r\n");
    if (!p2)
        return -1;
    
    hostname.assign(p1, p2 - p1);
    std::map<std::string, Host_md5>::iterator it = md5_fun.find(hostname);
    if(it != md5_fun.end() && !it->second.function(data, len))
    {
        ret = it->second.num;
    }

    return ret;
}

/**************************************************************************************
Function Name:          create_md5node
Input Parameters:       key,type
    key:                hashֵ
    type:               �ĸ�md5�ı��
Output Parameters:      void
Return Code:            -1:����ڵ�ʧ��,0:����ڵ�ɹ�
Description:            ��MD5������map�ڵ�
**************************************************************************************/
int lookup_md5node(uint64_t key)
{
	std::map<uint64_t, Http_md5*>::iterator it = md5_act.find(key);
	if(it == md5_act.end())
		return -1;
	else
		return 0;
		
}

/**************************************************************************************
Function Name:          create_md5node
Input Parameters:       key,type
    key:                hashֵ
    type:               �ĸ�md5�ı��
Output Parameters:      void
Return Code:            -1:����ڵ�ʧ��,0:����ڵ�ɹ�
Description:            ��MD5������map�ڵ�
**************************************************************************************/
int create_md5node(uint64_t key, int type)
{
    if(!lookup_md5node(key))
    {
        printf("md5 key have exist\n");
	    return -1;
    }

    Http_md5* node = new Http_md5(type);
    md5_act.insert(pair<uint64_t, Http_md5*>(key, node));
    return 0;
    
}

/**************************************************************************************
Function Name:          do_weixin
Input Parameters:       data,len,md5_value
    data:               �������ݵ��׵�ַ
    len:                �������ݵĳ���
    md5_value:          ����md5ֵ�ռ���׵�ַ
Output Parameters:      -1,0
Return Code:            0:����md5ֵ�ɹ�,-1:����md5ֵʧ��
Description:            ����pc��΢����������ļ���md5ֵ
**************************************************************************************/
static int do_weixin(struct PacketInfo* packet)
{
    if(!packet)
        return -1;
        
    boost::regex reg("filemd5\\W{4}\\w{32}");
    boost::cmatch mat;
    char* data = packet->body;
    char* p = NULL;
    unsigned short len = packet->bodyLen;
    
    if (boost::regex_search((const char*)data, (const char*)data + len, mat, reg))
    {
        p = (char*)mat.str(0).c_str() + 11;
        store_db(packet, p, 32); //md5��ֵΪ32���ֽ�
        
        return 0;
    }

    return -1;
}

/**************************************************************************************
Function Name:          do_http_md5
Input Parameters:       packet
    packet:             ���ݰ����׵�ַ
Output Parameters:      -1,0
Return Code:            0:����md5ֵ�ɹ�,-1:����md5ֵʧ��
Description:            ��������httpЭ���md5ֵ
**************************************************************************************/
int do_http_md5(struct PacketInfo* packet)
{
    uint64_t hashKey = 0;
    int node_ret = -2;
    int type = 0;
    bool is_from_server = (packet->srcPort == 80)?true:false;
    hashKey = makeHashkey(packet, is_from_server);
    
    type = lookup_hosttype(packet->body, packet->bodyLen);
    if(type > 0)
    {
        create_md5node(hashKey, type);
    }
    else if(type < 0)
    {
        return -1;
    }
            
    std::map<uint64_t, Http_md5*>::iterator it = md5_act.find(hashKey);
    if(it != md5_act.end())
    {
        node_ret = it->second->deal_process(packet, is_from_server);
        if(node_ret == -1 || node_ret == 1)
        {
            delete it->second;
            md5_act.erase(it->first);
        }
    }
    else
    {
        return -1;
    }

    return 0;
}

/**************************************************************************************
Function Name:          analyse_filemd5
Input Parameters:       packet
    packet:             ���ݰ��ṹ��ĵ�ַ
Output Parameters:      void
Return Code:            -1:������Ҫ��������ݰ�,0:�������ݰ��ɹ�
Description:            ����΢����������ļ���md5ֵ
**************************************************************************************/
int analyse_filemd5(struct PacketInfo* packet)
{
    int ret = -1;
    
    if(packet->destPort == 443)
    {
        ret = do_weixin(packet);
        
    }
    else if(packet->srcPort == 80 || packet->destPort == 80)
    {
        ret = do_http_md5(packet);
    }

    return ret;
}
