
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
    packet          数据包的首地址
    reverse         判断是否是回应包
Output Parameters:  void
Return Code:        计算出的hash值
Description:        根据四元组计算hash值
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
Description:        md5值入库
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
Description:            初始化map md5_fun的节点
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
    data:               传入的数据
    type:               传入数据的长度
Output Parameters:      void
Return Code:            -1:没有查找出对应的节点,0:没有找到host域,>0查找host节点成功
Description:            查找节点成功且匹配app行为成功
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
    key:                hash值
    type:               哪个md5的编号
Output Parameters:      void
Return Code:            -1:创造节点失败,0:创造节点成功
Description:            给MD5对象创造map节点
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
    key:                hash值
    type:               哪个md5的编号
Output Parameters:      void
Return Code:            -1:创造节点失败,0:创造节点成功
Description:            给MD5对象创造map节点
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
    data:               传入数据的首地址
    len:                传入数据的长度
    md5_value:          保存md5值空间的首地址
Output Parameters:      -1,0
Return Code:            0:解析md5值成功,-1:解析md5值失败
Description:            解析pc版微信软件传输文件的md5值
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
        store_db(packet, p, 32); //md5的值为32个字节
        
        return 0;
    }

    return -1;
}

/**************************************************************************************
Function Name:          do_http_md5
Input Parameters:       packet
    packet:             数据包的首地址
Output Parameters:      -1,0
Return Code:            0:解析md5值成功,-1:解析md5值失败
Description:            解析基于http协议的md5值
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
    packet:             数据包结构体的地址
Output Parameters:      void
Return Code:            -1:不是需要处理的数据包,0:处理数据包成功
Description:            解析微信软件传输文件的md5值
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
