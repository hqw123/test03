
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "http_md5.h"
#include "db_data.h"
#include "clue_c.h"
#include "Analyzer_log.h"

Http_md5::Http_md5(int type)
{
    m_type = type;
    memset(&m_request_packet, 0, sizeof(packet_info_t));
    memset(&m_response_packet, 0, sizeof(packet_info_t));
}

Http_md5::~Http_md5()
{
	release_node();
}

/*************************************************************************************
Function Name:      release_node
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        释放packet_info_t内部空间
**************************************************************************************/
void Http_md5::release_node()
{
    if (m_request_packet.header)
    {
        free(m_request_packet.header);
        m_request_packet.header = NULL;
    }
    
    if (m_request_packet.body)
    {
        free(m_request_packet.body);
        m_request_packet.body = NULL;
    }
    
    if (m_response_packet.header)
    {
        free(m_response_packet.header);
        m_response_packet.header = NULL;
    }
    
    if (m_response_packet.body)
    {
        free(m_response_packet.body);
        m_response_packet.body = NULL;
    }
}

/*************************************************************************************
Function Name:      rebuilt_packet
Input Parameters:   data,dataLen
    data:           数据包应用层的首地址
    dataLen:        数据包应用层的长度
Output Parameters:  void
Return Code:        -1:组包发生错误,0:数据包没有完全组成,1:数据包全部组完
Description:        将多个数据包组成一个完整的包
**************************************************************************************/
int Http_md5::rebuilt_packet(struct packet_info *entry, char* data, unsigned int dataLen)
{
    if (!(entry->status&0x01))
    {
        char *p = strstr(data, "\r\n\r\n");
        if (p)
        {
            p += 4;
            if (entry->headerLen == 0)
            {
                entry->headerLen = p - data;
                entry->header = (char* )malloc(p - data + 1);
                if(!entry->header) 
                    return -1;
                
                memcpy(entry->header, data, p - data);
                entry->header[entry->headerLen] = 0;
            }
            else
            {
                entry->header = (char *)realloc(entry->header, entry->headerLen + (p - data) + 1);
                if(!entry->header) 
                    return -1;
                
                memcpy(entry->header + entry->headerLen, data, p - data);
                entry->headerLen += p-data;
                entry->header[entry->headerLen] = 0;
            }
            
            entry->status |= 0x01;
            char *p1 = strcasestr(entry->header, "\r\nTransfer-Encoding: chunked");
            if (p1)
            {
                entry->status |= 0x02;
                entry->body = (char *)malloc(1);
                entry->body[0] = 0;
                entry->status |= 0x04;
                char *p2 = strstr(p, "\r\n");
                while (p2)
                {
                    if(p2 + 2 > data + dataLen) 
                        return 0;
                    
                    unsigned int len = 0;
                    char *p3 = NULL;
                    for (p3 = p; p3 < p2; p3++)
                    {
                        if(*p3>='0' && *p3<='9') 
                            len = len*16 + (*p3-'0');
                        else if(*p3>='a' && *p3<='f')
                            len = len*16 + (*p3-'a'+10);
                        else if(*p3>='A' && *p3<='F')
                            len = len*16 + (*p3-'A'+10);
                        else 
                            break;
                    }
                    
                    if (len == 0)
                    {
                        entry->body[entry->bodyLen] = 0;
                        return 1;
                    }
                    
                    p2 += 2;
                    if (p2+len <= data+dataLen)
                    {
                        entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
                        if (!entry->body) 
                            return -1;
                        
                        memcpy(entry->body + entry->bodyLen, p2, len);
                        entry->bodyLen += len;
                        entry->bodyTotal += len;
                        entry->status |= 0x04;
                        p = p2 + len + 2;            // 2 is "0d 0a"
                        p2 = strstr(p, "\r\n");
                        continue;
                    }
                    else
                    {
                        entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
                        if(!entry->body)
                            return -1;
                        
                        unsigned int slen = data + dataLen - p2;
                        memcpy(entry->body + entry->bodyLen, p2, slen);
                        entry->bodyTotal += len;
                        entry->bodyLen += slen;
                        entry->status &= 0xfffffffb;
                        break;
                    }
                }
            }
            else if(p1 = strcasestr(entry->header, "\r\nContent-Length: "))
            {
                p1 += 18;
                char *p3 = strstr(p1,"\r\n");
                char *p4 = NULL;
                unsigned int len = 0;
                while(*p1==' ')
                    p1++;
                
                for (p4 = p1; p4 < p3; p4++)
                {
                    if(*p4>='0' && *p4<='9')
                        len = len*10 + (*p4-'0');
                    else 
                        break;
                }
                
                entry->bodyTotal = len;
                entry->bodyLen = dataLen - (p-data);
                entry->body = (char *)malloc(entry->bodyLen + 1);
                if (!entry->body)
                    return -1;
                
                if (entry->bodyLen > 0)
                    memcpy(entry->body, p, entry->bodyLen);

                if (entry->bodyLen >= entry->bodyTotal)
                {
                    entry->body[entry->bodyLen] = 0;
                    return 1;
                }
            }
            else
            {
                return 1;
            }
        }
        else
        {
            if(entry->headerLen == 0)
            {
                entry->headerLen = dataLen;
                entry->header = (char* )malloc(dataLen + 1);
                if(!entry->header) 
                    return -1;
                
                memcpy(entry->header, data, dataLen);
            }
            else
            {
                entry->header = (char* )realloc(entry->header, entry->headerLen + dataLen + 1);
                memcpy(entry->header + entry->headerLen, data, dataLen);
                entry->headerLen += dataLen;
            }
        }
    }
    else
    {
        if (entry->status&0x02)
        {
            char *p = data;
            if (!(entry->status&0x04))
            {
                if(entry->bodyLen + dataLen < entry->bodyTotal)
                {
                    memcpy(entry->body + entry->bodyLen, data, dataLen);
                    entry->bodyLen += dataLen;
                }
                else
                {
                    int offset = entry->bodyTotal - entry->bodyLen;
                    memcpy(entry->body + entry->bodyLen, data, offset);
                    entry->bodyLen = entry->bodyTotal;
                    p = data + offset + 2;
                    entry->status |= 0x04;
                }
            }
            
            if (entry->status&0x04)
            {
                char *p2 = NULL;
                while(*p=='\r' || *p=='\n') 
                    p++;
                
                p2 = strstr(p, "\r\n");
                while (p2)
                {
                    if ((p2 + 2) > (data + dataLen)) 
                        return 0;
                    
                    unsigned int len = 0;
                    char *p3 = NULL;
                    for(p3 = p; p3 < p2; p3++)
                    {
                        if(*p3>='0' && *p3<='9') 
                            len = len*16 + (*p3 - '0');
                        else if(*p3>='a' && *p3<='f') 
                            len = len*16 + (*p3 - 'a' + 10);
                        else if(*p3>='A' && *p3<='F') 
                            len = len*16 + (*p3 - 'A' + 10);
                        else 
                            break;
                    }
                    
                    if (len == 0)
                    {
                        entry->body[entry->bodyLen] = 0;
                        return 1;
                    }
                    
                    p2 += 2;
                    if ((p2 + len) <= (data + dataLen))
                    {
                        entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
                        if(!entry->body)
                            return -1;
                        
                        memcpy(entry->body+entry->bodyLen, p2, len);
                        entry->bodyLen += len;
                        entry->bodyTotal += len;
                        entry->status |= 0x04;
                        p = p2 + len + 2;
                        p2 = strstr(p, "\r\n");
                        continue;
                    }
                    else
                    {
                        entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
                        if(!entry->body) 
                            return -1;
                        
                        unsigned int slen = data + dataLen - p2;
                        memcpy(entry->body + entry->bodyLen, p2, slen);
                        entry->bodyTotal += len;
                        entry->bodyLen += slen;
                        entry->status &= 0xfffffffb;
                        break;
                    }
                }
            }
        }
        else
        {
            entry->body = (char *)realloc(entry->body, entry->bodyLen + dataLen + 1);
            if (!entry->body)
            {
                return -1;
            }
            
            memcpy(entry->body + entry->bodyLen, data, dataLen);
            entry->bodyLen += dataLen;
            if (entry->bodyLen >= entry->bodyTotal)
            {
                entry->body[entry->bodyLen] = 0;
                return 1;
            }
        }
    }
    
    return 0;
}

/****************************************************************************
Function Name:           set_packet_base_info
Input Parameters:        pktinfo
Output Parameters:       pinfo
Return Code:             -1:fail, 0:success
Description:             set srcMac, destMac, srcIpv4, destIpv4, srcPort, destPort
****************************************************************************/
int Http_md5::set_packet_base_info(struct packet_info *pinfo, struct PacketInfo *pktinfo)
{
    sprintf(pinfo->src_mac, "%02x-%02x-%02x-%02x-%02x-%02x\0", pktinfo->srcMac[0]&0xff, pktinfo->srcMac[1]&0xff, 
            pktinfo->srcMac[2]&0xff, pktinfo->srcMac[3]&0xff, pktinfo->srcMac[4]&0xff, pktinfo->srcMac[5]&0xff);


    pinfo->saddr = pktinfo->srcIpv4;
    pinfo->daddr = pktinfo->destIpv4;

    pinfo->sport = pktinfo->srcPort;
    pinfo->dport = pktinfo->destPort;

    pinfo->capture_time = (unsigned int)pktinfo->pkt->ts.tv_sec;

    return 0;
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        存数据库
***************************************************************************************/
void Http_md5::store_db(int type)
{
    struct in_addr addr;
    MD5_T tmp_data;

    memset(&tmp_data, 0, sizeof(tmp_data));
    tmp_data.p_data.readed = 0;
    addr.s_addr = m_request_packet.saddr;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    strncpy(tmp_data.p_data.clientMac, m_request_packet.src_mac, 18);
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientPort, "%d", m_request_packet.sport);
    addr.s_addr = m_request_packet.daddr;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", m_request_packet.dport);
    tmp_data.p_data.captureTime = m_request_packet.capture_time;
    strcpy(tmp_data.md5_value, m_md5value.c_str());
    tmp_data.p_data.deleted = 0;
    if(type == 1 || type == 2)
        tmp_data.p_data.proType = TIANYI_NETWORK;
    else if(type == 3)
        tmp_data.p_data.proType = WANGYI_YUN;
    else if(type == 4)
        tmp_data.p_data.proType = TENCENT_VIDEO;
    
    msg_queue_send_data(FILEMD5, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:      decomp_gzip
Input Parameters:   src,len,dest
    src:            源数据的地址
    len:            源数据的长度
    dest:           压缩后数据的首地址
Output Parameters:  void
Return Code:        -1:压缩失败，0:压缩成功
Description:        解压数据
***************************************************************************************/
int Http_md5::decomp_gzip(char *src, unsigned int len, char **dest)
{
	int res = -1;
	char tmp[201] = {0};
	int have = 0;
	int is_first = 1;
	int n = 0;
	int has_error = 0;
	int ret = -1;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Byte*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Byte*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK)
        {
			//LOG_WARN("webmail:decomp_gzip(): decompressing gzip error\n");
			has_error = 1;
			break;
		} 
        else 
        {
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) 
            {
				*dest = (char *)malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
                
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
            else 
            {
				*dest = (char *)realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
                
				strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error) 
    {
		if (!is_first)
			free(*dest);
        
		*dest = NULL;
		return -1;
	}
    else
    {
		return 0;
	}
}

/**************************************************************************************
Function Name:          do_tianyiwangpanupload_md5
Input Parameters:       is_from_server
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            解析天翼网盘上传功能的md5值
**************************************************************************************/
int Http_md5::do_tianyiwangpanupload_md5(bool is_from_server)
{
    char* data = NULL;
    char* p1 = NULL, *p2 = NULL;
    
    if(!is_from_server)
    {
        data = m_request_packet.header;
        p1 = strstr(data, "Edrive-FileMD5:");
        if(!p1)
            return -1;

        p1 += strlen("Edrive-FileMD5: ");
        p2 = strstr(p1, "\r\n");
        m_md5value.assign(p1, p2 - p1);
        return 1;
    }
    
    return 0; 
}

/**************************************************************************************
Function Name:          do_tianyiwanpandownload_md5
Input Parameters:       is_from_server
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            解析天翼网盘下载功能的md5值
**************************************************************************************/
int Http_md5::do_tianyiwanpandownload_md5(bool is_from_server)
{
    char* data = NULL;
    char* p1 = NULL, *p2 = NULL;
    
    if(is_from_server)
    {
        data = m_response_packet.header;
        p1 = strstr(data, "ETag: ");
        if(!p1)
            return -1;

        p1 += strlen("ETag: ");
        p2 = strstr(p1, "\r\n");
        m_md5value.assign(p1, p2 - p1);
        return 1;
    }
    
    return 0; 
}

/**************************************************************************************
Function Name:          do_wangyiyun_md5
Input Parameters:       is_from_server
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            解析网易云盘的md5值
**************************************************************************************/
int Http_md5::do_wangyiyun_md5(bool is_from_server)
{
    char* data = NULL, *data_bak = NULL;
    char* p1 = NULL, *p2 = NULL;
    int result = 0;
    
    if(is_from_server)
    {
        data = m_response_packet.body;
        result = decomp_gzip(data, m_response_packet.bodyLen - 2, &data_bak);
        
        if(result == -1)
        {
            printf("do_wangyiyun_md5 decomp_gzip error\n");
            return -1;
        }
        p1 = strstr(data_bak, "\"md5\" : \"");
        if(!p1)
            return -1;
        
        p1 += strlen("\"md5\" : \"");
        p2 = strchr(p1, '\"');
        m_md5value.assign(p1, p2 - p1);
        free(data_bak);
        return 1;
    }
    
    return 0; 
}

/**************************************************************************************
Function Name:          do_tencent_video_upload_md5
Input Parameters:       is_from_server
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            解析腾讯视频的md5值
**************************************************************************************/
int Http_md5::do_tencent_video_upload_md5(bool is_from_server)
{
    char* data = NULL;
    char* p1 = NULL, *p2 = NULL;
    
    if(!is_from_server)
    {
        data = m_request_packet.body;
        p1 = strstr(data, "md5=");
        if(!p1)
            return -1;

        p1 += strlen("md5=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
        
        m_md5value.assign(p1, p2 - p1);
        return 1;
    }
    
    return 0; 
}

/**************************************************************************************
Function Name:          do_md5
Input Parameters:       is_from_server
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            http_md5解析模块的总函数
**************************************************************************************/
int Http_md5::do_md5(bool is_from_server)
{
    int ret = -1;
    
	switch(m_type)
	{
        case 1:
            ret = do_tianyiwangpanupload_md5(is_from_server);
            break;
        case 2:
            ret = do_tianyiwanpandownload_md5(is_from_server);
            break;
        case 3:
            ret = do_wangyiyun_md5(is_from_server);
            break;
        case 4:
            ret = do_tencent_video_upload_md5(is_from_server);
        default:
            break;
    }

    if(1 == ret)
    {
        store_db(m_type);
    }
    
    return ret;
}

/**************************************************************************************
Function Name:          deal_packet_process
Input Parameters:       packet,is_from_server
    packet:             数据包的地址
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,0:组包没有完成,1:解析成功
Description:            http_md5解析模块解析的入口函数
**************************************************************************************/
int Http_md5::deal_process(struct PacketInfo* packet, bool is_from_server)
{
     int ret = -1;
    
    if (!is_from_server)
    {   
        ret = rebuilt_packet(&m_request_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_request_packet, packet);
            ret = do_md5(is_from_server);
        }
    }
    else
    {
        ret = rebuilt_packet(&m_response_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_response_packet, packet);
            ret = do_md5(is_from_server);
        }
    }

    return ret;
}

