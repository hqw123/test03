
#include <string.h>
#include <boost/regex.hpp>
#include <stdio.h>
#include <iconv.h>
#include "db_data.h"
#include "jobsite_handler.h"

//TODO:
// 1.the logic of the regex search functions is not robust, we know, but can't modify it now, mostly trifling
//
//

// FIXME: this macro is just for test, remove it when released version is available
#define     DEBUG_MSG(fmt, args...)  fprintf(stderr, "[%s:%d]"fmt"\n", __FILE__, __LINE__, ##args)

jobsite_handler::jobsite_handler()
{
    memset(&m_entry, 0, sizeof(m_entry));
    m_job_type = 0;
}

jobsite_handler::~jobsite_handler()
{
    realease_pack();
}


static size_t gb2312_to_utf8(char *inbuf, size_t *inlen, char *obuf, size_t *olen)
{
	size_t bytes_convs = 0;
	iconv_t ic = 0;
	ic = iconv_open("UTF8", "GB2312");
	if (-1 == (long)ic)
		return -1;
	bytes_convs = iconv(ic, &inbuf, inlen, &obuf, olen);
	iconv_close(ic);
	return bytes_convs;
}

void jobsite_handler::parase_51_info(const jobsite_info *node, unsigned short type)
{
    if(0x01 == type)
    {
    	boost::regex  QC_exp_name("<td colspan=\"2\" class=\"name\">");
    	boost::regex  QC_exp_phone("<img.*?class=\"vam\".*?y2.png");
        boost::regex  QC_exp_addr("<img.*?class=\"vam\".*?y4.png");
    	const char *buf_end = node->d_buf + node->d_len;
    	const char *buf = node->d_buf;
    	char name_buf[MAX_NAME_LEN] = {0};
    	char phone_buf[MAX_PHONE_LEN] = {0};
    	char addr_buf[MAX_ADDR_LEN] = {0};

    	char utf8_name[MAX_NAME_LEN*2] = {0};
    	char utf8_addr[MAX_ADDR_LEN*2] = {0};
    	size_t icn_ilen = 0;
    	size_t icn_olen = sizeof(utf8_name);
    	size_t ica_ilen = sizeof(addr_buf);
    	size_t ica_olen = sizeof(utf8_addr);
    	size_t bytes_convs = 0;
       
    	size_t iolen = sizeof(phone_buf);
        
    	boost::cmatch ma_name;
    	boost::cmatch ma_phone;
        boost::cmatch ma_addr;
        
    	if (boost::regex_search(buf, buf_end, ma_name, QC_exp_name))
    	{
    		const char *vend = strchr(ma_name[0].second, '<');
    		if (!vend)  
    		    return;
    		
    		icn_ilen = vend - ma_name[0].second;
    		if (vend)
    		    memcpy(name_buf, ma_name[0].second, vend - ma_name[0].second);
    		//this->copy_value_among_ab(ma_name[0].second, ma_name[0].length(), name_buf, &iolen_2);
    		//this->dump(name_buf, sizeof(name_buf));
    	}

    	if (boost::regex_search(buf, buf_end, ma_phone, QC_exp_phone))
    	{
    		this->copy_value_among_ab(ma_phone[0].second, ma_phone[0].length(), phone_buf, &iolen);
    		//DEBUG_MSG("we get phone number:%s", phone_buf);
    	}

        if(boost::regex_search(buf, buf_end, ma_addr, QC_exp_addr))
        {
            get_51job_addr(ma_addr[0].second, ma_addr[0].length(), addr_buf, sizeof(addr_buf));
        }
    	// code page translate
    	bytes_convs += gb2312_to_utf8(name_buf, &icn_ilen, utf8_name, &icn_olen);
    	bytes_convs += gb2312_to_utf8(addr_buf, &ica_ilen, utf8_addr, &ica_olen);
    	//DEBUG_MSG("bytes_convs = %ld", bytes_convs);

    	bytes_convs = icn_ilen + ica_ilen;
    	unsigned int clue_id = get_clue_id(node->src_mac, inet_ntoa(*(struct in_addr *)&node->tp.saddr));
    	/*write personal_info data to shared memory, by zhangzm*/
    	PERSONAL_INFO_T tmp_data;
    	memset(&tmp_data, 0, sizeof(tmp_data));
    	
    	tmp_data.p_data.clueid = clue_id;
    	tmp_data.p_data.readed = 0;
    	strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&node->tp.saddr));
    	strncpy(tmp_data.p_data.clientMac, node->src_mac, 17);
    	sprintf(tmp_data.p_data.clientPort, "%d", node->tp.sport);
    	strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&node->tp.daddr));
    	sprintf(tmp_data.p_data.serverPort, "%d", node->tp.dport);
    	tmp_data.p_data.captureTime = (unsigned int)time(NULL);

    	if (!bytes_convs)
    		strncpy(tmp_data.name, utf8_name, 255);
    	else
    		strncpy(tmp_data.name, name_buf, 255);

    	strncpy(tmp_data.phone, phone_buf, 63);

    	if (!bytes_convs)
    		strncpy(tmp_data.address, utf8_addr, 511);
    	else
    		strncpy(tmp_data.address, addr_buf, 511);

    	strcpy(tmp_data.correlative, "");
    	
    	tmp_data.p_data.proType = 1901;
    	tmp_data.p_data.deleted = 0;
    	msg_queue_send_data(PERSONAL_INFO, (void *)&tmp_data, sizeof(tmp_data));
    }
}

void jobsite_handler::parase_zl_info(const jobsite_info *node, unsigned short type)
{
    if(0x01 == type)
    {
    	boost::regex  ZL_exp_name("lookResumes.*?<h1>.*</h1>");
    	const char *buf_end = node->d_buf + node->d_len;
    	const char *buf = node->d_buf;
    	char name_buf[MAX_NAME_LEN] = {0};
    	char phone_buf[MAX_PHONE_LEN] = {0};
    	char addr_buf[MAX_ADDR_LEN] = {0};
    	size_t iolen = sizeof(name_buf);	
    	boost::cmatch ma_name;
    	boost::cmatch ma_phone;

    	// ZL data is standard utf-8
    	//iconv_t ic = iconv_open();
    	if (boost::regex_search(buf, buf_end, ma_name, ZL_exp_name))
    	{
    		this->copy_value_among_ab(ma_name[0].first + 20, ma_name[0].length(), name_buf, &iolen);
    	}

    	unsigned int clue_id = get_clue_id(node->src_mac, inet_ntoa(*(struct in_addr *)&node->tp.saddr));
    	/*write personal_info data to shared memory, by zhangzm*/
    	PERSONAL_INFO_T tmp_data;
    	memset(&tmp_data, 0, sizeof(tmp_data));
    	
    	tmp_data.p_data.clueid = clue_id;
    	tmp_data.p_data.readed = 0;
    	strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&node->tp.daddr));
    	strncpy(tmp_data.p_data.clientMac, node->src_mac, 17);//MAC is error, zhangzm
    	sprintf(tmp_data.p_data.clientPort, "%d", node->tp.dport);
    	strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&node->tp.saddr));
    	sprintf(tmp_data.p_data.serverPort, "%d", node->tp.sport);
    	tmp_data.p_data.captureTime = (unsigned int)time(NULL);

    	strncpy(tmp_data.name, name_buf, 255);
    	strncpy(tmp_data.phone, phone_buf, 63);
    	strncpy(tmp_data.address, addr_buf, 511);

    	strcpy(tmp_data.correlative, "");
    	
    	tmp_data.p_data.proType = 1902;
    	tmp_data.p_data.deleted = 0;
    	msg_queue_send_data(PERSONAL_INFO, (void *)&tmp_data, sizeof(tmp_data));
    }
}


bool jobsite_handler::copy_value_among_ab(const char *data, size_t inlen, char *obuf, size_t *olen)
{
    const char *vstart = NULL, *vend = NULL;

    if (!obuf || *olen <= 0)  return false;
    vstart = data;
    vstart = strchr(vstart, '>');
    ++ vstart;
    if (vstart) vend = strchr(vstart, '<');
    if (vend && *olen > vend - vstart) 
    {
    	*olen = vend - vstart;
    	memcpy(obuf, vstart, *olen);
    	return true;	
    }

    return false;
}

/**************************************************************************************
Function Name:      get_51job_addr
Input Parameters:   data,inlen,olen
    data:           需要解析的原始数据
    inlen:          需要解析的原始数据的长度
    olen:           解析出数据缓冲区的长度
Output Parameters:  obuf
    obuf:           解析出成功的数据
Return Code:        true,false
Description:        释放类成员m_entry成员所分配的空间
***************************************************************************************/
bool jobsite_handler::get_51job_addr(const char *data, size_t inlen, char *obuf, size_t olen)
{
    char *p1 = NULL,*p2 = NULL;
    
    if(!obuf || olen <= 0)
        return false;

    p1 = strchr((char*)data, '-');
    if(p1)
    {
        for(p2 = p1; *p2 != '>'; p2--);
        p2 += 1;
        strncpy(obuf, p2, p1 - p2);
        for(p2 = p1; *p2 != '<'; p2++);
        strncat(obuf, p1, p2 - p1);
    }
    else
    {
        return false;
    }
    
    return true;
}

/**************************************************************************************
Function Name:      realease_pack
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        释放类成员m_entry成员所分配的空间
***************************************************************************************/
void jobsite_handler::realease_pack()
{
    if (m_entry.header)
    {
        free(m_entry.header);
        m_entry.header = NULL;
    }
    
    if (m_entry.body)
    {
        free(m_entry.body);
        m_entry.body = NULL;
    }

    memset(&m_entry, 0, sizeof(m_entry));
}

/*************************************************************************************
Function Name:      decomp_gzip
Input Parameters:   src,len
    src:            解压前数据的首地址
    len:            解压前数据的长度
Output Parameters:  dest
    dest:           解压后数据的首地址
Return Code:        -1:解压缩失败,0:解压缩成功
Description:        将压缩的数据解压缩
**************************************************************************************/
int jobsite_handler::decomp_gzip(char *src, unsigned int len, char **dest)
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
    		LOG_WARN("webmail:decomp_gzip(): decompressing gzip error\n");
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
    	//printf("decomp_gzip complete Error ...\n");
    	return -1;
    }
    else
    {
    	//printf("decomp_gzip complete Ok ...\n");
    	return 0;
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
int jobsite_handler::rebuilt_packet(char* data, unsigned int dataLen)
{
    if (!(m_entry.status&0x01))
    {
        char *p = strstr(data, "\r\n\r\n");
        if (p)
        {
            p += 4;
            if (m_entry.headerLen == 0)
            {
                m_entry.headerLen = p - data;
                m_entry.header = (char* )malloc(p - data + 1);
                if(!m_entry.header) 
                    return -1;
                
                memcpy(m_entry.header, data, p - data);
                m_entry.header[m_entry.headerLen] = 0;
            }
            else
            {
                m_entry.header = (char *)realloc(m_entry.header, m_entry.headerLen + (p - data) + 1);
                if(!m_entry.header) 
                    return -1;
                
                memcpy(m_entry.header + m_entry.headerLen, data, p - data);
                m_entry.headerLen += p-data;
                m_entry.header[m_entry.headerLen] = 0;
            }
            
            m_entry.status |= 0x01;
            char *p1 = strcasestr(m_entry.header, "\r\nTransfer-Encoding: chunked");
            if (p1)
            {
                m_entry.status |= 0x02;
                m_entry.body = (char *)malloc(1);
                m_entry.body[0] = 0;
                m_entry.status |= 0x04;
                char *p2 = strstr(p, "\r\n");
                while (p2)
                {
                    if ((p2 + 2) > (data + dataLen)) 
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
                        m_entry.body[m_entry.bodyLen] = 0;
                        return 1;
                    }
                    
                    p2 += 2;
                    if ((p2 + len) <= (data + dataLen))
                    {
                        m_entry.body = (char *)realloc(m_entry.body, m_entry.bodyTotal + len + 1);
                        if (!m_entry.body) 
                            return -1;
                        
                        memcpy(m_entry.body + m_entry.bodyLen, p2, len);
                        m_entry.bodyLen += len;
                        m_entry.bodyTotal += len;
                        m_entry.status |= 0x04;
                        p = p2 + len + 2;            // 2 is "0d 0a"
                        p2 = strstr(p, "\r\n");
                        continue;
                    }
                    else
                    {
                        m_entry.body = (char *)realloc(m_entry.body, m_entry.bodyTotal + len + 1);
                        if(!m_entry.body)
                            return -1;
                        
                        unsigned int slen = data + dataLen - p2;
                        memcpy(m_entry.body + m_entry.bodyLen, p2, slen);
                        m_entry.bodyTotal += len;
                        m_entry.bodyLen += slen;
                        m_entry.status &= 0xfffffffb;
                        break;
                    }
                }
            }
            else if(p1 = strcasestr(m_entry.header, "\r\nContent-Length: "))
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
                
                m_entry.bodyTotal = len;
                m_entry.bodyLen = dataLen - (p-data);
                m_entry.body = (char *)malloc(m_entry.bodyLen + 1);
                if (!m_entry.body)
                    return -1;
                
                if (m_entry.bodyLen > 0)
                    memcpy(m_entry.body, p, m_entry.bodyLen);

                if (m_entry.bodyLen >= m_entry.bodyTotal)
                {
                    m_entry.body[m_entry.bodyLen] = 0;
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
            if(m_entry.headerLen == 0)
            {
                m_entry.headerLen = dataLen;
                m_entry.header = (char* )malloc(dataLen + 1);
                if(!m_entry.header) 
                    return -1;
                
                memcpy(m_entry.header, data, dataLen);
            }
            else
            {
                m_entry.header = (char* )realloc(m_entry.header, m_entry.headerLen + dataLen + 1);
                memcpy(m_entry.header + m_entry.headerLen, data, dataLen);
                m_entry.headerLen += dataLen;
            }
        }
    }
    else
    {
        if (m_entry.status&0x02)
        {
            char *p = data;
            if (!(m_entry.status&0x04))
            {
                if(m_entry.bodyLen + dataLen < m_entry.bodyTotal)
                {
                    memcpy(m_entry.body + m_entry.bodyLen, data, dataLen);
                    m_entry.bodyLen += dataLen;
                }
                else
                {
                    int offset = m_entry.bodyTotal - m_entry.bodyLen;
                    memcpy(m_entry.body + m_entry.bodyLen, data, offset);
                    m_entry.bodyLen = m_entry.bodyTotal;
                    p = data + offset + 2;
                    m_entry.status |= 0x04;
                }
            }
            
            if (m_entry.status&0x04)
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
                        m_entry.body[m_entry.bodyLen] = 0;
                        return 1;
                    }
                    
                    p2 += 2;
                    if ((p2 + len) <= (data + dataLen))
                    {
                        m_entry.body = (char *)realloc(m_entry.body, m_entry.bodyTotal + len + 1);
                        if(!m_entry.body)
                            return -1;
                        
                        memcpy(m_entry.body+m_entry.bodyLen, p2, len);
                        m_entry.bodyLen += len;
                        m_entry.bodyTotal += len;
                        m_entry.status |= 0x04;
                        p = p2 + len + 2;
                        p2 = strstr(p, "\r\n");
                        continue;
                    }
                    else
                    {
                        m_entry.body = (char *)realloc(m_entry.body, m_entry.bodyTotal + len + 1);
                        if(!m_entry.body) 
                            return -1;
                        
                        unsigned int slen = data + dataLen - p2;
                        memcpy(m_entry.body + m_entry.bodyLen, p2, slen);
                        m_entry.bodyTotal += len;
                        m_entry.bodyLen += slen;
                        m_entry.status &= 0xfffffffb;
                        break;
                    }
                }
            }
        }
        else
        {
            m_entry.body = (char *)realloc(m_entry.body, m_entry.bodyLen + dataLen + 1);
            if (!m_entry.body)
            {
                return -1;
            }
            
            memcpy(m_entry.body + m_entry.bodyLen, data, dataLen);
            m_entry.bodyLen += dataLen;
            if (m_entry.bodyLen >= m_entry.bodyTotal)
            {
                m_entry.body[m_entry.bodyLen] = 0;
                return 1;
            }
        }
    }
    
    return 0;
}

/**************************************************************************************
Function Name:          analyse_job
Input Parameters:       type,packet
    type:               平台的类型
    packet:             数据包的地址
Output Parameters:      void
Return Code:            -1:失败,0:组包没有完成,1:解析成功
Description:            招聘网站解析的入口函数
**************************************************************************************/
int jobsite_handler::analyse_job(unsigned short type, PacketInfo* packet)
{
    int result = -1;
    unsigned short type1 = 0, type2 = 0;
    char* p_dest = NULL;
    
    //type1 表示哪个平台，type2 表示哪种行为类型的包
    type1 = (type >> 8) & 0x00ff;
    type2 = type & 0x00ff; 
    m_job_type = type1 + 1900;
    
    result = decomp_gzip(m_entry.body, m_entry.bodyLen - 2, &p_dest);
    if (result == -1 || p_dest == NULL)
        return -1;
    
    jobsite_info info;
    memset(&info, 0, sizeof(info));
    info.tp.daddr = packet->srcIpv4;
    info.tp.saddr = packet->destIpv4;
    info.tp.dport = packet->srcPort;
    info.tp.sport = packet->destPort;
    info.src_mac = (char*)malloc(20);
    memset(info.src_mac, 0, 20);
    sprintf(info.src_mac, "%02x-%02x-%02x-%02x-%02x-%02x", packet->destMac[0], packet->destMac[1], packet->destMac[2], packet->destMac[3],\
            packet->destMac[4], packet->destMac[5]);
    info.d_buf = p_dest;
    info.d_len = strlen(p_dest);
  
    if(m_job_type == JOB_51)
    {
        parase_51_info(&info, type2);
    }
    else if(m_job_type == JOB_ZL)
    {
        parase_zl_info(&info, type2);
    }
    else
    {
        return -1;
    }

    free(info.src_mac);
    free(p_dest);
	
    return 1;
}

/**************************************************************************************
Function Name:          deal_packet_process
Input Parameters:       type,packet,is_from_server
    type:               平台的类型
    packet:             数据包的地址
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,0:组包没有完成,1:解析成功
Description:            招聘网站解析的主入口函数
**************************************************************************************/
int jobsite_handler::deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    char* dest = NULL;
	
    if(is_from_server)
    {
        ret = rebuilt_packet(packet->body, packet->bodyLen);
        if(1 == ret)
        {
            ret = analyse_job(type, packet);
        }
    }
    else
    {
        return 0;
    }
	
    return ret;
}

