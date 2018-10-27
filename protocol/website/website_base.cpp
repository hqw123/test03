/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : website_base.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for website base class
*  
* Evolution( Date | Author | Description ) 
* 2017.06.28 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "website_base.h"
#include "Analyzer_log.h"

/**************************************************************************************
Function Name:         website_base
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Website_base的构造函数,初始化一些成员变量
***************************************************************************************/
website_base::website_base()
{
    memset(&m_request_packet, 0, sizeof(m_request_packet));
    memset(&m_response_packet, 0, sizeof(m_response_packet));
}

/**************************************************************************************
Function Name:         ~website_base
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Website_base的析构函数,释放成员变量，释放成员变量所申请的空间
**************************************************************************************/
website_base::~website_base()
{
    release_node();
}

/**************************************************************************************
Function Name:      realease_pack
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        释放类成员m_entry成员所分配的空间
***************************************************************************************/
void website_base::release_node()
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

/****************************************************************************
Function Name:           set_packet_base_info
Input Parameters:        pktinfo
Output Parameters:       pinfo
Return Code:             -1:fail, 0:success
Description:             set srcMac, destMac, srcIpv4, destIpv4, srcPort, destPort
****************************************************************************/
int website_base::set_packet_base_info(struct packet_info *pinfo, struct PacketInfo *pktinfo)
{
    //memcpy(pinfo->srcMac, pktinfo->srcMac, 6);
    //memcpy(pinfo->destMac, pktinfo->destMac, 6);

    sprintf(pinfo->src_mac, "%02x-%02x-%02x-%02x-%02x-%02x\0", pktinfo->srcMac[0]&0xff, pktinfo->srcMac[1]&0xff, 
            pktinfo->srcMac[2]&0xff, pktinfo->srcMac[3]&0xff, pktinfo->srcMac[4]&0xff, pktinfo->srcMac[5]&0xff);


    pinfo->saddr = pktinfo->srcIpv4;
    pinfo->daddr = pktinfo->destIpv4;

    pinfo->sport = pktinfo->srcPort;
    pinfo->dport = pktinfo->destPort;

    pinfo->capture_time = (unsigned int)pktinfo->pkt->ts.tv_sec;

    return 0;
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
int website_base::rebuilt_packet(struct packet_info *entry, char* data, unsigned int dataLen)
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
Function Name:           decomp_gzip
Input Parameters:        src, len
Output Parameters:       dest
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int website_base::decomp_gzip(char *src, unsigned int len, char **dest)
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
Function Name:          url_decode
Input Parameters:       inbuf,inlen
    inbuf:              解码之前的数据
    inlen:              解码之前的数据大小
Output Parameters:      outbuf,olen
    outbuf:             解码之后的数据
    olen:               解码之后的数据大小
Return Code:            返回解码之后的数据大小
Description:            将输入的数据解码，然后输出
***************************************************************************************/
int website_base::url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
{
    int j = 0;
    int hex = 0; 
    for (size_t i = 0; i < inlen; ++i)
    {  
        switch (inbuf[i])  
        {
            case '+':  
                outbuf[j++] = ' ';
                break;  
            case '%': 
                if (isxdigit(inbuf[i + 1]) && isxdigit(inbuf[i + 2]))
                {
                    char hexStr[3] = {0};
                    strncpy(hexStr, &inbuf[i + 1], 2);
                    hex = strtol(hexStr, 0, 16);

                    if (!(hex >= 48 && hex <= 57) || //0-9  
                                (hex >=97 && hex <= 122) ||   //a-z  
                                (hex >=65 && hex <= 90) ||    //A-Z  
                                (hex == 0x2d ) || (hex == 0x2e) || (hex == 0x2f) || (hex == 0x5f)) 
								
                    {
                        outbuf[j++] = char(hex);
                        i += 2; 
                    }
                    else 
						outbuf[j++] = '%';
				}
                else
                {
                    outbuf[j++] = '%';
                }
                break; 
            default: 
                outbuf[j++] = inbuf[i];
                break;  
        }
    }
	
    return j;  
}

/********************************************************************************
Function Name:           enc_unicode_to_utf8_one
Input Parameters:        unic
    unic:                字符的Unicode编码值 
Output Parameters:       pOutput, outSize
    pOutput:             指向输出的用于存储UTF8编码值的缓冲区的指针 
    outSize:             转换后的字符的UTF8编码所占的字节数
Return Code:             -1 or 0
Description:             
将一个字符的Unicode(UCS-2和UCS-4)编码转换成UTF-8编码. 
1. UTF8没有字节序问题, 但是Unicode有字节序要求; 
   字节序分为大端(Big Endian)和小端(Little Endian)两种; 
   在Intel处理器中采用小端法表示, 在此采用小端法表示. (低地址存低位) 
2. 请保证 pOutput 缓冲区有最少有 6 字节的空间大小! 
********************************************************************************/
int website_base::enc_unicode_to_utf8_one(unsigned long unic, unsigned char *pOutput, int *outSize)
{
    if (!pOutput)
        return -1;
  
    if ( unic <= 0x0000007F )  
    {  
        // * U-00000000 - U-0000007F:  0xxxxxxx  
        *pOutput     = (unic & 0x7F);  
        *outSize = 1;  
    }  
    else if ( unic >= 0x00000080 && unic <= 0x000007FF )  
    {  
        // * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx  
        *(pOutput+1) = (unic & 0x3F) | 0x80;  
        *pOutput     = ((unic >> 6) & 0x1F) | 0xC0;  
        *outSize = 2;  
    }  
    else if ( unic >= 0x00000800 && unic <= 0x0000FFFF )  
    {  
        // * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx  
        *(pOutput+2) = (unic & 0x3F) | 0x80;  
        *(pOutput+1) = ((unic >>  6) & 0x3F) | 0x80;  
        *pOutput     = ((unic >> 12) & 0x0F) | 0xE0;  
        *outSize = 3;  
    }  
    else if ( unic >= 0x00010000 && unic <= 0x001FFFFF )  
    {  
        // * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx  
        *(pOutput+3) = (unic & 0x3F) | 0x80;  
        *(pOutput+2) = ((unic >>  6) & 0x3F) | 0x80;  
        *(pOutput+1) = ((unic >> 12) & 0x3F) | 0x80;  
        *pOutput     = ((unic >> 18) & 0x07) | 0xF0;  
        *outSize = 4;  
    }  
    else if ( unic >= 0x00200000 && unic <= 0x03FFFFFF )  
    {  
        // * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
        *(pOutput+4) = (unic & 0x3F) | 0x80;  
        *(pOutput+3) = ((unic >>  6) & 0x3F) | 0x80;  
        *(pOutput+2) = ((unic >> 12) & 0x3F) | 0x80;  
        *(pOutput+1) = ((unic >> 18) & 0x3F) | 0x80;  
        *pOutput     = ((unic >> 24) & 0x03) | 0xF8;  
        *outSize = 5;  
    }  
    else if ( unic >= 0x04000000 && unic <= 0x7FFFFFFF )  
    {  
        // * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
        *(pOutput+5) = (unic & 0x3F) | 0x80;  
        *(pOutput+4) = ((unic >>  6) & 0x3F) | 0x80;  
        *(pOutput+3) = ((unic >> 12) & 0x3F) | 0x80;  
        *(pOutput+2) = ((unic >> 18) & 0x3F) | 0x80;  
        *(pOutput+1) = ((unic >> 24) & 0x3F) | 0x80;  
        *pOutput     = ((unic >> 30) & 0x01) | 0xFC;  
        *outSize = 6;  
    }  
  
    return 0;  
}

/****************************************************************************
Function Name:           unicode_to_utf8
Input Parameters:        inbuf, inlen, olen
Output Parameters:       outbuf
Return Code:             length of outbuf
Description:             将unicode 转化成 utf8
****************************************************************************/
int website_base::unicode_to_utf8(const char *inbuf, u_int inlen, char *outbuf, u_int olen)
{
    u_int i = 0;
	int ret = -1;
	int out_len = 0;
	u_long uni_val = 0;
	char hex_str[5] = {0};
    char *tmpbuf = outbuf;
    
	for (i = 0; i < inlen; ++i)
	{
	    switch (inbuf[i])
	    {
            case '%':
            case '\\':
            {
                if ('u' == inbuf[i + 1])
                {
                    strncpy(hex_str, &inbuf[i + 2], 4);
                    uni_val = strtol(hex_str, 0, 16);

                    ret = enc_unicode_to_utf8_one(uni_val, (unsigned char*)tmpbuf, &out_len);
                    if (ret < 0)
                        return -1;

                    tmpbuf += out_len;
                    i += 5;
                }
                else
                {
                    *tmpbuf++ = '%';
                }
            }
            break;
            
			default:
				*tmpbuf++ = inbuf[i];
				break;
        }
	}

    return tmpbuf - outbuf;
}


