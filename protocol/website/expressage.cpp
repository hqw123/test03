/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : expressage.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing online expressage
*
* Evolution( Date | Author | Description ) 
* 2017.06.12 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <stdlib.h>
#include <string>
#include <arpa/inet.h>

#include "expressage.h"
#include "db_data.h"
#include "Analyzer_log.h"
#include "clue_c.h"

/**************************************************************************************
Function Name:         Expressage
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Expressage的构造函数,初始化一些成员变量
***************************************************************************************/
Expressage::Expressage()
{
    m_recv_number = "";
    m_send_number = "";
    m_recv_name = "";
    m_recv_addr = "";
    m_send_name = "";
    m_send_addr = "";
    m_type = 0;
}

/**************************************************************************************
Function Name:         ~Expressage
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Expressage的析构函数,释放一些成员变量
***************************************************************************************/
Expressage::~Expressage()
{
    
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        存数据库
***************************************************************************************/
void Expressage::store_db()
{
    struct in_addr addr;
    EXPRESSAGE_T tmp_data;
    
    memset(&tmp_data,0, sizeof(EXPRESSAGE_T));  
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

    strcpy(tmp_data.send_number, m_send_number.c_str());
    strcpy(tmp_data.recv_number, m_recv_number.c_str());
    strcpy(tmp_data.send_name, m_send_name.c_str());
    strcpy(tmp_data.recv_name, m_recv_name.c_str());
    strcpy(tmp_data.send_addr, m_send_addr.c_str());
    strcpy(tmp_data.recv_addr, m_recv_addr.c_str());
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = m_type;

    msg_queue_send_data(EXPRESSAGE, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:      update_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        存数据库
***************************************************************************************/
void Expressage::update_db()
{
    
}

/**************************************************************************************
Function Name:          analyse_shentong
Input Parameters:       type,is_from_server
    type:               操作类型
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析申通快递模块
**************************************************************************************/
int Expressage::analyse_shentong(unsigned short type, bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    char* buff = NULL;

    if(is_from_server)
        return -1;
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4); 
        
        p1 = strstr(buff, "AcceptPhone=");
        if(p1)
        {
            p1 += strlen("AcceptPhone=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_number.assign(p1, p2 - p1);
        }
       
        p1 = strstr(buff, "AcceptName=");
        if(p1)
        {
            p1 += strlen("AcceptName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_name.assign(p1, p2 - p1);
        }
        
        p1 = strstr(buff, "AcceptProCityArea=");
        if(p1)
        {
            p1 += strlen("AcceptProCityArea=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "AcceptAddress=");
        if(p1)
        {
            p1 += strlen("AcceptAddress=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.append(p1, p2 - p1);
        }

        p1 = strstr(buff, "SenderPhone=");
        if(p1)
        {
            p1 += strlen("SenderPhone=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_number.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "SenderName=");
        if(p1)
        {
            p1 += strlen("SenderName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "SenderProCityAres=");
        if(p1)
        {
            p1 += strlen("SenderProCityAres=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "SenderAddress=");
        if(p1)
        {
            p1 += strlen("SenderAddress=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.append(p1, p2 - p1);
        }
        
        store_db();
        free(buff);
        
        return 1;
    }
}

/**************************************************************************************
Function Name:          analyse_yuantong
Input Parameters:       type,is_from_server
    type:               操作类型
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析圆通快递模块
**************************************************************************************/
int Expressage::analyse_yuantong(unsigned short type, bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    char *buff = NULL; 

    if(is_from_server)
        return -1;
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4); 
        
        p1 = strstr(buff, "receiveMobile=");
        if(p1)
        {
            p1 += strlen("receiveMobile=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_number.assign(p1, p2 - p1);
        }
        
        p1 = strstr(buff, "receiveName=");
        if(p1)
        {
            p1 += strlen("receiveName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_name.assign(p1, p2 - p1);
        }
        
        p1 = strstr(buff, "receiveAddress=");
        if(p1)
        {
            p1 += strlen("receiveAddress=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.assign(p1, p2 - p1);
            m_recv_addr.append(1, ' ');
        }

        p1 = strstr(buff, "receiveRegionId=");
        if(p1)
        {
            p1 += strlen("receiveRegionId="); 
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.append(p1, p2 - p1);
        }

        p1 = strstr(buff, "sendMobile=");
        if(p1)
        {
            p1 += strlen("sendMobile=");
            p2 = strchr(p1, '&');
			if (p2)
                m_send_number.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "sendName=");
        if(p1)
        {
            p1 += strlen("sendName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "sendAddress=");
        if(p1)
        {
            p1 += strlen("sendAddress=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.assign(p1, p2 - p1);
            m_send_addr.append(1, ' ');
        }

        p1 = strstr(buff, "sendRegionId=");
        if(p1)
        {
            p1 += strlen("sendRegionId=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.append(p1, p2 - p1);
        }
        
        store_db();
        free(buff);
        
        return 1;
    }
	
    return -1;
}

/**************************************************************************************
Function Name:          analyse_yunda
Input Parameters:       type,is_from_server
    type:               操作类型
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析韵达快递模块
**************************************************************************************/
int Expressage::analyse_yunda(unsigned short type, bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    char *buff = NULL;

    if(is_from_server)
        return -1;
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);   
        
        p1 = strstr(buff, "senderMobile\":\"");
        if(p1)
        {
            p1 += strlen("senderMobile\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_send_number.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "senderName\":\"");
        if(p1)
        {
            p1 += strlen("senderName\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_send_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "senderAddress\":\"");
        if(p1)
        {
            p1 += strlen("senderAddress\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_send_addr.assign(p1, p2 - p1);
            m_send_addr.append(1, ' ');
        }

        p1 = strstr(buff, "senderArea\":\"");
        if(p1)
        {
            p1 += strlen("senderArea\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_send_addr.append(p1, p2 - p1);
        }

        p1 = strstr(buff, "receiverMobile\":\"");
        if(p1)
        {
            p1 += strlen("receiverMobile\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_recv_number.assign(p1, p2 - p1);  
        }

        p1 = strstr(buff, "receiverName\":\"");
        if(p1)
        {
            p1 += strlen("receiverName\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_recv_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "receiverAddress\":\"");
        if(p1)
        {
            p1 += strlen("receiverAddress\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_recv_addr.assign(p1, p2 - p1);
            m_recv_addr.append(1, ' ');
        }

        p1 = strstr(buff, "receiverArea\":\"");
        if(p1)
        {
            p1 += strlen("receiverArea\":\"");
            p2 = strchr(p1, '\"');
            if (p2)
                m_recv_addr.append(p1, p2 - p1);
        }

        store_db();
        free(buff);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_ems
Input Parameters:       type,is_from_server
    type:               操作类型
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析中国邮政快递模块
**************************************************************************************/
int Expressage::analyse_ems(unsigned short type, bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    char *buff = NULL;

    if(is_from_server)
        return -1;
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);   

        p1 = strstr(buff, "shipment.sendMobile=");
        if(p1)
        {
            p1 += strlen("shipment.sendMobile=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_number.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "shipment.sendName=");
        if(p1)
        {
            p1 += strlen("shipment.sendName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "shipment.sendDetailadd=");
        if(p1)
        {
            p1 += strlen("shipment.sendDetailadd=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.assign(p1, p2 - p1);
            m_send_addr.append(1, ' ');
        }

        p1 = strstr(buff, "shipment.sendCounty=");
        if(p1)
        {
            p1 += strlen("shipment.sendCounty=");
            p2 = strchr(p1, '&');
            if (p2)
                m_send_addr.append(p1, p2 - p1);
        }

        p1 = strstr(buff, "shipment.receiveMobile=");
        if(p1)
        {
            p1 += strlen("shipment.receiveMobile=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_number.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "shipment.receiveName=");
        if(p1)
        {
            p1 += strlen("shipment.receiveName=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_name.assign(p1, p2 - p1);
        }

        p1 = strstr(buff, "shipment.receiveDetailadd=");
        if(p1)
        {
            p1 += strlen("shipment.receiveDetailadd=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.assign(p1, p2 - p1);
            m_recv_addr.append(1, ' ');
        }

        p1 = strstr(buff, "shipment.receiveCounty=");
        if(p1)
        {
            p1 += strlen("shipment.receiveCounty=");
            p2 = strchr(p1, '&');
            if (p2)
                m_recv_addr.append(p1, p2 - p1);
        }

        free(buff);
        store_db();

        return 1;
    }
	
    return -1;
}

/**************************************************************************************
Function Name:          analyse_shunfeng
Input Parameters:       type,is_from_server
    type:               操作类型
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析顺丰快递模块
**************************************************************************************/
int Expressage::analyse_shunfeng(unsigned short type, bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    char *p3 = NULL, *p4 = NULL;
    char *buff = NULL;

    if(is_from_server)
        return -1;

    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);   

        p1 = strstr(buff, "\"reciverInfo\":[");
        if(p1)
        {
            p1 += strlen("\"reciverInfo\":[");
            p2 = strchr(p1, ']');
            if(p2)
            {
                p3 = strstr(p1, "\"countryName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"countryName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_addr.assign(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"provinceName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"provinceName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"cityName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"cityName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"countyName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"countyName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"address\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"address\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"contactName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"contactName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_name.assign(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"contactMobile\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"contactMobile\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_recv_number.assign(p3, p4 - p3);
                }
            }
        }

        p1 = strstr(buff, "\"shipperInfo\":{");
        if(p1)
        {
            p1 += strlen("\"shipperInfo\":{");
            p2 = strchr(p1, '}');
            if(p2)
            {
                p3 = strstr(p1, "\"countryName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"countryName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_addr.assign(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"provinceName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"provinceName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"cityName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"cityName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"countyName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"countyName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"address\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"address\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_addr.append(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"contactName\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"contactName\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_name.assign(p3, p4 - p3);
                }

                p3 = strstr(p1, "\"contactMobile\":\"");
                if(p3 && (p3 < p2))
                {
                    p3 += strlen("\"contactMobile\":\"");
                    p4 = strchr(p3, '\"');
                    if (p4)
                        m_send_number.assign(p3, p4 - p3);
                }
            }
        }

        store_db();
        free(buff);

        return 1;
    }
	
	return -1;
}

/**************************************************************************************
Function Name:          analyse_expressage
Input Parameters:       type,packet,is_from_server
    type:               平台的类型
    packet:             数据包的地址
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,1:解析成功
Description:            解析快递模块
**************************************************************************************/
int Expressage::analyse_expressage(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    unsigned short type1 = 0, type2 = 0;

    if (is_from_server)
        return -1;
    
    type1 = (type >> 8) & 0x00ff;
    type2 = type & 0x00ff; 
    m_type = type1 + EXPRESSAGECLASS;
    
    switch(m_type)
    {
        case SHENTONG:
            ret = analyse_shentong(type2, is_from_server);    
            break;
            
        case YUANTONG:
            ret = analyse_yuantong(type2, is_from_server);
            break;
            
        case YUNDA:
            ret = analyse_yunda(type2, is_from_server);
            break;

        case EMS:
            ret = analyse_ems(type2, is_from_server);
            break;
            
        case SHUNFENG:
            ret = analyse_shunfeng(type2, is_from_server);
            break;
            
        default:
            break;
    }

    return ret;
}

/**************************************************************************************
Function Name:          deal_packet_process
Input Parameters:       type,packet,is_from_server
    type:               平台的类型
    packet:             数据包的地址
    is_from_server:     0表示请求包,1表示回应包
Output Parameters:      void
Return Code:            -1:失败,0:组包没有完成,1:解析成功
Description:            快递模块解析的入口函数
**************************************************************************************/
int Expressage::deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    
    if(!is_from_server)
    {
        ret = rebuilt_packet(&m_request_packet, packet->body, packet->bodyLen);
        if(1 == ret)
        {
            set_packet_base_info(&m_request_packet, packet);
            ret = analyse_expressage(type, packet, is_from_server);
        }
    }
    
    return ret;
}


