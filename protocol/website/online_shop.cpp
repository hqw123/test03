/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : online_shop.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing online shop website
*
* Evolution( Date | Author | Description ) 
* 2017.06.01 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <string>
#include <stdlib.h>
#include <arpa/inet.h>

#include "online_shop.h"
#include "db_data.h"
#include "Analyzer_log.h"
#include "clue_c.h"

/**************************************************************************************
Function Name:         Onlineshop
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Onlineshop的构造函数,初始化一些成员变量
***************************************************************************************/
Onlineshop::Onlineshop()
{
    m_order_number = "";
    m_telephone_number = "";
    m_sign_id = "";
    
    m_shopping_account = NULL;
    m_shopper = NULL;
    m_shop_addr = NULL;
    m_shop_type = 0;
}

/**************************************************************************************
Function Name:         ~Onlineshop
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Onlineshop的析构函数,释放成员变量，释放成员变量所申请的空间
**************************************************************************************/
Onlineshop::~Onlineshop()
{
    realease_data(); 
}

/********************************************************************************************
Function Name:      getCookie
Input Parameters:   data,datalen
Output Parameters:  void
Return Code:        0:失败或不含有Cookie, 1:含有Cookie
Description:        给类的成员变量m_cookie赋值
*********************************************************************************************/
int Onlineshop::getCookie(char* data, int datalen)
{
    if (data == NULL)
        return 0;
	
    const char *cookiePattern = "Cookie:";
    char *addr = strstr(data, cookiePattern);
    if (!addr)
        return 0;
    
    int index = 0;
    index = addr - data + strlen(cookiePattern);
    index++;
    while ((index < datalen) && (data[index] !='\r'))
    {
        m_cookie.append(1, data[index]);
        index++;
    }
	
    return 1;
}

/**********************************************************************************************
Function Name:      store_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        将对应的数据存数据库
***********************************************************************************************/
void Onlineshop::store_db()
{
    struct in_addr addr;
    ONLINESHOP_T tmp_data;
    
    memset(&tmp_data, 0, sizeof(ONLINESHOP_T));
    tmp_data.p_data.readed = 0;

    addr.s_addr = m_request_packet.saddr;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    strncpy(tmp_data.p_data.clientMac, m_request_packet.src_mac, 17);
    
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);
    sprintf(tmp_data.p_data.clientPort, "%d", m_request_packet.sport);

    addr.s_addr = m_request_packet.daddr;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", m_request_packet.dport);
    
    tmp_data.p_data.captureTime = m_request_packet.capture_time;
    
    if (m_shopping_account)
    {
        strncpy(tmp_data.shopping_account, this->m_shopping_account, 128);
    }

    strncpy(tmp_data.telephone_number, this->m_telephone_number.c_str(), 20);

    if (m_shopper)
    {
        strncpy(tmp_data.shopper, this->m_shopper, 128);
    }

    if(m_shop_addr)
    {
        strncpy(tmp_data.shop_addr, this->m_shop_addr, 1024);
    }
    
    strncpy(tmp_data.sign_id, this->m_sign_id.c_str(), 40);
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = m_shop_type;
    
    msg_queue_send_data(ONLINESHOP, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:      update_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        更新数据库
***************************************************************************************/
void Onlineshop::update_db()
{
    char chpMac[18] = {0};
    COMMON_UPDATE_T tmp_update;
    memset(&tmp_update, 0, sizeof(COMMON_UPDATE_T));
    
    struct in_addr addr;
    addr.s_addr =  m_request_packet.saddr;
    tmp_update.clueid = get_clue_id(m_request_packet.src_mac, inet_ntoa(addr));
    
    //更新数据库
    if (m_shop_type == DANGDANG || m_shop_type == GUOMEI)
    {    
        sprintf(tmp_update.update_sql, "update ONLINE_SHOP set ordernumber='%s' where orderid='%s' and type=%d", m_order_number.c_str(), m_sign_id.c_str(), m_shop_type);      
    }
    else if(m_shop_type == SUNING)
    {
        sprintf(tmp_update.update_sql, "update ONLINE_SHOP set ordernumber='%s',account='%s' where orderid='%s' and type=%d",\
                m_order_number.c_str(), m_shopping_account, m_sign_id.c_str(), m_shop_type);     
    }
    
    msg_queue_send_data(COMMON_UPDATE, (void *)&tmp_update, sizeof(tmp_update));
}

/***************************************************************************************
Function Name:      realease_data
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        释放类成员指针变量所指向的空间
****************************************************************************************/
void Onlineshop::realease_data()
{
    if(m_shopping_account)
    {
        free(m_shopping_account);
        m_shopping_account = NULL;
    }
    
    if(m_shopper)
    {
        free(m_shopper);
        m_shopper = NULL;
    }

    if(m_shop_addr)
    {
        free(m_shop_addr);
        m_shop_addr = NULL;
    }
}

/**********************************************************************************************
Function Name:      get_guomei_person_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取国美在线的个人信息
***********************************************************************************************/
int Onlineshop::get_guomei_person_info(bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    
    if (!is_from_server)
    {
        if (!getCookie(m_request_packet.header, m_request_packet.headerLen))
            return -1;
    
        p1 = strstr((char*)m_cookie.c_str(), "DSESSIONID=");
        if (p1)
        {
            p1 += strlen("DSESSIONID=");
            for(p2 = p1; *p2 != ';'; p2++);
            m_sign_id.assign(p1, 0, p2-p1);
        }
    }
    else
    {
        char buffer[300] = {0};
        char *p3 = NULL, *p4 = NULL;
        int len = 0;
        
        p1 = strstr(m_response_packet.body, "\"uda\":");
        if(p1)
        {
            p3 = strstr(p1, "\"stateName\":\"");
            if (p3)
            {
                p3 += strlen("\"stateName\":\"");
                p4 = strstr(p3, "\",");
                strncpy(buffer, p3, p4 - p3);
            }

            p3 = strstr(p1, "\"cityName\":\"");
            if (p3)
            {
                p3 += strlen("\"cityName\":\"");
                p4 = strstr(p3, "\",");
                strncat(buffer, p3, p4 - p3);
            }

            p3 = strstr(p1, "\"countyName\":\"");
            if (p3)
            {
                p3 += strlen("\"countyName\":\"");
                p4 = strstr(p3,  "\",");
                strncat(buffer, p3, p4 - p3);
            }

            p3 = strstr(p1, "\"townName\":\"");
            if (p3)
            {
                p3 += strlen("\"townName\":\"");
                p4 = strstr(p3,  "\",");
                strncat(buffer, p3, p4 - p3);
            }

            p3 = strstr(p1, "\"address\":\"");
            if (p3)
            {
                p3 += strlen("\"address\":\"");
                p4 = strstr(p3,  "\"},");
                strncat(buffer, p3, p4 - p3);
            }

            len = strlen(buffer);
            m_shop_addr = (char*)malloc(len * 4);
            if (!m_shop_addr)
            {
                return -1;
            }

            memset(m_shop_addr, 0, len * 4);
            url_decode(buffer, len, m_shop_addr, len*4);   
        }
        else
        {
            return -1;
        }

        memset(buffer, 0, 300);
        len = 0;
        
        p1 = strstr(m_response_packet.body, "\"uds\":");
        if (p1)
        {
            p3 = strstr(p1, "\"sname\":\"");
            if(p3)
            {
                p3 += strlen("\"sname\":\"");
                p4 = strstr(p3, "\",");
                strncpy(buffer, p3, p4 - p3);
                len = strlen(buffer);
                m_shopper = (char*)malloc(len * 4);
                memset(m_shopper, 0, len * 4);
                url_decode(buffer, len, m_shopper, len*4);   
            }

            p3 = strstr(p1, "\"phone\":\"");
            if (p3)
            {
                p3 += strlen("\"phone\":\"");
                p4 = strstr(p3, "\",");
                m_telephone_number.assign(p3, 0, p4 - p3);
            }
        }
        else
        {
            return -1;
        }

        memset(buffer, 0, 300);
        len = 0;
        p1 = strstr(m_response_packet.body, "\"headTypes\":[");
        if (p1)
        {
            p3 = strstr(p1, "\"content\":\"");
            p3 += strlen("\"content\":\"");
            p4 = strstr(p3, "\",");
            memcpy(buffer, p3, (p4 - p3)>299?299:(p4 - p3));
            len = strlen(buffer);
            m_shopping_account = (char*)malloc(len * 4);
            if(!m_shopping_account)
                return -1;

            memset(m_shopping_account, 0, len * 4);
            url_decode(buffer, len, m_shopping_account, len * 4);   
        }
        else
        {
            return -1;
        }
		
        store_db();
        return 1;
    }

    return 0;
}

/**********************************************************************************************
Function Name:      get_guomei_order_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取国美在线的订单信息
***********************************************************************************************/
int Onlineshop::get_guomei_order_info(bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;

    if (!is_from_server)
    {
        p1 = m_request_packet.header + 35;
        for (p2 = p1; *p2 != '&'; p2++);
        
        m_order_number.assign(p1, 0 , p2 - p1);

        if (!getCookie(m_request_packet.header, m_request_packet.headerLen))
            return -1;
        
        p1 = strstr((char*)m_cookie.c_str(), "DSESSIONID=");
        if (p1)
        {
            p1 += strlen("DSESSIONID=");
            for(p2 = p1; *p2 != ';'; p2++);
            m_sign_id.assign(p1, 0, p2 - p1);
        }
        else
        {
            return -1;
        }
    
        update_db();
        return 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/***************************************************************************************
Function Name:      analysis_guomei
Input Parameters:   opertype, is_from_server
Output Parameters:  void
Return Code:        -1:失败,0:数据处理成功，但还不完全,1:数据处理成功且全部处理完成
Description:        解析国美相应的数据
****************************************************************************************/
int Onlineshop::analysis_guomei(unsigned short opertype, bool is_from_server)
{
    int ret = -1;

    switch (opertype)
    {
        case 0x01:
            ret = get_guomei_person_info(is_from_server);
            break;

        case 0x02:
            ret = get_guomei_order_info(is_from_server);
            break;
    }

    return ret;
}

/**********************************************************************************************
Function Name:      get_dangdang_person_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取当当网的个人信息
***********************************************************************************************/
int Onlineshop::get_dangdang_person_info(bool is_from_server)
{
    char buffer[300] = {0};
    int len = 0;
    char *p1 =  NULL, *p2 = NULL;

    if (!is_from_server)
    {  
        if (!getCookie(m_request_packet.header, m_request_packet.headerLen))
            return -1;
            
        p1 = strstr((char*)m_cookie.c_str(), "permanent_id=");
        if (p1)
        {
            p1 += strlen("permanent_id=");
            for(p2 = p1; *p2 != ';'; p2++);
            m_sign_id.assign(p1, 0, p2-p1);
        }

        p1 = strstr((char*)m_cookie.c_str(), "uname=");
        if (p1)
        {
            p1 += strlen("uname=");
            for(p2 = p1; *p2 != '&'; p2++);
            memcpy(buffer, p1, (p2-p1) < 299 ? (p2-p1):299);
            len = strlen(buffer);
            m_shopping_account = (char*)malloc(len * 4);
            if(!m_shopping_account)
            {
                return -1;
            }
            memset(m_shopping_account, 0, len * 4);
            url_decode(buffer, len, m_shopping_account, len * 4);
        }

        memset(buffer, 0, 300);
        p1 = strstr(m_request_packet.body, "ship_name=");
        if(p1)
        {
            p1 += strlen("ship_name=");
            for(p2 = p1; *p2 != '&'; p2++);
            memcpy(buffer, p1, (p2 - p1) < 299 ? (p2-p1):299);
            len = strlen(buffer);
            m_shopper = (char*)malloc(len * 4);
            if(!m_shopper)
            {
                return -1;
            }
            memset(m_shopper, 0, len * 4);
            url_decode(buffer, len, m_shopper, len * 4);
        }

        memset(buffer, 0, 300);
        p1 = strstr(m_request_packet.body, "ship_mb=");
        if(p1)
        {
            p1 += strlen("ship_mb=");
            for(p2 = p1; *p2 != '&'; p2++);
            m_telephone_number.assign(p1, 0, p2 - p1);
        }

        //get shop address
        p1 = strstr(m_request_packet.body, "ship_address=");
        if(p1)
        {
            p1 += strlen("ship_address=");
            for(p2 = p1; *p2 != '&'; p2++);
            strncpy(buffer, p1, p2 - p1);
            strcat(buffer, " ");  
        }

        //append shop address
        p1 = strstr(m_request_packet.body, "ship_zip=");
        if (p1)
        {
           p1 += strlen("ship_zip=");
            for(p2 = p1; *p2 != '&'; p2++);
            if((p2 - p1) > 0)
            {
                strncat(buffer, p1, p2 - p1);
            }
            
            len = strlen(buffer);
            m_shop_addr = (char*)malloc(len * 4);
            if(!m_shop_addr)
            {
                return -1;
            }
            memset(m_shop_addr, 0, len * 4);
            url_decode(buffer, len, m_shop_addr, len * 4);
        }

        store_db();
        return 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**********************************************************************************************
Function Name:      get_dangdang_order_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取当当网的订单信息
***********************************************************************************************/
int Onlineshop::get_dangdang_order_info(bool is_from_server)
{
    char *p1 =  NULL, *p2 = NULL;

    if (!is_from_server)
    { 
        if (!getCookie(m_request_packet.header, m_request_packet.headerLen))
            return -1;
    
        p1 = strstr((char*)m_cookie.c_str(), "permanent_id=");
        if (p1)
        {
            p1 += strlen("permanent_id=");
            for(p2 = p1; *p2 != ';'; p2++);
            m_sign_id.assign(p1, 0, p2 - p1);
        }
        else
        {
            return -1;
        }

        p1 = strstr(m_request_packet.header, "grand_order_id=");
        if (p1)
        {
            p1 += strlen("grand_order_id=");
            for (p2 = p1; *p2 != '&'; p2++);
            m_order_number.assign(p1, 0, p2 - p1);
        }
        else
        {
            return -1;
        }
        
        update_db();
        return 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**********************************************************************************************
Function Name:      analysis_dangdang
Input Parameters:   opertype
Output Parameters:  void
Return Code:        -1:失败,1:成功
Description:        解析当当网相应的数据
***********************************************************************************************/
int Onlineshop::analysis_dangdang(unsigned short opertype, bool is_from_server)
{
    int ret = -1;

    switch (opertype)
    {
        case 0x01:
            ret = get_dangdang_person_info(is_from_server);
            break;

        case 0x02:
            ret = get_dangdang_order_info(is_from_server);
            break;
    }

    return ret;
}

/**********************************************************************************************
Function Name:      get_suning_person_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取苏宁易购的个人信息
***********************************************************************************************/
int Onlineshop::get_suning_person_info(bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    int len = 0;

    if (!is_from_server)
    {
        char buffer[512] = {0};
        p1 = strstr(m_request_packet.body, "cart2No=");
        if(p1)
        {
            p1 += strlen("cart2No=");
            for(p2 = p1; *p2 != '&'; p2++);
            m_sign_id.assign(p1, 0, p2 - p1);
        }

        p1 = strstr(m_request_packet.body, "receiverName=");
        if(p1)
        {
            p1 += strlen("receiverName=");
            for(p2 = p1; *p2 != '&'; p2++);  
            strncpy(buffer, p1, p2 - p1);
        }

        len = strlen(buffer);
        m_shopper = (char*)malloc(len * 4);
        memset(m_shopper, 0, len * 4);
        url_decode(buffer, len, m_shopper, len * 4);

        memset(buffer, 0, 512);
        p1 = strstr(m_request_packet.body, "receiverMobile=");
        if(p1)
        {
            p1 += strlen("receiverMobile=");
            for(p2 = p1; *p2 != '&'; p2++);
            m_telephone_number.assign(p1, 0, p2 - p1);
        }

        p1 = strstr(m_request_packet.body, "address1=");
        if(p1)
        {
            p1 += strlen("address1=");
            for(p2 = p1; *p2 != '&'; p2++);
            strncpy(buffer, p1, p2 - p1);
        }

        p1 = strstr(m_request_packet.body, "address2=");
        if(p1)
        {
            p1 += strlen("address2=");
            for(p2 = p1; *p2 != '&'; p2++);
            strncat(buffer, p1, p2 - p1);
        }

        len = strlen(buffer);
        m_shop_addr = (char*)malloc(len * 4);
        if(!m_shop_addr)
            return -1;
        
        memset(m_shop_addr, 0, len * 4);
        url_decode(buffer, len, m_shop_addr, len * 4);
        store_db();
        return 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**********************************************************************************************
Function Name:      get_suning_order_info
Input Parameters:   is_from_server
Output Parameters:  void
Return Code:        -1:失败, 0:成功，但处理不完全，1:成功，处理完全
Description:        获取苏宁易购的订单信息
***********************************************************************************************/
int Onlineshop::get_suning_order_info(bool is_from_server)
{
    char *p1 = NULL, *p2 = NULL;
    int len = 0;

    if (!is_from_server)
    {
        char buf[100] = {0};
        p1 = strstr(m_request_packet.header, "loginUserName=");
        if(p1)
        {
            p1 += strlen("loginUserName=");
            for(p2 = p1; *p2 != '&'; p2++);
            
            memcpy(buf, p1, (p2 - p1)>99?99:(p2 - p1));
            len = strlen(buf);
            m_shopping_account = (char*)malloc(len * 4);
            memset(m_shopping_account, 0, len * 4);
            url_decode(buf, len, m_shopping_account, len * 4);
        }
        else
        {
            return -1;
        }

        p1 = strstr(m_request_packet.header, "orderId=");
        if(p1)
        {
            p1 += strlen("orderId=");
            for(p2 = p1; *p2 != '&'; p2++);
            m_order_number.assign(p1, 0, p2 - p1);
        }
        else
        {
            return -1;
        }

        p1 = strstr(m_request_packet.header, "cart2No=");
        if(p1)
        {
            p1 += strlen("cart2No=");
            p2 = strstr(p1, "\r\n");
            m_sign_id.assign(p1, 0, p2 - p1);
        }
        else
        {
            return -1;
        }
        update_db();
        return 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**************************************************************************************
Function Name:      analysis_suning
Input Parameters:   opertype
Output Parameters:  void
Return Code:        -1:失败,1:成功
Description:        解析苏宁相应的数据
**************************************************************************************/
int Onlineshop::analysis_suning(unsigned short opertype, bool is_from_server)
{
    int ret = -1;

    switch (opertype)
    {
        case 0x01:
            ret = get_suning_person_info(is_from_server);
            break;

        case 0x02:
            ret = get_suning_order_info(is_from_server);
            break;
    }

    return ret;
}

/***************************************************************************************
Function Name:      do_analysis
Input Parameters:   packet, type, is_from_server
    type:       解析子模块的编号
Output Parameters:  void
Return Code:        -1:失败,0:成功
Description:        解析模块的总函数
***************************************************************************************/
int Onlineshop::do_analysis(PacketInfo* packet, unsigned short type, bool is_from_server)
{
    int ret = -1;
    unsigned short type1 = 0, type2 = 0;
    
    //type1 表示哪个平台，type2 表示哪种行为类型的包
    type1 = (type >> 8) & 0x00ff;
    type2 = type & 0x00ff; 
    m_shop_type = type1 + ONLINESHOPCLASS;

    switch (m_shop_type)
    {
        case DANGDANG:
            ret = analysis_dangdang(type2, is_from_server);
            break;
    
        case SUNING:
            ret = analysis_suning(type2, is_from_server);
            break;
    
        case GUOMEI:
            ret = analysis_guomei(type2, is_from_server);
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
Description:            购物模块解析的入口函数
**************************************************************************************/
int Onlineshop::deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    
    if (!is_from_server)
    {   
        ret = rebuilt_packet(&m_request_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_request_packet, packet);
            ret = do_analysis(packet, type, is_from_server);
        }
    }
    else
    {
        ret = rebuilt_packet(&m_response_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_response_packet, packet);
            ret = do_analysis(packet, type, is_from_server);
        }
    }

    return ret;
}

