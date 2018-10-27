/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : app_location.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing app location
*
* Evolution( Date | Author | Description ) 
* 2017.09.26 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <string.h>
#include <arpa/inet.h>

#include "Analyzer_log.h"
#include "app_location.h"
#include "db_data.h"
#include "clue_c.h"

Location::Location()
{
    m_lat = "";
    m_lon = "";
}

Location::~Location()
{
    
}


void Location::update_db()
{
    
}

/**************************************************************************************
Function Name:      update_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        存数据库
***************************************************************************************/
void Location::store_db(int map_type)
{
    struct in_addr addr;
    APPLOCATION_T tmp_data;

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

    strcpy(tmp_data.lat, m_lat.c_str());
    strcpy(tmp_data.lon, m_lon.c_str());
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = map_type;
    msg_queue_send_data(APPLOCATION, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:      analyse_gaode
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_gaode(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(!is_from_server)
            return 0;

        data = m_response_packet.body;
        p1 = strstr(data, "<cenx>");
        if(!p1)
            return -1;
      
        p1 += strlen("<cenx>");
        p2 = strstr(p1, "</cenx>");
        if(!p2)
            return -1;
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "<ceny>");
        if(!p1)
            return -1;

        p1 += strlen("<ceny>");
        p2 = strstr(p1, "</ceny>");
        if(!p2)
            return -1;
        
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GPS);
        
        return 1;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      analyse_meituan
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_meituan(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL, *data_bak = NULL;

    if(0x01 == type)
    {
        if(!is_from_server)
            return 0;
       
        data = m_request_packet.body;
        data_bak = (char*)malloc(m_request_packet.bodyLen* 2);
        if(!data_bak)
        {
            printf("data_bak malloc fail\n");
            return -1;
        }
        memset(data_bak, 0, m_request_packet.bodyLen * 2);
        
        url_decode(data, m_request_packet.bodyLen, data_bak, m_request_packet.bodyLen * 2);

        p1 = strstr(data_bak, "\"lng\":");
        if(!p1)
        {
            free(data_bak);
            return -1;
        }
        
        p1 += strlen("\"lng\":");
        p2 = strchr(p1, '.');
        if(!p2)
        {
            free(data_bak);
            return -1;
        }
        
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data_bak, "\"lat\":");
        if(!p1)
        {
           free(data_bak);
           return -1;
        }
        p1 += strlen("\"lat\":");
        p2 = strchr(p1, '.');
        if(!p2)
        {
            free(data_bak);
            return -1;
        }
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lat.assign(p1, p2 - p1);
        free(data_bak);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_yilongtravel
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_yilongtravel(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "Longitude:");
        if(!p1)
            return -1;

        p1 += strlen("Longitude: ");
        p2 = strstr(p1, "\r\n");
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "Latitude:");
        if(!p1)
            return -1;

        p1 += strlen("Latitude: ");
        p2 = strstr(p1, "\r\n");
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_BD09);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_hellobike_momo
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_hellobike_momo(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type || 0x02 == type)
    {
        if(is_from_server)
            return 0;
        
        if(0x01 == type)
        {
            data = m_request_packet.body;
        }
        else if(0x02 == type)
        {
            data = m_request_packet.header;
        }
        p1 = strstr(data, "location=");
        if(!p1)
            return -1;

        p1 += strlen("location=");
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;

        m_lon.assign(p1, p2 - p1);
        p1 = p2 + 1;
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      analyse_aiwujiwu
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_aiwujiwu(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        p1 = strstr(data, "\"device_gps\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"device_gps\":\"");
        if(!strncmp(p1, "unknown", 7))
            return -1;
        
        p2 = strchr(p1, '|');
        m_lat.assign(p1, p2 - p1);

        p1 = p2 + 1;
        p2 = strchr(p1, '\"');
        if(!p2)
            return -1;

        m_lon.assign(p1, p2 - p1);
        store_db(MAP_GPS);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_weixin
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_weixin(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "center=");
        if(!p1)
            return -1;

        p1 += strlen("center=");
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;

        m_lon.assign(p1, p2 - p1);

        p1 = p2 + 1;
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_xiaomistore
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_xiaomistore(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        p1 = strstr(data, "lng=");
        if(!p1)
            return -1;

        p1 += strlen("lng=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat=");
        if(!p1)
            return -1;

        p1 += strlen("lat=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_BD09);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_baiduvideo
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_baiduvideo(unsigned short type, bool is_from_server)
{    
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(!is_from_server)
            return 0;

        data = m_response_packet.body;
        p1 = strstr(data, "\"x\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"x\":\"");
        p2 = strchr(p1, '\"');
        if(!p2)
            return -1;

        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "\"y\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"y\":\"");
        p2 = strchr(p1, '\"');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_dazhongcomment
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        
***************************************************************************************/
int Location::analyse_dazhongcomment(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;
        
        data = m_request_packet.header;
        p1 = strstr(data, "lng=");
        if(!p1)
            return -1;

        p1 += strlen("lng=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat=");
        if(!p1)
            return -1;

        p1 += strlen("lat=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_tencent_new
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取腾讯新闻的坐标
***************************************************************************************/
int Location::analyse_tencent_news(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        p1 = strstr(data, "lon=");
        if(!p1)
            return -1;

        p1 += strlen("lon=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat=");
        if(!p1)
            return -1;

        p1 += strlen("lat=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_kuwo_music
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取酷我音乐的坐标
***************************************************************************************/
int Location::analyse_kuwo_music(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "longtitude=");
        if(!p1)
            return -1;

        p1 += strlen("longtitude=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "latitude=");
        if(!p1)
            return -1;

        p1 += strlen("latitude=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_souhu_video
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取搜狐视频的坐标
***************************************************************************************/
int Location::analyse_souhu_video(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "longitude=");
        if(!p1)
            return -1;

        p1 += strlen("longitude=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "latitude=");
        if(!p1)
            return -1;

        p1 += strlen("latitude=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GPS);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_souhu_video
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取搜狐视频的坐标
***************************************************************************************/
int Location::analyse_letv(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        p1 = strstr(data, "longitude=");
        if(!p1)
            return -1;

        p1 += strlen("longitude=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "latitude=");
        if(!p1)
            return -1;

        p1 += strlen("latitude=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_souhu_news
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取搜狐新闻的坐标
***************************************************************************************/
int Location::analyse_souhu_news(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type || 0x02 == type)
    {
        if(!is_from_server)
            return 0;

        data = m_response_packet.body;
        p1 = strstr(data, "\"y\":");
        if(!p1)
            return -1;

        p1 += strlen("\"y\":");
        
        p2 = strchr(p1, '.');
        if(!p2)
           return -1;
           
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lat.assign(p1, p2 - p1);
        
        p1 = strstr(data, "\"x\":");
        if(!p1)
            return -1;

        p1 += strlen("\"x\":");
        p2 = strchr(p1, '.');
        if(!p2)
           return -1;
           
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lon.assign(p1, p2 - p1);
        store_db(MAP_GPS);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_shijijiayuan
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取世纪佳缘的坐标
***************************************************************************************/
int Location::analyse_shijijiayuan(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL, *data_bak = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        data_bak = (char*)malloc(strlen(data) * 4);
        if(!data_bak)
        {
            printf("data_bak malloc fail\n");
            return -1;
        }
        memset(data_bak, 0, strlen(data) * 4);
        
        url_decode(data, strlen(data), data_bak, strlen(data) * 4);
        p1 = strstr(data_bak, "\"lat\":");
        if(!p1)
        {
            free(data_bak);
            return -1;
        }
        p1 += strlen("\"lat\":");
        p2 = strchr(p1, '.');
        if(!p2)
        {
           free(data_bak);
           return -1;
        }  
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }

        m_lat.assign(p1, p2 - p1);
        p1 = strstr(data_bak, "\"lng\":");
        if(!p1)
           return -1;
        p1 += strlen("\"lng\":");
        p2 = strchr(p1, '.');
        if(!p2)
        {
           free(data_bak);
           return -1;
        }   
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);

        free(data_bak);
        store_db(MAP_BD09);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_shijijiayuan
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取世纪佳缘的坐标
***************************************************************************************/
int Location::analyse_moji_weather(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.body;
        p1 = strstr(data, "\"lon\":");
        if(!p1)
            return -1;

        p1 += strlen("\"lon\":");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;
			
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "\"lat\":");
        if(!p1)
            return -1;

        p1 += strlen("\"lat\":");
        p2 = strchr(p1, '.');
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
		
        if(!p2)
            return -1;

        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_360_browser
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取360浏览器的坐标
***************************************************************************************/
int Location::analyse_360_browser(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(!is_from_server)
            return 0;

        data = m_response_packet.body;
        p1 = strstr(data, "\"location\":[");
        if(!p1)
            return -1;
      
        p1 += strlen("\"location\":[");
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;
        m_lat.assign(p1, p2 - p1);

        p1 = p2 + 1;
        if(!p1)
            return -1;

        p2 = strchr(p1, ']');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);
        store_db(MAP_GPS);
        
        return 1;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      analyse_huangli_weather
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取黄历天气的坐标
***************************************************************************************/
int Location::analyse_huangli_weather(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "point=");
        if(!p1)
            return -1;
      
        p1 += strlen("point=");
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;
        m_lat.assign(p1, p2 - p1);

        p1 = p2 + 1;
  
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      analyse_go_weather
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取go天气的坐标
***************************************************************************************/
int Location::analyse_go_weather(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(!is_from_server)
            return 0;

        data = m_response_packet.body;
        p1 = strstr(data, "\"latlng\":\"");
        if(!p1)
            return -1;
      
        p1 += strlen("\"latlng\":\"");
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;
        m_lat.assign(p1, p2 - p1);

        p1 = p2 + 1;
  
        p2 = strchr(p1, ',');
        if(!p2)
            return -1;
        
        m_lon.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      analyse_tianqitong
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取天气通的坐标
***************************************************************************************/
int Location::analyse_tianqitong(unsigned short type, bool is_from_server)
{ 
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "lon=");
        if(!p1)
            return -1;

        p1 += strlen("lon=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat=");
        if(!p1)
            return -1;

        p1 += strlen("lat=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_58tongcheng
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取58同城的坐标
***************************************************************************************/
int Location::analyse_58tongcheng(unsigned short type, bool is_from_server)
{ 
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "lon: ");
        if(!p1)
            return -1;

        p1 += strlen("lon ");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat: ");
        if(!p1)
            return -1;

        p1 += strlen("lat: ");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_BD09);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_sohunews
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取凤凰新闻的坐标
***************************************************************************************/
int Location::analyse_ifengnews(unsigned short type, bool is_from_server)
{ 
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "dln=");
        if(!p1)
            return -1;

        p1 += strlen("dln=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "dlt=");
        if(!p1)
            return -1;

        p1 += strlen("dlt=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_BD09);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_sinanews
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取新浪新闻的坐标
***************************************************************************************/
int Location::analyse_sinanews(unsigned short type, bool is_from_server)
{
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL, *data_bak = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;
       
        data = m_request_packet.header;
        data_bak = (char*)malloc(m_request_packet.headerLen* 2);
        if(!data_bak)
        {
            printf("data_bak malloc fail\n");
            return -1;
        }
        memset(data_bak, 0, m_request_packet.headerLen * 2);
        
        url_decode(data, m_request_packet.headerLen, data_bak, m_request_packet.headerLen * 2);

        p1 = strstr(data_bak, "location=");
        if(!p1)
        {
            free(data_bak);
            return -1;
        }
        p1 += strlen("location=");
        p2 = strchr(p1, '.');
        if(!p2)
        {
            free(data_bak);
            return -1;
        }
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lat.assign(p1, p2 - p1);

        p1 = p2 + 1;
        
        p2 = strchr(p1, '.');
        if(!p2)
        {
            free(data_bak);
            return -1;
        }
        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);
        free(data_bak);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:      analyse_youku
Input Parameters:   type, is_from_server
Output Parameters:  void
Return Code:        int
Description:        获取优酷视频的坐标
***************************************************************************************/
int Location::analyse_youku(unsigned short type, bool is_from_server)
{ 
    char* p1 = NULL, *p2 = NULL;
    char* data = NULL;

    if(0x01 == type)
    {
        if(is_from_server)
            return 0;

        data = m_request_packet.header;
        p1 = strstr(data, "lot=");
        if(!p1)
            return -1;

        p1 += strlen("lot=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lon.assign(p1, p2 - p1);

        p1 = strstr(data, "lat=");
        if(!p1)
            return -1;

        p1 += strlen("lat=");
        p2 = strchr(p1, '.');
        if(!p2)
            return -1;

        p2 += 1;
        while(*p2 >= '0' && *p2 <='9')
        {
            p2++;
        }
        
        m_lat.assign(p1, p2 - p1);
        store_db(MAP_GCJ02);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_location
Input Parameters:       type,packet
    type:               平台的类型
    is_from_server      数据包的方向
Output Parameters:      void
Return Code:            -1:失败,0:解析没有完成,1:解析成功
Description:            解析app定位模块
**************************************************************************************/
int Location::analyse_location(unsigned short type, bool is_from_server)
{
    int ret = -1;
    unsigned short type1 = 0, type2 = 0;
    
    //type1 表示哪个平台，type2 表示哪种行为类型的包
    type1 = (type >> 8) & 0x00ff;
    type2 = type & 0x00ff; 

    switch(type1)
    {
        case A_GAODE:
            ret = analyse_gaode(type2, is_from_server);
            break;
            
        case A_MEITUAN:
        case A_MEITUAN_WAIMAI:
        case A_WANNENGKEY:
            ret = analyse_meituan(type2, is_from_server);
            break;
     
        case A_YILONGTRAVEL:
            ret = analyse_yilongtravel(type2, is_from_server);
            break;
            
        case A_HELLOBIKE:
        case A_MOMO:
            ret = analyse_hellobike_momo(type2, is_from_server);
            break;
            
        case A_AIWUJIWU:
            ret = analyse_aiwujiwu(type2, is_from_server);
            break;
            
        case A_WEIXIN:
        case A_QQLITE:
            ret = analyse_weixin(type2, is_from_server);
            break;
                   
        case A_XIAOMISTORE:
            ret = analyse_xiaomistore(type2, is_from_server);
            break;
            
        case A_BAIDUVIDEO:
            ret = analyse_baiduvideo(type2, is_from_server);
            break;
            
        case A_DAZHONGDIANPIN:
        case A_YY:
        case A_LIEBAO_BROWSER:
            ret = analyse_dazhongcomment(type2, is_from_server);
            break;

        case A_TENCENT_NEWS:
            ret = analyse_tencent_news(type2, is_from_server);
            break;

        case A_KUWO_MUSIC:
            ret = analyse_kuwo_music(type2, is_from_server);
            break;

        case A_SOUHU_VIDEO:
            ret = analyse_souhu_video(type2, is_from_server);
            break;
            
        case A_LETV:
            ret = analyse_letv(type2, is_from_server);
            break;

        case A_SOUHU_NEWS:
            ret = analyse_souhu_news(type2, is_from_server);
            break;

        case A_SHIJIJIAYUAN:
            ret = analyse_shijijiayuan(type2, is_from_server);
            break;

        case A_MIJIWEATHER:
            ret = analyse_moji_weather(type2, is_from_server);
            break;

        case A_360_BROWSER:
            ret = analyse_360_browser(type2, is_from_server);
            break;
                
        case A_HUANGLI_WEATHER:
            ret = analyse_huangli_weather(type2, is_from_server);
            break;

        case A_GO_WEATHER:
            ret = analyse_go_weather(type2, is_from_server);
            break;

        case A_XIECHENGTRAVEL:
        case A_TIANQITONG:
        case A_ZHWNL:
            ret = analyse_tianqitong(type2, is_from_server);
            break;
            
        case A_IFENG_NEWS:
            ret = analyse_ifengnews(type2, is_from_server);
            break;
            
        case A_TONGCHENG_58:
            ret = analyse_58tongcheng(type2, is_from_server);
            break;

        case A_SINANEWS:
        case A_SOUGOUSEARCH:
            ret = analyse_sinanews(type2, is_from_server);
            break;

        case A_YOUKUVIDEO:
            ret = analyse_youku(type2, is_from_server);
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
Description:            app定位模块解析的入口函数
**************************************************************************************/
int Location::deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    
    if (!is_from_server)
    {   
        ret = rebuilt_packet(&m_request_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_request_packet, packet);
            ret = analyse_location(type, is_from_server);
        }
    }
    else
    {
        ret = rebuilt_packet(&m_response_packet, packet->body, packet->bodyLen);
        if (ret == 1)
        {
            set_packet_base_info(&m_response_packet, packet);
            ret = analyse_location(type, is_from_server);
        }
    }

    return ret;
}

