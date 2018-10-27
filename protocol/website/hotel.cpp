/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : hotel.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing travel-hotel
*
* Evolution( Date | Author | Description ) 
* 2017.06.19 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <stdlib.h>
#include <string>
#include <arpa/inet.h>
#include <iconv.h>

#include "hotel.h"
#include "db_data.h"
#include "Analyzer_log.h"
#include "clue_c.h"

/**************************************************************************************
Function Name:         Hotel
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Hotel�Ĺ��캯��,��ʼ��һЩ��Ա����
***************************************************************************************/
Hotel::Hotel()
{
    m_name = "";
    m_number = "";
    m_email = "";
    m_addr = "";
    m_hotelname = "";
    m_intime = 0;
    m_outtime = 0;
    m_type = 0;
}

/**************************************************************************************
Function Name:         ~Hotel
Input Parameters:      void
Output Parameters:     void
Return Code:           void
Description:           Hotel����������,�ͷ�һЩ��Ա����
***************************************************************************************/
Hotel::~Hotel()
{
  
}


/**************************************************************************************
Function Name:      convert_time_format
Input Parameters:   data
    data:������������ַ���
Output Parameters:  void
Return Code:        > 0:�������ʱ���ַ���ת���ɵĵ�ǰ����,-1:����
Description:        �������ʱ���ַ���ת���ɵĵ�ǰ����
***************************************************************************************/
time_t Hotel::convert_time_format(const char *data)
{
    struct tm tm_ptr;
    time_t timeval;
    int result_val = -1;

    if (!data)
    	return -1;

    result_val = sscanf(data, "%04d-%02d-%02d %02d:%02d:%02d", &tm_ptr.tm_year, &tm_ptr.tm_mon, &tm_ptr.tm_mday, &tm_ptr.tm_hour, &tm_ptr.tm_min, &tm_ptr.tm_sec);
    if (result_val != -1)
    {
        tm_ptr.tm_year = tm_ptr.tm_year - 1900;
        tm_ptr.tm_mon = tm_ptr.tm_mon - 1;

        timeval = mktime(&tm_ptr);
    }
    else
    {
        timeval = time(NULL);
    }

    return timeval;
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        �����ݿ�
***************************************************************************************/
void Hotel::store_db()
{
    struct in_addr addr;
    HOTEL_T tmp_data;

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

    strcpy(tmp_data.name, m_name.c_str());
    strcpy(tmp_data.number, m_number.c_str());
    strcpy(tmp_data.email, m_email.c_str());
    strcpy(tmp_data.hotel_addr, m_addr.c_str());
    strcpy(tmp_data.hotel_name, m_hotelname.c_str());
    tmp_data.intime = m_intime;
    tmp_data.outtime = m_outtime;
    
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = m_type;
    
    msg_queue_send_data(HOTEL, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:      update_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        �����ݿ�
***************************************************************************************/
void Hotel::update_db()
{
    
}

/**************************************************************************************
Function Name:          analyse_mangguo
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ����â��������ģ��
**************************************************************************************/
int Hotel::analyse_mangguo(unsigned short type)
{
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL,*addr_buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        p1 = strstr(buff, "linkeManStr=");
        if(p1)
        {
            p1 += strlen("linkeManStr=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_name.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "mobile=");
        if(p1)
        {
            p1 += strlen("mobile=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "email=");
        if(p1)
        {
            p1 += strlen("email=");
            p2 = strchr(p1, '&');
            if(p2 && (p2 - p1) > 0)
            {
                m_email.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "hotelName=");
        if(p1)
        {
            p1 += strlen("hotelName=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_hotelname.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "checkinDate=");
        if(p1)
        {
            p1 += strlen("checkinDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                intime.assign(p1, p2 - p1);
                intime.append(" 12:00:00");
                m_intime = convert_time_format(intime.c_str());
            }
        }

        p1 = strstr(buff, "checkoutDate=");
        if(p1)
        {
            p1 += strlen("checkoutDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                outtime.assign(p1, p2 - p1);
                outtime.append(" 12:00:00");
                m_outtime = convert_time_format(outtime.c_str());
            }
        }

        p1 = strstr(m_request_packet.header, "cityName=");
        if(p1)
        {
            p1 += strlen("cityName=");
            p2 = strchr(p1, ';');
            if(p2)
            {
                addr_buff = (char*)malloc((p2 - p1) * 4);
                if(!addr_buff)
                    return -1;
                memset(addr_buff, 0, (p2 - p1) * 4);
                
                unicode_to_utf8(p1, p2 - p1, addr_buff, (p2 - p1) * 4);
                m_addr.assign(addr_buff);
                free(addr_buff);
            }
        }
       
        store_db();
        free(buff);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_sevenday
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ����7��������ģ��
**************************************************************************************/
int Hotel::analyse_sevenday(unsigned short type)
{
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
			
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        p1 = strstr(buff, "contactName=");
        if(p1)
        {
            p1 += strlen("contactName=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_name.assign(p1, p2 - p1);
            }
                
        }

        p1 = strstr(buff, "contactTel=");
        if(p1)
        {
            p1 += strlen("contactTel=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "checkInDate=");
        if(p1)
        {
            p1 += strlen("checkInDate=");    
            intime.assign(p1, 10);
            m_intime = atol(intime.c_str());
        }

        p1 = strstr(buff, "checkOutDate=");
        if(p1)
        {
            p1 += strlen("checkOutDate=");
            outtime.assign(p1, 10);
            m_outtime = atol(outtime.c_str());
        }
        
        store_db();
        free(buff);

        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_yilong
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ��������������ģ��
**************************************************************************************/
int Hotel::analyse_yilong(unsigned short type)
{
    
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL,*head_buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
			
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        head_buff = (char*)malloc(m_request_packet.headerLen * 4);
        if(!head_buff)
            return -1;
			
        memset(head_buff, 0, m_request_packet.headerLen * 4);
        url_decode(m_request_packet.header, m_request_packet.headerLen, head_buff, m_request_packet.headerLen * 4);
        
        p1 = strstr(buff, "requestModel.hotelContacter.name=");
        if(p1)
        {
            p1 += strlen("requestModel.hotelContacter.name=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_name.assign(p1, p2 - p1);
            }
        }

        p1 =  strstr(buff, "requestModel.hotelContacter.mobileString=");
        if(p1)
        {
            p1 += strlen("requestModel.hotelContacter.mobileString=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "requestModel.hotelContacter.email=");
        if(p1)
        {
            p1 += strlen("requestModel.hotelContacter.email=");
            p2 = strchr(p1, '&');
            if(p2 && (p2 - p1) > 0)
            {
                m_email.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(head_buff, "CityName=");
        if(p1)
        {
            p1 += strlen("CityName=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_addr.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(head_buff, "InDate=");
        if(p1)
        {
            p1 += strlen("InDate=");
            p2 = strchr(p1, ';');
            if(p2)
            {
                intime.assign(p1, p2 - p1);
                intime.append(1, ' ');
            }
        }

        p1 = strstr(buff, "requestModel.timeEarly=");
        if(p1)
        {
            p1 += strlen("requestModel.timeEarly=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                intime.append(p1, p2 - p1);
                intime.append(":00");
                m_intime = convert_time_format(intime.c_str());
            }
        }

        p1 = strstr(head_buff, "OutDate=");
        if(p1)
        {
            p1 += strlen("OutDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                outtime.assign(p1, p2 - p1);
                outtime.append(1, ' ');
            }
        }

        p1 = strstr(buff, "requestModel.timeLater=");
        if(p1)
        {
            p1 += strlen("requestModel.timeLater=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                 outtime.append(p1, p2 - p1);
                 outtime.append(":00");
                 m_outtime = convert_time_format(outtime.c_str());
            }
        }
        
        store_db();
        free(buff);
        free(head_buff);
        
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_xiecheng
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ����Я��������ģ��
**************************************************************************************/
int Hotel::analyse_xiecheng(unsigned short type)
{
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    
    if(0x01 == type)
    {
        
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        p1 = strstr(buff, "MobilePhone=");
        if(p1)
        {
            p1 += strlen("MobilePhone=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                 m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "ContactEmail=");
        if(p1)
        {
            p1 += strlen("ContactEmail=");
            p2 = strchr(p1, '&');
            if(p2 && (p2 - p1) > 0)
            {
                m_email.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "GuestName=");
        if(p1)
        {
            p1 += strlen("GuestName=");
            p2 = strchr(p1, '&');
            if(p2 && (p2 - p1) > 0)
            {
                m_name.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "Arrival=");
        if(p1)
        {
            p1 += strlen("Arrival=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                intime.assign(p1, p2 - p1);
                intime.append(" 12:00:00");
                m_intime = convert_time_format(intime.c_str());
            }
        }

        p1 = strstr(buff, "Departure=");
        if(p1)
        {
            p1 += strlen("Departure=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                outtime.assign(p1, p2 - p1);
                outtime.append(" 12:00:00");
                m_outtime = convert_time_format(outtime.c_str());
            }
        }

        p1 = strstr(m_request_packet.header, "adscityen=");
        if(p1)
        {
            p1 += strlen("adscityen=");
            p2 = strchr(p1, ';');
            if(p2)
            {
                m_addr.assign(p1, p2 - p1);
            }
        }
        
        store_db();
        free(buff);
        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_tongcheng
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ����ͬ��������ģ��
**************************************************************************************/
int Hotel::analyse_tongcheng(unsigned short type)
{
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL,*head_buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    std::string addr_bak = "";
    
    if(0x01 == type)
    {
        
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
			
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        head_buff = (char*)malloc(m_request_packet.headerLen * 4);
        if(!head_buff)
            return -1;
			
        memset(head_buff, 0, m_request_packet.headerLen * 4);
        url_decode(m_request_packet.header, m_request_packet.headerLen, head_buff, m_request_packet.headerLen * 4);
        
        p1 = strstr(buff, "ContactName=");
        if(p1)
        {
            p1 += strlen("ContactName=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_name.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "ContactMobile=");
        if(p1)
        {
            p1 += strlen("ContactMobile=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "ComeDate=");
        if(p1)
        {
            p1 += strlen("ComeDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                intime.assign(p1, p2 - p1);
                intime.append(" 12:00:00");
                m_intime = convert_time_format(intime.c_str());
            }
        }

        p1 = strstr(buff, "LeaveDate=");
        if(p1)
        {
            p1 += strlen("LeaveDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                outtime.assign(p1, p2 - p1);
                outtime.append(" 12:00:00");
                m_outtime = convert_time_format(outtime.c_str());
            }
        }

        //�����ַת����Ҫת����
        p1 = strstr(head_buff, "HotelCityName\":\"");
        if(p1)
        {
            char* tmp_addr = NULL;
            
            p1 += strlen("HotelCityName\":\"");
            p2 = strchr(p1, '\"');
            if(p2)
            {
                addr_bak.assign(p1, p2 - p1);
                tmp_addr = (char*)malloc((p2 - p1) * 4);
                memset(tmp_addr, 0, (p2 - p1) * 4);
                url_decode(addr_bak.c_str(), p2 - p1, tmp_addr, (p2 - p1) * 4);
                m_addr.assign(tmp_addr);
                free(tmp_addr);
            }
        }
            
        free(buff);
        free(head_buff);
        store_db();

        return 1;
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_tuniu
Input Parameters:       type
    type:               ƽ̨������
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            ����;ţ������ģ��
**************************************************************************************/
int Hotel::analyse_tuniu(unsigned short type)
{
    char *p1 = NULL,*p2 = NULL;
    char *buff = NULL;
    std::string intime = "";
    std::string outtime = "";
    
    if(0x01 == type)
    {
        buff = (char*)malloc(m_request_packet.bodyLen * 4);
        if(!buff)
            return -1;
        memset(buff, 0, m_request_packet.bodyLen * 4);
        url_decode(m_request_packet.body, m_request_packet.bodyLen, buff, m_request_packet.bodyLen * 4);

        p1 = strstr(buff, "contactName[]=");
        if(p1)
        {
            p1 += strlen("contactName[]=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_name.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "tel=");
        if(p1)
        {
            p1 += strlen("tel=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_number.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "email=");
        if(p1)
        {
            p1 += strlen("email=");
            p2 = strchr(p1, '&');
            if(p2 && (p2 - p1) > 0)
            {
                m_email.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "hotelName=");
        if(p1)
        {
            p1 += strlen("hotelName=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                m_hotelname.assign(p1, p2 - p1);
            }
        }

        p1 = strstr(buff, "checkInDate=");
        if(p1)
        {
            p1 += strlen("checkInDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                intime.assign(p1, p2 - p1);
                intime.append(" 12:00:00");
                m_intime = convert_time_format(intime.c_str());
            }
        }

        p1 = strstr(buff, "checkOutDate=");
        if(p1)
        {
            p1 += strlen("checkOutDate=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                outtime.assign(p1, p2 - p1);
                outtime.append(" 12:00:00");
                m_outtime = convert_time_format(outtime.c_str());
            }
        }

        store_db();
        free(buff);
    }

    return -1;
}

/**************************************************************************************
Function Name:          analyse_hotel
Input Parameters:       type,packet
    type:               ƽ̨������
    packet:             ���ݰ��ĵ�ַ
Output Parameters:      void
Return Code:            -1:ʧ��,1:�����ɹ�
Description:            �������ģ��
**************************************************************************************/
int Hotel::analyse_hotel(unsigned short type, PacketInfo* packet)
{
    int ret = -1;
    unsigned short type1 = 0, type2 = 0;
    
    type1 = (type >> 8) & 0x00ff;
    type2 = type & 0x00ff; 
    m_type = type1 + HOTELCLASS;

    switch(m_type)
    {
        case TONGCHENG:
            ret = analyse_tongcheng(type2);
            break;

        case XIECHENG:
            ret = analyse_xiecheng(type2);
            break;

        case YILONG:
            ret = analyse_yilong(type2);
            break;

        case SEVENDAT:
            ret = analyse_sevenday(type2);
            break;

        case MANGGUO:
            ret = analyse_mangguo(type2);
            break;

        case TUNIU:
            ret = analyse_tuniu(type2);
            break;
            
        default:
            break;
    }

    return ret;
}

/**************************************************************************************
Function Name:          deal_packet_process
Input Parameters:       type,packet,is_from_server
    type:               ƽ̨������
    packet:             ���ݰ��ĵ�ַ
    is_from_server:     0��ʾ�����,1��ʾ��Ӧ��
Output Parameters:      void
Return Code:            -1:ʧ��,0:���û�����,1:�����ɹ�
Description:            �Ƶ�ģ���������ں���
**************************************************************************************/
int Hotel::deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server)
{
    int ret = -1;
    
    if(!is_from_server)
    {
        ret = rebuilt_packet(&m_request_packet, packet->body, packet->bodyLen);
        if(1 == ret)
        {
            set_packet_base_info(&m_request_packet, packet);
            ret = analyse_hotel(type, packet);
        }
    }
    
    return ret;
}
