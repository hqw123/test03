/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : hotel.h
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

#ifndef HOTEL_H
#define HOTEL_H

#include <iostream>
#include <sys/time.h>
#include <time.h>

#include "website_base.h"

enum
{
    HOTELCLASS = 2400,
    TONGCHENG,
    XIECHENG,
    YILONG,
    SEVENDAT,
    MANGGUO,
    TUNIU,
};

class Hotel : public website_base
{
private:
    std::string m_name;
    std::string m_number;
    std::string m_email;
    std::string m_addr;
    std::string m_hotelname;
    time_t m_intime;
    time_t m_outtime;
    unsigned short m_type;
    
public:
    Hotel();
    ~Hotel();
    int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server);

private:
    time_t convert_time_format(const char *data);
    void store_db();
    void update_db();
    int analyse_hotel(unsigned short type, PacketInfo* packet);
    int analyse_tongcheng(unsigned short type);
    int analyse_xiecheng(unsigned short type);
    int analyse_yilong(unsigned short type);
    int analyse_sevenday(unsigned short type);
    int analyse_mangguo(unsigned short type);
    int analyse_tuniu(unsigned short type);
};

#endif
