/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : airline.h
*
* Module : libanalyzeServer.so
*
* Description:  the file for analyzing airline website
*  
* Evolution( Date | Author | Description ) 
* 2017.05.26 | zhangzm | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#ifndef _AIRLINE_H_
#define _AIRLINE_H_

#include <map>
#include <string>

#include "website_base.h"
#include "../PacketParser.h"

using namespace std;

#define AIRLINE_TYPE 2200

enum
{
    CTRIP_AIRLINE = 0x01,
    SZX_AIRLINE
};

typedef struct passenger_info
{
    string       name;
    //unsigned int certType;
    string       certNo;
}passenger_info_t;

class airline : public website_base
{
private:

    string m_origin_city;
    string m_dest_city;

    string m_origin_airport;
    string m_dest_airport;

    string m_begin_time;
    string m_end_time;

    //string m_air_company;
    string m_flightNO;

    unsigned int m_order_time;
    string m_contact_name;
    string m_contact_mobile_phone;
    string m_contact_mail;
    string m_contact_telephone;

    unsigned int m_passenger_count;
    struct passenger_info *m_passenger;

    string m_orderid;

    unsigned short m_type;   // protocol type

private:

    void store_db();
    void update_db();

    int get_szx_passengers_info(const char *json_data);
    int szx_post_process(bool is_from_server);
    int szx_get_process(bool is_from_server);

    int get_ctrip_passengers_info(const char *json_data);    
    int ctrip_post_process(bool is_from_server);
    int ctrip_get_process(bool is_from_server);
    
    int deal_ctrip_data(unsigned short action_type, bool is_from_server);
    int deal_szx_data(unsigned short action_type, bool is_from_server);
    
    int analyse_airline_data(unsigned short type, bool is_from_server);
    
public:
    
    airline();
    ~airline();

    int deal_packet_process(unsigned short type, struct PacketInfo* pktinfo, bool is_from_server);
};

#endif  /*_AIRLINE_H_*/


