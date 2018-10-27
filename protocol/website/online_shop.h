/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : online_shop.h
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

#ifndef SHOP_H
#define SHOP_H

#include <iostream>

#include "website_base.h"
enum
{
    ONLINESHOPCLASS = 2100,
    DANGDANG,
    SUNING,
    GUOMEI,
};

class Onlineshop : public website_base
{
private:
    std::string m_order_number;
    std::string m_telephone_number;
    std::string m_sign_id;
    char* m_shopping_account;
    char* m_shopper;
    char* m_shop_addr;
    unsigned short m_shop_type;
    std::string m_cookie;
    
private:
    int getCookie(char* data, int datalen);
    void realease_data();
    int do_analysis(PacketInfo* packet, unsigned short type, bool is_from_server);  //is_from_server -- true: from server to client, false: from client to server

    int get_guomei_person_info(bool is_from_server);
    int get_guomei_order_info(bool is_from_server);
    int get_dangdang_person_info(bool is_from_server);
    int get_dangdang_order_info(bool is_from_server);
    int get_suning_person_info(bool is_from_server);
    int get_suning_order_info(bool is_from_server);
    
    int analysis_dangdang(unsigned short opertype, bool is_from_server);
    int analysis_suning(unsigned short opertype, bool is_from_server);
    int analysis_guomei(unsigned short opertype, bool is_from_server);
    void store_db();
    void update_db(); 
    
public:
    Onlineshop();
    ~Onlineshop();
    int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server);
};

#endif  /*SHOP_H*/
