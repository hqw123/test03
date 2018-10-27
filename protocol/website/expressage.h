
#ifndef EXPRESSAGE_H
#define EXPRESSAGE_H

#include <iostream>
#include "website_base.h"

enum
{
    EXPRESSAGECLASS = 2300,
    SHENTONG,
    YUANTONG,
    YUNDA,
    EMS,
    SHUNFENG,
};

class Expressage : public website_base
{
private:
    std::string m_recv_number;
    std::string m_send_number;
    std::string m_recv_name;
    std::string m_send_name;
    std::string m_recv_addr;
    std::string m_send_addr;
    unsigned short m_type;
    
public:
    Expressage();
    ~Expressage();
    int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server);

private:
    int analyse_shentong(unsigned short type, bool is_from_server); 
    int analyse_yuantong(unsigned short type, bool is_from_server);
    int analyse_yunda(unsigned short type, bool is_from_server);
    int analyse_ems(unsigned short type, bool is_from_server);
    int analyse_shunfeng(unsigned short type, bool is_from_server);
    int analyse_expressage(unsigned short type, PacketInfo* packet, bool is_from_server);
    void store_db();
    void update_db();
};

#endif
