/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : website_base.h
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

#ifndef WEBSITE_BASE_H
#define WEBSITE_BASE_H

#include <iostream>
#include "../PacketParser.h"

typedef struct packet_info
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    char src_mac[20];
    unsigned int capture_time;
    
    char *header;
	int  headerLen;
	char *body;
	unsigned int bodyLen;
	unsigned int bodyTotal;
	unsigned int status;
}packet_info_t;

class website_base
{
private:
    void release_node();
    int enc_unicode_to_utf8_one(unsigned long unic, unsigned char *pOutput, int *outSize);

protected:
    struct packet_info m_request_packet;
    struct packet_info m_response_packet;

public:
    website_base();
    virtual ~website_base();

    int decomp_gzip(char *src, unsigned int len, char **dest);
    int set_packet_base_info(struct packet_info *pinfo, struct PacketInfo *pktinfo);
    int unicode_to_utf8(const char *inbuf, u_int inlen, char *outbuf, u_int olen);
    int url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen);
    int rebuilt_packet(struct packet_info *entry, char* data, unsigned int dataLen);

    virtual void update_db() = 0; 
    //virtual void store_db() = 0;
    virtual int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server) = 0;
};

#endif


