/*
 ******************************************************************************
 *
 * (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.
 *
 * File Name : data_shunt.h
 *
 * Module : libanalyzeServer.so
 *
 * Description:  the file for analysing data on port 80
 *
 * Evolution( Date | Author | Description )
 * 2017.05.24 | zhangzm | v2.0 delivery based on T01.
 *
 ******************************************************************************
 */

#ifndef _DATA_SHUNT_H_
#define _DATA_SHUNT_H_

#include <map>
#include <string>

#include "user_action.h"
#include "../PacketParser.h"
#include "../webmail-LZ/list.h"

#ifndef __cacheline_aligned

#define CO_IN_CACHE_SHIFT       7
#define CO_CACHE_LINE_SIZE      (1 << CO_IN_CACHE_SHIFT)

#define __cacheline_aligned     __attribute__((aligned(CO_CACHE_LINE_SIZE)))
#endif

//B is business
enum
{
    B_AIRLINE = 0x01,
    B_ONLINE_SHOP,
    B_JOB,
    B_EXPRESSAGE,
    B_HOTEL,
    B_LOCATION,
};

typedef struct map_object
{
    unsigned int b_type;  // belong to abstract business, e.g. online_shop, airline.
    unsigned int type;    // belong to specific business, e.g. dangdang_shop, suning_shop, szx_airline.
    void *object;
}mapObject;

typedef unsigned int (user_action::*process_function)(unsigned int, char *);

typedef struct shunt_type_map
{
    const char *host;
    unsigned int type;
    process_function cb;
}shunt_type_map_t;

typedef struct mbox_gather
{
    const char  *key;
    unsigned int key_value;
    size_t hashv;
    size_t bucket_index;
    struct hlist_node mb_hash;
    process_function vacb;
} mbox_gather_t __attribute__((aligned(8)));

class data_shunt
{
private:
    size_t mbox_max_size;

    user_action *u_action;
    struct hlist_head *mbox_hash_table;
    std::map<uint64_t, mapObject> mapNode;

private:
    uint64_t makeHashkey(PacketInfo *pkt, bool reverse)
    {
        uint64_t ret;
        if(reverse)
            ret = ((uint64_t)(pkt->srcIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->destPort << 16 | (uint32_t)pkt->srcPort);
        else
            ret = ((uint64_t)(pkt->destIpv4 & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)pkt->srcPort << 16 | (uint32_t)pkt->destPort);
        return ret;
    }

    size_t BKDRHash(const char *str)
    {
        size_t ch;
        size_t hash = 0;  
        //while (ch = (size_t)*str++)
        //    hash = hash * 131 + ch;
        //    gcc may not optimize this code on X86_64
        while (ch = (size_t)*str++)
            hash = (hash << 7) + (hash << 1) + hash + ch;
        return hash;
    }

    void init_mbox_table();
    void destroy_mbox_table();
    mbox_gather_t* mbox_lookup_value(const char *key);

    unsigned int get_data_type(char *data);
    unsigned int lookup_map_object(uint64_t key);
    int create_map_node(uint64_t key, struct PacketInfo* pktinfo, uint32_t type, bool is_from_server);
    int notify_map_node(uint64_t key, struct PacketInfo* pktinfo, uint32_t type, bool is_from_server);
    int delete_map_node(uint64_t key);

public:
    data_shunt();
    ~data_shunt();

    int data_shunt_main(struct PacketInfo* pktinfo);
    
};

#endif  /*_DATA_SHUNT_H_*/


