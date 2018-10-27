/*
 ******************************************************************************
 *
 * (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
 *
 * File Name : data_shunt.cpp
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>

#include "airline.h"
#include "online_shop.h"
#include "data_shunt.h"
#include "jobsite_handler.h"
#include "expressage.h"
#include "hotel.h"
#include "app_location.h"

/*bit16~23:business classify, bit8~15:website platform classify, bit0~7:specific action*/
static shunt_type_map_t shunt_map[] = 
{
    /*ctrip website, airlines*/
    {"flights.ctrip.com",    0x010100, &user_action::validate_ctrip_action},
    //{"s.c-ctrip.com",        0x010100, &user_action::validate_ctrip_action},
    
    /*shenzhen airlines*/
    {"www.shenzhenair.com",  0x010200, &user_action::validate_szx_action},
    {"www.webdissector.com", 0x010200, &user_action::validate_szx_action},

    /*dangdang online shop*/
    {"checkoutb.dangdang.com", 0x020100, &user_action::validate_dangdang_action},

    /*suning online shop*/
    {"shopping.suning.com",    0x020200, &user_action::validate_suning_action},
    {"click.suning.cn",        0x020200, &user_action::validate_suning_action},

    /*gome online shop*/
    {"cart.gome.com.cn",       0x020300, &user_action::validate_guomei_action},
    {"success.gome.com.cn",    0x020300, &user_action::validate_guomei_action},

    /*jobs website*/
    {"i.51job.com",            0x030100, &user_action::validate_51job_action},
    {"i.zhaopin.com",          0x030200, &user_action::validate_zl_job_action},

    /*expressage*/
    {"www.sto.cn",             0x040100, &user_action::validate_sto_action},
    {"ec.yto.net.cn",          0x040200, &user_action::validate_yto_action},
    {"member.yundaex.com",     0x040300, &user_action::validate_yda_action},
    {"www.11183.com.cn",       0x040400, &user_action::validate_ems_action},
    {"www.sf-express.com",     0X040500, &user_action::validate_shunfeng_action},

    /*hotel*/
    {"www.ly.com",             0x050100, &user_action::validate_tongcheng_hotel_action},
    {"hotels.ctrip.com",       0x050200, &user_action::validate_xiecheng_hotel_action},
    {"hotel.elong.com",        0x050300, &user_action::validate_yilong_hotel_action},
    {"www.plateno.com",        0x050400, &user_action::validate_7day_hotel_action},
    {"hotel.mangocity.com",    0x050500, &user_action::validate_mangguo_hotel_action},
    {"hotel.tuniu.com",        0x050600, &user_action::validate_tuniu_hotel_action},

    /*app_position*/
    {"m5.amap.com",              0x060100, &user_action::validate_gaode_position_action},
    {"mreport.meituan.com",      0x060200, &user_action::validate_meituan_position_action},
    {"m.ctrip.com",              0x060300, &user_action::validate_xiecheng_position_action},
    {"mobile-api2011.elong.com", 0x060400, &user_action::validate_yilong_position_action},
    {"restapi.amap.com",         0x060500, &user_action::validate_hellobike_or_momo_position_action},
    {"log.reyun.com",            0x060600, &user_action::validate_aiwujiwu_position_action},
    {"st.map.qq.com",            0x060700, &user_action::validate_weixin_position_action},
    {"st.map.soso.com",          0x060800, &user_action::validate_qqlite_position_action},
    {"api.m.mi.com",             0x060a00, &user_action::validate_xiaomistore_position_action},
    {"loc.map.baidu.com",        0x060b00, &user_action::validate_baiduvideo_position_action},
    {"140.207.217.32",           0x060c00, &user_action::validate_dazhongcomment_position_action},
    {"w.inews.qq.com",           0x060d00, &user_action::validate_tencent_news_position_action},
    {"api.iclient.ifeng.com",    0x060e00, &user_action::validate_ifeng_news_position_action},
    {"mobilead.kuwo.cn",         0x060f00, &user_action::validate_kuwo_music_position_action},
    {"api.tv.sohu.com",          0x061000, &user_action::validate_souhu_video_position_action},
    {"cn.api.push.le.com",       0x061100, &user_action::validate_letv_position_action},
    {"mengine.go2map.com",       0x061200, &user_action::validate_sohu_news_position_action},
    {"idx.3g.yy.com",            0x061300, &user_action::validate_yy_position_action},
    {"api2.jiayuan.com",         0x061400, &user_action::validate_shijijiayuan_position_action},
    {"weather.api.moji.com",     0x061500, &user_action::validate_moji_weather_position_action},
    {"tqt.weibo.cn",             0x061600, &user_action::validate_tianqitong_position_action},
    {"api.mobile.meituan.com",   0x061700, &user_action::validate_meituan_waimai_position_action},
    {"an.m.liebao.cn",           0x061800, &user_action::validate_liebao_browser_position_action},
    {"api.map.haosou.com",       0x061900, &user_action::validate_360_browser_position_action},
    {"tq.ifjing.com",            0x061a00, &user_action::validate_huangli_weather_position_action},
    {"goweatherex.3g.cn",        0x061b00, &user_action::validate_go_weather_position_action},
    {"app.58.com",               0x061c00, &user_action::validate_58tongcheng_position_action},
    {"news-log.51y5.net",        0x061d00, &user_action::validate_wannengkey_position_action},
    {"zhwnlapi.etouch.cn",       0x061e00, &user_action::validate_zhwnl_position_action},
    {"newsapi.sina.cn",          0x061f00, &user_action::validate_sinanews_position_action},
    {"t.sogou.com",              0x062000, &user_action::validate_sougousearch_position_action},
    {"iyes.youku.com",           0x062100, &user_action::validate_youku_position_action},
};

/****************************************************************************
Function Name:           data_shunt
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
data_shunt::data_shunt()
{
    mbox_max_size = 2048;
    init_mbox_table();
    
    u_action = new user_action;
}

/****************************************************************************
Function Name:           ~data_shunt
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
data_shunt::~data_shunt()
{
    delete u_action;
    destroy_mbox_table();
}

/****************************************************************************
Function Name:           init_mbox_table
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
void data_shunt::init_mbox_table()
{
	int i = 0;
	mbox_hash_table = (struct hlist_head *)memalign(CO_CACHE_LINE_SIZE, sizeof(struct hlist_head) * mbox_max_size);
	for (i = 0; i < mbox_max_size; i++)	
		INIT_HLIST_HEAD(&mbox_hash_table[i]);

	for (i = 0; i < sizeof(shunt_map)/sizeof(shunt_map[0]); i++)
	{
		size_t bucket_i = 0;
		mbox_gather_t *m = (mbox_gather_t *)memalign(CO_CACHE_LINE_SIZE, sizeof(mbox_gather_t));
		m->key = shunt_map[i].host;
		m->key_value = shunt_map[i].type;
		memset(&m->mb_hash, 0, sizeof(m->mb_hash));
		m->hashv = BKDRHash(m->key);
		bucket_i = m->hashv % mbox_max_size;
		m->bucket_index = bucket_i;
		m->vacb = shunt_map[i].cb;
		hlist_add_head(&m->mb_hash, &mbox_hash_table[bucket_i]);
	}
}

/****************************************************************************
Function Name:           destroy_mbox_table
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
void data_shunt::destroy_mbox_table()
{
	// not implement yet
}

/****************************************************************************
Function Name:           mbox_lookup_value
Input Parameters:        key
Output Parameters:       void
Return Code:             mbox_gather_t * or NULL
Description:             
****************************************************************************/
mbox_gather_t* data_shunt::mbox_lookup_value(const char *key)
{
    size_t hash = BKDRHash(key);
    struct hlist_head *h = &mbox_hash_table[hash % mbox_max_size];
    mbox_gather_t *retval;
    struct hlist_node *node = h->first;
    mbox_gather_t *mb;

    hlist_for_each_entry(mb, node, h, mb_hash)
    if (mb->hashv == hash && !strcmp(mb->key, key))
        return mb;

    return NULL;
}

/****************************************************************************
Function Name:           get_data_type
Input Parameters:        data
Output Parameters:       void
Return Code:             mixtype, 0 or !0
Description:             
****************************************************************************/
unsigned int data_shunt::get_data_type(char *data)
{
    unsigned int mixtype = 0;
    unsigned int data_type = 0;
    char *host_p = strcasestr(data, "Host:");
    char *host_e = NULL;
    char host_v[128] = {0}; // ¥Ê∑≈”Ú√˚
    int hostlen = 0;

    if (!host_p)
        return mixtype;

    // skip the length of "Host: " keyword
    host_p += 5;
    if(*host_p == ' ')
        host_p++;

    host_e = strstr(host_p, "\r\n");
    hostlen = host_e - host_p;
    if (hostlen < 127 && hostlen > 0)
    {
        strncpy(host_v, host_p, hostlen);
    }
    else
    {
        return mixtype;
    }
    
	mbox_gather_t *mb = mbox_lookup_value(host_v);
	if (!mb) 
        return mixtype;
	
	data_type = mb->key_value;
	// FIXME: offset +5 , this may not work for mail sohu <HTTP PUT, not POST>
	if (!strncmp(data, "GET ", 4) || !strncmp(data, "PUT ", 4))
		mixtype = (u_action->*(mb->vacb))(data_type, data + 4);
	else
		mixtype = (u_action->*(mb->vacb))(data_type, data + 5);

	return mixtype;
}

/****************************************************************************
Function Name:           lookup_map_object
Input Parameters:        key
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             
****************************************************************************/
unsigned int data_shunt::lookup_map_object(uint64_t key)
{
    unsigned int type = 0;
    std::map<uint64_t, mapObject>::iterator iter;

    iter = mapNode.find(key);
    if (iter != mapNode.end())
    {
        type = iter->second.type;
    }

    return type;
}

/****************************************************************************
Function Name:           create_map_node
Input Parameters:        key, pktinfo, type, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int data_shunt::create_map_node(uint64_t key, struct PacketInfo* pktinfo, uint32_t type, bool is_from_server)
{
    int ret = -1;
    unsigned int b_type = (type&0xff0000) >> 16;

    if (0 < lookup_map_object(key))
    {
        //the hash key is exist, this key is error.
        printf("the hash key is exist, this key is error.\n");
        return ret;
    }

    switch (b_type)
    {
        case B_ONLINE_SHOP:
        {
            Onlineshop *shop_object = new Onlineshop;
            unsigned short c_type = (unsigned short)(type&0xffff);
            
            ret = shop_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if (0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)shop_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete shop_object;
            }
        }
        break;

        case B_AIRLINE:
        {
            airline *airline_object = new airline;
            unsigned short c_type = (unsigned short)(type&0xffff);
            
            ret = airline_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if (0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)airline_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete airline_object;
            }
        }
        break;

        case B_JOB:
        {
            jobsite_handler* jobsit_object = new jobsite_handler;
            unsigned short c_type = (unsigned short)(type&0xffff);

            ret = jobsit_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if(0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)jobsit_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete jobsit_object;
            }
        }
        break;

        case B_EXPRESSAGE:
        {
            Expressage* expressage_object = new Expressage;
            unsigned short c_type = (unsigned short)(type&0xffff);
            
            ret = expressage_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if(0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)expressage_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete expressage_object;
            }
        }    
        break;

        case B_HOTEL:
        {
            Hotel* hotel_object = new Hotel;
            unsigned short c_type = (unsigned short)(type&0xffff);

            ret = hotel_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if(0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)hotel_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete hotel_object;
            }
        }
        break;

        case B_LOCATION:
        {
            Location* location_object = new Location;
            unsigned short c_type = (unsigned short)(type&0xffff);

            ret = location_object->deal_packet_process(c_type, pktinfo, is_from_server);
            if(0 == ret)
            {
                mapObject tmpMapObject;
                memset(&tmpMapObject, 0, sizeof(tmpMapObject));

                tmpMapObject.b_type = b_type;
                tmpMapObject.type = type;
                tmpMapObject.object = (void *)location_object;
                mapNode.insert(std::map<uint64_t, mapObject>::value_type(key, tmpMapObject));
            }
            else
            {
                delete location_object;
            }
        }
        break;
        
        default:
        break;
    }

    return ret;
}

/****************************************************************************
Function Name:           notify_map_node
Input Parameters:        key, pktinfo, type, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int data_shunt::notify_map_node(uint64_t key, struct PacketInfo* pktinfo, uint32_t type, bool is_from_server)
{
    int ret = -1;
    unsigned int b_type = (type&0xff0000) >> 16;

    switch (b_type)
    {
        case B_ONLINE_SHOP:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;
            
            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;
            
            Onlineshop *shop_object = (Onlineshop *)iter->second.object;
            ret = shop_object->deal_packet_process(c_type, pktinfo, is_from_server);
        }
        break;

        case B_AIRLINE:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;
            
            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;
            
            airline *airline_object = (airline *)iter->second.object;
            ret = airline_object->deal_packet_process(c_type, pktinfo, is_from_server);
        }
        break;

        case B_JOB:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;
            
            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;
            
            jobsite_handler *jobsite_object = (jobsite_handler *)iter->second.object;
            ret = jobsite_object->deal_packet_process(c_type, pktinfo, is_from_server);     
        }
        break;

        case B_EXPRESSAGE:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;

            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;
            
            Expressage* expressage_object = (Expressage*)iter->second.object;
            ret = expressage_object->deal_packet_process(c_type, pktinfo, is_from_server);     
        }
        break;

        case B_HOTEL:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;

            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;

            Hotel* hotel_object = (Hotel*)iter->second.object;
            ret = hotel_object->deal_packet_process(c_type, pktinfo, is_from_server); 
        }
        break;

        case B_LOCATION:
        {
            unsigned short c_type = (unsigned short)(type&0xffff);
            std::map<uint64_t, mapObject>::iterator iter;

            iter = mapNode.find(key);
            if (iter == mapNode.end())
                break;

            Location* location_object = (Location*)iter->second.object;
            ret = location_object->deal_packet_process(c_type, pktinfo, is_from_server);
        }
        break;
        
        default:
        break;
    }

    return ret;
}

/****************************************************************************
Function Name:           delete_map_node
Input Parameters:        key
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int data_shunt::delete_map_node(uint64_t key)
{
    std::map<uint64_t, mapObject>::iterator iter;

    iter = mapNode.find(key);
    if (iter != mapNode.end())
    {
        switch (iter->second.b_type)
        {
            case B_ONLINE_SHOP:
            {
                if (iter->second.object != NULL)
                {
                    Onlineshop *t_online_shop = (Onlineshop *)iter->second.object;
                    delete t_online_shop;
                }
            }
            break;

            case B_AIRLINE:
            {
                if (iter->second.object != NULL)
                {
                    airline *t_airline = (airline *)iter->second.object;
                    delete t_airline;
                }
            }
            break;

            case B_JOB:
            {
                if (iter->second.object != NULL)
                {
                    jobsite_handler *jobsite_object = (jobsite_handler *)iter->second.object;
                    delete jobsite_object;
                } 
            }
            break;

            case B_EXPRESSAGE:
            {
                if (iter->second.object != NULL)
                {
                    Expressage *expressage_object = (Expressage *)iter->second.object;
                    delete expressage_object;
                } 
            }
            break;

            case B_HOTEL:
            {
                if (iter->second.object != NULL)
                {
                    Hotel *hotel_object = (Hotel *)iter->second.object;
                    delete hotel_object;
                } 
            }
            break;

            case B_LOCATION:
            {
                if (iter->second.object != NULL)
                {
                    Location *location_object = (Location *)iter->second.object;
                    delete location_object;
                } 
            }
            break;
        }

        mapNode.erase(iter->first);
    }

    return 0;
}

/********************************************************************************
Function Name:     data_shunt_main
Input Parameters:  pktinfo
Output Parameters: void
Return Code:       -1:error, 0:success but not finish, 1:success and deal finish
Description:             
*********************************************************************************/
int data_shunt::data_shunt_main(struct PacketInfo* pktinfo)
{
    int ret = -1;

	if ( pktinfo->pktType != TCP || (pktinfo->srcPort != 80 && pktinfo->destPort != 80))
	{
		return ret;
	}

	if (!pktinfo->bodyLen && !pktinfo->tcp->fin && !pktinfo->tcp->rst)
	{
		return ret;
	}

    bool is_from_server = (pktinfo->srcPort == 80)?true:false;
    uint64_t hashKey = makeHashkey(pktinfo, is_from_server);
    
    uint32_t packet_type = get_data_type(pktinfo->body);
    if (0 == packet_type)
    {
        packet_type = lookup_map_object(hashKey);
        if (packet_type > 0)
        {
            ret = notify_map_node(hashKey, pktinfo, packet_type, is_from_server);
            
            /*-1 is error; 0 is ok, but data reserve; 1 is deal finish*/
            if (-1 == ret || 1 == ret)
            {
                //release map node
                delete_map_node(hashKey);
            }
        }
        else
        {
            return ret;
        }
    }
    else
    {
        ret = create_map_node(hashKey, pktinfo, packet_type, is_from_server);
    }

    return ret;
}


