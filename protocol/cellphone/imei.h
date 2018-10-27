/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : imei.h
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing cellphone imei
*
* Evolution( Date | Author | Description ) 
* 2017.10.09 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#ifndef IMEI_H
#define IMEI_H 

#include <iostream>
#include <string>
#include <map>

typedef int (*common_imei) (char* body, unsigned int bodylen, char* imei);

#define IMEI_PROTO 2701
#define IMEI_LEN 15

#define ASSERT_I(body, bodylen, imei) \
{\
    if(body == NULL || bodylen == 0 || imei == NULL)\
        return -1;\
}

typedef struct imei_code
{
    std::string hostname;
    common_imei function;
}imei_mapnode;

void imei_map_init();
int analyse_imei(struct PacketInfo* packet);
int do_aiwujiwu(char* body, unsigned int bodylen, char* imei);
int do_dazhongcomment(char* body, unsigned int bodylen, char* imei);
int do_gaodeditu(char* body, unsigned int bodylen, char* imei);
int do_meituan(char* body, unsigned int bodylen, char* imei);
int do_qqlite(char* body, unsigned int bodylen, char* imei);
int do_yilong(char* body, unsigned int bodylen, char* imei);
int do_weixin(char* body, unsigned int bodylen, char* imei);
int do_tencent_news_tim(char* body, unsigned int bodylen, char* imei);
int do_ifeng_news(char* body, unsigned int bodylen, char* imei);
int do_kuwo_music(char* body, unsigned int bodylen, char* imei);
int do_souhu_video(char* body, unsigned int bodylen, char* imei);
int do_letv(char* body, unsigned int bodylen, char* imei);
int do_souhu_news(char* body, unsigned int bodylen, char* imei);
int do_baidu_video(char* body, unsigned int bodylen, char* imei);
int do_jd(char* body, unsigned int bodylen, char* imei);
int do_today_toutiao(char* body, unsigned int bodylen, char* imei);
int do_kugou(char* body, unsigned int bodylen, char* imei);
int do_qq_music(char* body, unsigned int bodylen, char* imei);
int do_aiqiyi(char* body, unsigned int bodylen, char* imei);
int do_youku(char* body, unsigned int bodylen, char* imei);
int do_yy(char* body, unsigned int bodylen, char* imei);
int do_douyu(char* body, unsigned int bodylen, char* imei);
int do_huya(char* body, unsigned int bodylen, char* imei);
int do_shijijiayuan(char* body, unsigned int bodylen, char* imei);
int do_wannengwifi(char* body, unsigned int bodylen, char* imei); 
int do_moji_weather(char* body, unsigned int bodylen, char* imei);
int do_tianqitong(char* body, unsigned int bodylen, char* imei);
int do_weather_kb(char* body, unsigned int bodylen, char* imei);
int do_liebao_browser(char* body, unsigned int bodylen, char* imei);
int do_sinaweibo(char* body, unsigned int bodylen, char* imei);
int do_meituanwaimai(char* body, unsigned int bodylen, char* imei);
int do_qq(char* body, unsigned int bodylen, char* imei);
void store_db(struct PacketInfo* packet, char* imei);
#endif
