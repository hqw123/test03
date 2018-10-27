/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : app_location.h
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

#ifndef APP_LOCATION_H
#define APP_LOCATION_H

#include <iostream>
#include "website_base.h"

//??????
enum
{
    MAP_GPS = 2601,
    MAP_GCJ02,
    MAP_BD09,
    MAP_MKT
};

enum
{  
    A_GAODE = 1,      //高德地图
    A_MEITUAN,   //美团
    A_XIECHENGTRAVEL,         //携程旅游
    A_YILONGTRAVEL,    //艺龙旅行
    A_HELLOBIKE,   //hello单车
    A_AIWUJIWU, //爱屋及乌
    A_WEIXIN, //微信
    A_QQLITE, //qq轻聊版
    A_MOMO, //陌陌
    A_XIAOMISTORE, //小米商城
    A_BAIDUVIDEO,//百度视频
    A_DAZHONGDIANPIN,       //大众点评
    A_TENCENT_NEWS,//腾讯新闻
    A_IFENG_NEWS,//凤凰新闻
    A_KUWO_MUSIC,//酷我音乐
    A_SOUHU_VIDEO,// 搜狐视频
    A_LETV,//乐视视频
    A_SOUHU_NEWS,//搜狐新闻 搜狗地图  搜狗浏览器
    A_YY,//YY
    A_SHIJIJIAYUAN,//世纪佳缘
    A_MIJIWEATHER,//墨迹天气
    A_TIANQITONG,//天气通
    A_MEITUAN_WAIMAI,//美团外卖
    A_LIEBAO_BROWSER,//猎豹浏览器
    A_360_BROWSER,//360浏览器   
    A_HUANGLI_WEATHER,//黄历天气预报
    A_GO_WEATHER,//go天气
    A_TONGCHENG_58,//58同城
    A_WANNENGKEY,//万能钥匙
    A_ZHWNL,//中华万年历
    A_SINANEWS,//新浪新闻
    A_SOUGOUSEARCH,//搜狗搜索
    A_YOUKUVIDEO,//优酷视频
};

class Location : public website_base
{
private:
    std::string m_lat;
    std::string m_lon;
public:
    Location();
    ~Location();
    int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server);
private:
    int analyse_gaode(unsigned short type, bool is_from_server); 
    int analyse_meituan(unsigned short type, bool is_from_server);
    int analyse_dazhongcomment(unsigned short type, bool is_from_server);
    int analyse_yilongtravel(unsigned short type, bool is_from_server);
    int analyse_hellobike_momo(unsigned short type, bool is_from_server);
    int analyse_aiwujiwu(unsigned short type, bool is_from_server);
    int analyse_weixin(unsigned short type, bool is_from_server);
    int analyse_xiaomistore(unsigned short type, bool is_from_server);
    int analyse_baiduvideo(unsigned short type, bool is_from_server);
    int analyse_tencent_news(unsigned short type, bool is_from_server);
    int analyse_kuwo_music(unsigned short type, bool is_from_server);
    int analyse_souhu_video(unsigned short type, bool is_from_server);
    int analyse_letv(unsigned short type, bool is_from_server);
    int analyse_souhu_news(unsigned short type, bool is_from_server);
    int analyse_shijijiayuan(unsigned short type, bool is_from_server);
    int analyse_moji_weather(unsigned short type, bool is_from_server);
    int analyse_tianqitong(unsigned short type, bool is_from_server);
    int analyse_360_browser(unsigned short type, bool is_from_server);
    int analyse_huangli_weather(unsigned short type, bool is_from_server);
    int analyse_go_weather(unsigned short type, bool is_from_server);
    int analyse_58tongcheng(unsigned short type, bool is_from_server);
    int analyse_ifengnews(unsigned short type, bool is_from_server);
    int analyse_sinanews(unsigned short type, bool is_from_server);
    int analyse_youku(unsigned short type, bool is_from_server);
    void store_db(int map_type);
    void update_db();
    int analyse_location(unsigned short type, bool is_from_server);
};

#endif

