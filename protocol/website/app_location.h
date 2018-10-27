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
    A_GAODE = 1,      //�ߵµ�ͼ
    A_MEITUAN,   //����
    A_XIECHENGTRAVEL,         //Я������
    A_YILONGTRAVEL,    //��������
    A_HELLOBIKE,   //hello����
    A_AIWUJIWU, //���ݼ���
    A_WEIXIN, //΢��
    A_QQLITE, //qq���İ�
    A_MOMO, //İİ
    A_XIAOMISTORE, //С���̳�
    A_BAIDUVIDEO,//�ٶ���Ƶ
    A_DAZHONGDIANPIN,       //���ڵ���
    A_TENCENT_NEWS,//��Ѷ����
    A_IFENG_NEWS,//�������
    A_KUWO_MUSIC,//��������
    A_SOUHU_VIDEO,// �Ѻ���Ƶ
    A_LETV,//������Ƶ
    A_SOUHU_NEWS,//�Ѻ����� �ѹ���ͼ  �ѹ������
    A_YY,//YY
    A_SHIJIJIAYUAN,//���ͼ�Ե
    A_MIJIWEATHER,//ī������
    A_TIANQITONG,//����ͨ
    A_MEITUAN_WAIMAI,//��������
    A_LIEBAO_BROWSER,//�Ա������
    A_360_BROWSER,//360�����   
    A_HUANGLI_WEATHER,//��������Ԥ��
    A_GO_WEATHER,//go����
    A_TONGCHENG_58,//58ͬ��
    A_WANNENGKEY,//����Կ��
    A_ZHWNL,//�л�������
    A_SINANEWS,//��������
    A_SOUGOUSEARCH,//�ѹ�����
    A_YOUKUVIDEO,//�ſ���Ƶ
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

