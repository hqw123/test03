/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : user_action.h
*
* Module : libanalyzeServer.so
*
* Description:  the file for analyzing user action online
*  
* Evolution( Date | Author | Description ) 
* 2017.05.26 | zhangzm | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#ifndef _USER_ACTION_H_
#define _USER_ACTION_H_

class user_action
{
private:

public:
    user_action(){};
    ~user_action(){};
    
    unsigned int validate_ctrip_action(unsigned int mails_byte, char *uri);
    unsigned int validate_szx_action(unsigned int mails_byte, char *uri);
    unsigned int validate_dangdang_action(unsigned int mails_byte, char *uri);
    unsigned int validate_suning_action(unsigned int mails_byte, char *uri);
    unsigned int validate_guomei_action(unsigned int mails_byte, char *uri);
    unsigned int validate_51job_action(unsigned int mails_byte, char *uri);
    unsigned int validate_zl_job_action(unsigned int mails_byte, char *uri);
    unsigned int validate_sto_action(unsigned int mails_byte, char *uri);
    unsigned int validate_yto_action(unsigned int mails_byte, char *uri);
    unsigned int validate_yda_action(unsigned int mails_byte, char *uri);
    unsigned int validate_ems_action(unsigned int mails_byte, char *uri);
    unsigned int validate_shunfeng_action(unsigned int mails_byte, char *uri);
    unsigned int validate_tongcheng_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_xiecheng_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_yilong_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_7day_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_mangguo_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_tuniu_hotel_action(unsigned int mails_byte, char *uri);
    unsigned int validate_gaode_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_meituan_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_xiecheng_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_yilong_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_hellobike_or_momo_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_aiwujiwu_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_weixin_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_qqlite_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_xiaomistore_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_baiduvideo_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_dazhongcomment_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_tencent_news_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_ifeng_news_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_kuwo_music_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_souhu_video_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_letv_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_sohu_news_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_yy_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_shijijiayuan_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_moji_weather_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_tianqitong_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_liebao_browser_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_360_browser_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_meituan_waimai_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_huangli_weather_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_go_weather_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_58tongcheng_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_wannengkey_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_zhwnl_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_sinanews_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_sougousearch_position_action(unsigned int mails_byte, char *uri);
    unsigned int validate_youku_position_action(unsigned int mails_byte, char *uri);
};

#endif  /*_USER_ACTION_H_*/


