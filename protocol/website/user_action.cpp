/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : user_action.cpp
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "user_action.h"

/****************************************************************************
Function Name:           validate_ctrip_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse ctrip action
****************************************************************************/
unsigned int user_action::validate_ctrip_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if (strstr(uri, "/booknew/api/book/saveorder"))
        act_byte = 0x10;
    else if (strstr(uri, "/booknew/api/delivery/getaddresses"))
        act_byte = 0x11;
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_szx_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse shenzhenair action
****************************************************************************/
unsigned int user_action::validate_szx_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if (strstr(uri, "/szair_B2C/saveOrder.action"))
        act_byte = 0x10;
    else if (strstr(uri, "/recv/gs.gif"))
        act_byte = 0x11;
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_dangdang_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse dangdang action
****************************************************************************/
unsigned int user_action::validate_dangdang_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if (!strncmp(uri, "/web/consignee/submit HTTP", 26))
        act_byte = 0x0001;//获取用户个人信息
    else if (!strncmp(uri, "/web/cashier/?", 14))
        act_byte = 0x0002;//获取订单号
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_suning_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse suning action
****************************************************************************/
unsigned int user_action::validate_suning_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if (!strncmp(uri, "/confDeliInfo.do HTTP", 21))
        act_byte = 0x0001; //获取用户个人信息
    else if (!strncmp(uri, "/sa/ajaxPageSale.gif?", 21))
        act_byte = 0x0002;//获取订单号
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_guomei_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse guomei action
****************************************************************************/
unsigned int user_action::validate_guomei_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if (!strncmp(uri, "/home/api/order/initOrder HTTP", 30))
        act_byte = 0x0001;//获取用户个人信息
    else if (!strncmp(uri, "/order/paymentInfo?", 19))
        act_byte = 0x0002;//获取订单号
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_51job_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse 51job action
****************************************************************************/
unsigned int user_action::validate_51job_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(strstr(uri, "/resume/resume_preview.php"))
        act_byte = 0x0001;//获取招聘网站的个人信息
    else
        return 0;
    
    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_zl_job_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse zl_job action
****************************************************************************/
unsigned int user_action::validate_zl_job_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(strstr(uri, "Home/ResumePreview?"))
        act_byte = 0x0001;//获取招聘网站的个人信息
    else
        return 0;
    
    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_sto_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse sto action
****************************************************************************/
unsigned int user_action::validate_sto_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/Order/IndexCreate HTTP", 23))
        act_byte = 0x0001;//获取快递订单收件人的相关信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_yto_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse yto action
****************************************************************************/
unsigned int user_action::validate_yto_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/order/saveResult.htm HTTP", 26))
        act_byte = 0x0001;//获取快递订单收件人的相关信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_yda_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse yda action
****************************************************************************/
unsigned int user_action::validate_yda_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/ydmb/service/order/create.json HTTP", 36))
        act_byte = 0x0001;//获取快递订单收件人的相关信息
    else 
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_ems_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse ems action
****************************************************************************/
unsigned int user_action::validate_ems_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/ec-web/order/saveShipmentAction.action HTTP", 44))
        act_byte = 0x0001;//获取快递订单收件人的相关信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_shunfeng_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse shunfeng action
****************************************************************************/
unsigned int user_action::validate_shunfeng_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/sf-service-owf-web/service/order/neworder HTTP", 47))
        act_byte = 0x0001;//获取快递订单收件人的相关信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_tongcheng_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse tongcheng action
****************************************************************************/
unsigned int user_action::validate_tongcheng_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/hotel/handler/SubmitOrder.json HTTP", 36))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_xiecheng_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse xiecheng action
****************************************************************************/
unsigned int user_action::validate_xiecheng_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/DomesticBook/DomeInputNewOrderCS.aspx HTTP", 43))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_xiecheng_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse yilong action
****************************************************************************/
unsigned int user_action::validate_yilong_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/ajax/fillorder/submitorderinfo HTTP", 36))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_7day_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse 7day action
****************************************************************************/
unsigned int user_action::validate_7day_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/booking/book HTTP", 18))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_7day_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse 7day action
****************************************************************************/
unsigned int user_action::validate_mangguo_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/hotel-complete.shtml HTTP", 26))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte; 
}

/****************************************************************************
Function Name:           validate_tuniu_hotel_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse tuniu action
****************************************************************************/
unsigned int user_action::validate_tuniu_hotel_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/order/subscribe HTTP", 21))
        act_byte = 0x0001;//获取酒店的一些用户信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_gaode_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse gaode action
****************************************************************************/
unsigned int user_action::validate_gaode_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/ws/transfer/auth/aps/locate?", 29))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_meituan_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse meituan action
****************************************************************************/
unsigned int user_action::validate_meituan_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/data/collect.json?", 19))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_xiecheng_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse xiecheng action
****************************************************************************/
unsigned int user_action::validate_xiecheng_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/restapi/h5api/searchapp/search?", 32))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_yilong_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse yilong action
****************************************************************************/
unsigned int user_action::validate_yilong_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/messagecenter/offline/message?", 31))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_hellobike_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse hellobike action
****************************************************************************/
unsigned int user_action::validate_hellobike_or_momo_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/v3/geocode/regeo HTTP", 22))
        act_byte = 0x0001;//获取hellobike地址信息
    else if(!strncmp(uri, "/v3/staticmap?", 14))
        return 0x060902;//获取陌陌地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_aiwujiwu_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse aiwujiwu action
****************************************************************************/
unsigned int user_action::validate_aiwujiwu_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/receive/pkginfo HTTP", 21))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_weixin_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse weixin action
****************************************************************************/
unsigned int user_action::validate_weixin_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/api?", 5) && strstr(uri, "referer=weixin"))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_qqlite_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse qqlite action
****************************************************************************/
unsigned int user_action::validate_qqlite_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "//api?", 6))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_xiaomistore_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse xiaomistore action
****************************************************************************/
unsigned int user_action::validate_xiaomistore_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/v1/home/appInfov2 HTTP", 23))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_intelligentbus_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse intelligentbus action
****************************************************************************/
unsigned int user_action::validate_baiduvideo_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/sdk.php HTTP", 13))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_dazhongcomment_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse dazhongcomment action
****************************************************************************/
unsigned int user_action::validate_dazhongcomment_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/mapi/mindex/getindexliveinfo.bin?", 34))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_tencent_news_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse tencent_news action
****************************************************************************/
unsigned int user_action::validate_tencent_news_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/upLoadLoc?", 11))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_ifeng_news_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse ifeng_news action
****************************************************************************/
unsigned int user_action::validate_ifeng_news_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/userInterestTag?", strlen("/userInterestTag?")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_kuwo_music_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse kuwo_music action
****************************************************************************/
unsigned int user_action::validate_kuwo_music_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/EcomResourceServer/getMotor.do?", 32))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_souhu_video_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse souhu_video action
****************************************************************************/
unsigned int user_action::validate_souhu_video_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/mobile_user/device/clientconf.json?", 36))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_letv_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse letv action
****************************************************************************/
unsigned int user_action::validate_letv_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/client/androidReg HTTP", 23))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_sohu_news_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse letv action
****************************************************************************/
unsigned int user_action::validate_sohu_news_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/location HTTP", 14))
        act_byte = 0x0001;//获取地址信息
    else if(!strncmp(uri, "/location?", 10))
        act_byte = 0x0002;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_yy_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse yy action
****************************************************************************/
unsigned int user_action::validate_yy_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/mobyy/navs?", 12))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_shijijiayuan_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse shijijiayuan action
****************************************************************************/
unsigned int user_action::validate_shijijiayuan_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/geo/fast_getid_cached.php? HTTP", 32))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}   

/****************************************************************************
Function Name:           validate_moji_weather_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse moji_weather action
****************************************************************************/
unsigned int user_action::validate_moji_weather_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/data/detail HTTP", 17))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_tianqitong_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse tianqitong action
****************************************************************************/
unsigned int user_action::validate_tianqitong_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/api.php?", 9))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_meituan_waimai_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse meituanwaimai action
****************************************************************************/
unsigned int user_action::validate_meituan_waimai_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/locate/v2/sdk/loc?", 19))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_liebao_browser_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse liebao browser action
****************************************************************************/
unsigned int user_action::validate_liebao_browser_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/cmb/hot?", 9))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_360_browser_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse 360 browser action
****************************************************************************/
unsigned int user_action::validate_360_browser_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/local?", 7))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_huangli_weather_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse huangli weather action
****************************************************************************/
unsigned int user_action::validate_huangli_weather_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/api/?", 6))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_go_weather_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse go weather action
****************************************************************************/
unsigned int user_action::validate_go_weather_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/goweatherex/city/gps?", 22))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_58tongcheng_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse 58tongcheng action
****************************************************************************/
unsigned int user_action::validate_58tongcheng_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/api/home/app/getindexinfo/?", 28))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_wannengkey_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse wannengkey action
****************************************************************************/
unsigned int user_action::validate_wannengkey_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/trace/data.do HTTP", strlen("/trace/data.do HTTP")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_zhwnl_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse zhwnl action
****************************************************************************/
unsigned int user_action::validate_zhwnl_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/Ecalender/api/city?", strlen("/Ecalender/api/city?")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_sinanews_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse sinanews action
****************************************************************************/
unsigned int user_action::validate_sinanews_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/?resource=activity/common", strlen("/?resource=activity/common")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_sougousearch_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse sougousearch action
****************************************************************************/
unsigned int user_action::validate_sougousearch_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/update_platform/update.php?", strlen("/update_platform/update.php?")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

/****************************************************************************
Function Name:           validate_youku_position_action
Input Parameters:        mails_byte, uri
Output Parameters:       void
Return Code:             type, 0 or !0
Description:             analyse youku action
****************************************************************************/
unsigned int user_action::validate_youku_position_action(unsigned int mails_byte, char *uri)
{
    unsigned int act_byte = 0;
    if(!strncmp(uri, "/adv/startpage?", strlen("/adv/startpage?")))
        act_byte = 0x0001;//获取地址信息
    else
        return 0;

    return mails_byte | act_byte;
}

