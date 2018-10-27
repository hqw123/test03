/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : imei.cpp
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

#include <sys/time.h> 
#include <arpa/inet.h>
#include <boost/regex.hpp>

#include "imei.h"
#include "db_data.h"
#include "clue_c.h"
#include "Analyzer_log.h"

static std::map<string, common_imei> imei_fun;

static imei_mapnode appnode[] = {
    {"log.reyun.com", do_aiwujiwu},
    {"mapi.dianping.com", do_dazhongcomment},
    {"wgo.mmstat.com", do_gaodeditu},
    {"api-unionid.meituan.com", do_meituan},
    {"apikey.map.qq.com", do_qqlite},
    {"mobile-api2011.elong.com", do_yilong},
    {"masdk.3g.qq.com", do_weixin},
    {"mcgi.v.qq.com", do_tencent_news_tim},
    {"api.iclient.ifeng.com", do_ifeng_news},
    {"mobilead.kuwo.cn", do_kuwo_music},
    {"m.aty.sohu.com", do_souhu_video},
    {"dynamic.app.m.letv.com", do_letv},
    {"api.k.sohu.com", do_souhu_news},
    {"app.video.baidu.com", do_baidu_video},
    {"httpdns.m.jd.com", do_jd},
    {"ib.snssdk.com", do_today_toutiao},
    {"config.mobile.kugou.com", do_kugou},
    {"commdata.v.qq.com", do_qq_music},
    {"data.video.iqiyi.com", do_aiqiyi},
    {"push.m.youku.com", do_youku},
    {"res.3g.yy.com", do_yy},
    {"49453k0l.vr.loveota.com", do_douyu},
    {"crash-reporting.yy.com", do_huya},
    {"api.jiayuan.com", do_shijijiayuan},
    {"c.wkanx.com", do_wannengwifi},
    {"me.api.moji.com", do_moji_weather},
    {"forecast.sina.cn", do_tianqitong},
    {"nativetqkb.dftoutiao.com", do_weather_kb},
    {"cr.m.liebao.cn", do_liebao_browser},
    {"sdkapp.mobile.sina.cn", do_sinaweibo},
    {"wmapi.meituan.com", do_meituanwaimai},
    {"sdksp.video.qq.com", do_qq},
};

/**************************************************************************************
Function Name:      imei_map_init
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        ?????imei?????map??????
***************************************************************************************/
void imei_map_init()
{
    for(int i = 0; i < sizeof(appnode) / sizeof(imei_mapnode); i++)
    {
        imei_fun.insert(pair<std::string, common_imei>(appnode[i].hostname, appnode[i].function));
    }
}

/**************************************************************************************
Function Name:      do_aiwujiwu
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_aiwujiwu(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	  
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /receive/tkio/register HTTP", 32))
    {
        p1 = strstr(body, "\"_imei\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"_imei\":\"");
        p2 = strchr(p1, '\"');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));
        
        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_dazhongcomment
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_dazhongcomment(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /mapi/collect/geth5favorconfig.bin HTTP", 43))
    {
        p1 = strstr(body, "pragma-device: ");
        if(!p1)
            return -1;

        p1 += strlen("pragma-device: ");
        p2 = strstr(p1, "\r\n");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_gaodeditu
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_gaodeditu(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /minitrade.", 16))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_meituan
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_meituan(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "PUT /unionid/android/update HTTP", 32))
    {
        p1 = strstr(body, "\"simulateId\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"simulateId\":\"");
        p2 = strchr(p1, '\"');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_qqlite
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??qq????imei?
***************************************************************************************/
int do_qqlite(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /mkey/index.php/mkey/check?", 31))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_yilong
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_yilong(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /mtools/getVersionInfo?", 27))
    {
        p1 = strstr(body, "Guid: ");
        if(!p1)
            return -1;

        p1 += strlen("Guid: ");
        p2 = strstr(p1, "\r\n");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_weixin
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_weixin(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
    
    const char *p = NULL;
   
    if(!strncmp(body, "POST / HTTP", 11))
    {
        boost::cmatch mat;
        boost::regex reg("NA&NA&V3@\\D{4}\\d{15}");
        
        if(boost::regex_search((const char*)body, (const char*)body + bodylen, mat, reg))
        {
            p = mat.str(0).c_str() + 13;
            strncpy(imei, p, IMEI_LEN);
        }
        else
        {
            return -1;
        }
        
        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_tencent_news
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_tencent_news_tim(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /commdatav2?install_time", 28))
    {
        p1 = strstr(body, "device_id=");
        if(!p1)
            return -1;

        p1 += strlen("origin_imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    else if(!strncmp(body, "GET /commdatav2?cmd", 19))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    else
    {
        return -1;
    }
}

/**************************************************************************************
Function Name:      do_ifeng_news
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_ifeng_news(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /ifengNewsKeepLiveConfig?", 29))
    {
        p1 = strstr(body, "deviceid=");
        if(!p1)
            return -1;

        p1 += strlen("deviceid=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_kuwo_music
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_kuwo_music(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /EcomResourceServer/getMotor.do?", 36))
    {
        p1 = strstr(body, "cid=");
        if(!p1)
            return -1;

        p1 += strlen("cid=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_souhu_video
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_souhu_video(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /openload?", 14))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_letv
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_letv(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /android/dynamic.php?", 25))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_souhu_news
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_souhu_news(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /api/client/config.go?", 26))
    {
        p1 = strstr(body, "Authorization:");
        if(!p1)
            return -1;

        p1 += strlen("Authorization: ");
        p2 = strstr(p1, "\r\n");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_baidu_video
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_baidu_video(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /bootimg/?", 15))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_jd
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ????????imei?
***************************************************************************************/
int do_jd(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /d?dn=api.m.jd.com HTTP", 27))
    {
        p1 = strstr(body, "uuid=");
        if(!p1)
            return -1;

        p1 += strlen("uuid=");
        p2 = strchr(p1, '-');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_today_toutiao
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_today_toutiao(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /concern/v2/follow/my_follow/?", 35))
    {
        p1 = strstr(body, "uuid=");
        if(!p1)
            return -1;

        p1 += strlen("uuid=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_kugou
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_kugou(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /api/v2/config/index?", 25))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_qq_music
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??qq???imei?
***************************************************************************************/
int do_qq_music(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /commdatav2?cmd=", 20))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_aiqiyi
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??????imei?
***************************************************************************************/
int do_aiqiyi(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	 
    char* p1 = NULL, *p2 = NULL;
    
    if (!strncmp(body, "GET /v.f4v HTTP", 15))
    {
        p1 = strstr(body, "qyid:");
        if (!p1)
            return -1;

        p1 += strlen("qyid:");
        p2 = strstr(p1, "\r\n");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_youku
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_youku(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei); 
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /collect-api/get_push_interval_config?", 42))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_yy
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??yy?imei?
***************************************************************************************/
int do_yy(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei); 
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /config/m/android/broadCastGroupFilter.json?", 48))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_douyu
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_douyu(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	  
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /picksdkgame.php?", 21))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_huya
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ?????imei?
***************************************************************************************/
int do_huya(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /dau/reporting HTTP", 24))
    {
        p1 = strstr(body, "\"imei\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"imei\":\"");
        p2 = strstr(p1, "\",");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_shijijiayuan
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_shijijiayuan(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /mobile/get_version.php? HTTP", 34))
    {
        p1 = strstr(body, "deviceid=");
        if(!p1)
            return -1;

        p1 += strlen("deviceid=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_wannengwifi
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_wannengwifi(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);

    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /opscr HTTP", 16))
    {
        p1 = strstr(body, "\"imei\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"imei\":\"");
        p2 = strchr(p1, '\"');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_moji_weather
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_moji_weather(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /json/entrance/list HTTP", 29))
    {
        p1 = strstr(body, "\"identifier\":\"");
        if(!p1)
            return -1;

        p1 += strlen("\"identifier\":\"");
        p2 = strchr(p1, '\"');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_tianqitong
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??????imei?
***************************************************************************************/
int do_tianqitong(char* body,  unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /app/overall/stat.php?", 26))
    {
        p1 = strstr(body, "uid=");
        if(!p1)
            return -1;

        p1 += strlen("uid=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_weather_kb
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_weather_kb(char* body, unsigned int bodylen,  char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /admethod/appad?", 20))
    {
        p1 = strstr(body, "imei%22:%22");
        if(!p1)
            return -1;

        p1 += strlen("imei%22:%22");
        p2 = strchr(p1, '%');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_liebao_browser
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ????????imei?
***************************************************************************************/
int do_liebao_browser(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /location/city?", 19))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_sinaweibo
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_sinaweibo(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);
	
    char* p1 = NULL, *p2 = NULL;
    if(!strncmp(body, "POST /interface/sdk/actionad.php HTTP", 37))
    {       
        p1 = strstr(body, "aduserid%22%3A%22");
        if(!p1)
            return -1;
        
        p1 += strlen("aduserid%22%3A%22");
        p2 = strstr(p1, "%22");
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));
        
        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_meituanwaimai
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ???????imei?
***************************************************************************************/
int do_meituanwaimai(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);

    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "POST /api/v6/user/address/getaddr?", 34))
    {
        p1 = strstr(body, "utm_content=");
        if(!p1)
            return -1;

        p1 += strlen("utm_content=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      do_qq
Input Parameters:   body
Output Parameters:  imei
Return Code:        int
Description:        ??QQ?imei?
***************************************************************************************/
int do_qq(char* body, unsigned int bodylen, char* imei)
{
    ASSERT_I(body, bodylen, imei);

    char* p1 = NULL, *p2 = NULL;
    
    if(!strncmp(body, "GET /getmfomat?", 15))
    {
        p1 = strstr(body, "imei=");
        if(!p1)
            return -1;

        p1 += strlen("imei=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;
        
        strncpy(imei, p1, (p2 - p1) > IMEI_LEN ? IMEI_LEN : (p2 - p1));

        return 0;
    }
    
    return -1;
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   packet, imei
Output Parameters:  void
Return Code:        void
Description:        ????
***************************************************************************************/
void store_db(struct PacketInfo* packet, char* imei)
{
    struct in_addr addr;
    IMEI_T tmp_data;

    memset(&tmp_data, 0, sizeof(tmp_data));
    tmp_data.p_data.readed = 0;
    addr.s_addr = packet->srcIpv4;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x\0", packet->srcMac[0]&0xff, packet->srcMac[1]&0xff, 
            packet->srcMac[2]&0xff, packet->srcMac[3]&0xff, packet->srcMac[4]&0xff, packet->srcMac[5]&0xff);
    
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);
    sprintf(tmp_data.p_data.clientPort, "%d", packet->srcPort);
    addr.s_addr = packet->destIpv4;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", packet->destPort);
    tmp_data.p_data.captureTime = packet->pkt->ts.tv_sec;

    strncpy(tmp_data.imei, imei, 15);
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = IMEI_PROTO;
    
    msg_queue_send_data(CELLPHONE_IMEI, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:          analyse_imei
Input Parameters:       packet
    packet:             ??????
Output Parameters:      void
Return Code:            -1:????????,0:??????????ok
Description:            ??imei?????????
**************************************************************************************/
int analyse_imei(struct PacketInfo* packet)
{
    char *p1 = NULL, *p2 = NULL;
    std::string host_buf;
    char phone_imei[IMEI_LEN + 1] = {0};
    
    if (packet == NULL || packet->body == NULL || packet->bodyLen == 0 || packet->destPort != 80)
        return -1;

    p1 = strcasestr(packet->body, "Host:");
    if (p1)
    {
        p1 += strlen("Host: ");
        p2 = strstr(p1, "\r\n");
        if (!p2)
            return -1;
        
        host_buf.assign(p1, p2 - p1);
    }
    else
    {
        return -1;
    }

    std::map<std::string, common_imei>::iterator it = imei_fun.find(host_buf);
    if (it != imei_fun.end() && it->second && !it->second(packet->body, packet->bodyLen , phone_imei))
    {
        store_db(packet, phone_imei);
    }
    else 
    {
        return -1;
    }
    
    return 0;
}

