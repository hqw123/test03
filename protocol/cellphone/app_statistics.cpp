/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : statistics.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing app statistics
*
* Evolution( Date | Author | Description ) 
* 2017.08.07 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/
#include <boost/regex.hpp>
#include <sys/time.h> 
#include <arpa/inet.h>

#include "app_statistics.h"
#include "db_data.h"
#include "clue_c.h"
#include "Analyzer_log.h"

static std::map<std::string, common_app> appstatistics_fun;
static statistics_mapnode appnode[] = {
    {"updatecenter.qq.com", do_qq},
    {"szextshort.weixin.qq.com", do_weixin},
    {"update.yy.com", do_yy},
    {"flow.wangwang.taobao.com", do_aliwangwang},
    {"popo.dl.126.net", do_wangyipopo},
    {"gray.cc.163.com", do_wangyicc},
    {"server.fetiononline.com", do_feixin},
    {"a.xnimg.cn", do_renrendesk},
    {"im.baidu.com", do_baiduhi},
    {"config.android.qqpy.sogou.com", do_qqpinyin},
    {"config.qqpy.sogou.com", do_qqwubi},
    {"ping.pinyin.sogou.com", do_sougoupinyin},
    {"ime.sogou.com", do_sougouwubi},
    {"update.wn51.com", do_wannengwubi},
    {"pinyin.engkoo.com", do_binpinyin},
    {"ossp.voicecloud.cn", do_ifly},
    {"www.unispim.com", do_huayupinyin},
    {"s.xinshuru.com", do_shouxininput},
    {"update.dfshurufa.com", do_dongfanginput},
    {"update.pinyin.2345.com", do_2345wangpai},
    {"shurufa.baidu.com", do_baidupinyin},
    {"ads.123.piadu.com", do_xiaoyaoinput},
    {"upgrade.xl9.xunlei.com", do_xunlei},
    {"fs-update.qq.com:80", do_qqxuanfeng},
    {"www.bingdian001.com", do_bingdianwenku},
    {"download.flvcd.com", do_shuoshuflv},
    {"update.easymule.com", do_dianlv},
    {"apps.bittorrent.com", do_uTorrent},
    {"update.lanspirit.net", do_bitspirit},
    {"irs01.com", do_flashget},
    {"desktop.youku.com", do_youku},
    {"btjoy.com", do_vagaa},
    {"googleads.g.doubleclick.net", do_xfplay},
    {"update.p2sp.baidu.com", do_baiduyingyin},
    {"config5.update.baofeng.com", do_baofengyingyin},
    {"upd.jjvod.com:999", do_jijiyingyin},
    {"text-ad.qvod.com", do_qvod},
    {"liveupdate.xigua.tv", do_xiguatv},
    {"conf.v.xunlei.com", do_xunleikankan},
    {"update.purecodec.com", do_purecode},
    {"potplayertv.daum.net", do_potplayer},
    {"upmobile.v.qq.com:1864", do_qqyingyin},
    {"search.vrs.sohu.com", do_souhuplayer},
    {"log.kmplayer.com", do_kmplayer},
    {"softstat.kugou.com", do_kugou},
    {"monitor.music.qq.com", do_qqmusic},
    {"tingapi.ting.baidu.com", do_baidumusic},
    {"www.kuwo.cn", do_kuwomusic},
    {"www.foobar2000.org", do_foobar2000},
    {"ttlrc.qianqian.com", do_qianqianjingting},
    {"musicbox2.sogou.com", do_sougoumusic},
    {"box2.9ku.com", do_jiukumusic},
    {"musicbox.1ting.com", do_yitingmusic},
    {"www.google-analytics.com", do_duomimusic},
    {"dsd.tiantianfm.com", do_tiantianmusic},
    {"log.xiami.com", do_xiamimusic},
    {"m7.music.126.net", do_wangyiyunmusic},
    {"data.meitu.com", do_meituxiuxiu_paipai},
    {"fodder.neoimaging.cn", do_guangyinkantu},
    {"cl.conew.com", do_keniuimage},
    {"www.theinpaint.com", do_inpaint},
    {"www.iseesoft.cn", do_isee},
    {"res.qhmsg.com", do_eosmsg},
    {"route.store.qq.com", do_qqimage},
    {"ad.winrar.com.cn", do_winrar},
    {"i.kpzip.com", do_kuaiya},
    {"zip.update.360safe.com", do_360zip},
    {"update.haozip.2345.com", do_2345haoya},
    {"update.winzip.com", do_winzip},
    {"cn.winmount.com", do_winmount},
    {"www.spidersoft.com", do_webzip},
    {"updateh.360safe.com", do_360safe},
    {"sdupm.360.cn", do_360shadu},
    {"hu005.www.duba.net", do_jinshanduba},
    {"up.ijinshan.com", do_jinshanweishi},
    {"rsup10.rising.com.cn", do_ruixing_shadu_safe},
    {"update.pcsafe.2345.com", do_2345safe},
    {"personal.avira-update.com", do_avira},
    {"iau.trendmicro.com.cn", do_qushikeji},
    {"repository.eset.com", do_nod32},
    {"v7event.stats.avast.com", do_avast},
    {"liveupdate.symantecliveupdate.com", do_nuodun},
    {"conna.gj.qq.com", do_qqguanjia},
    {"w.x.baidu.com", do_baidudefender},
    {"cidian.youdao.com", do_youdaodirectory},
    {"note.youdao.com", do_youdaonote},
    {"update.powerword.wps.cn", do_jinshanciba},
    {"datacollect.foxmail.com.cn", do_foxmail},
    {"download.endnote.com", do_endnote},
    {"community.adobe.com", do_adobe_acrobat_reader},
    {"app.xunjiepdf.com", do_caj_word},
    {"www.edrawsoft.com:443", do_edrawmax},
    {"hzs14.cnzz.com", do_ppt_word},
    {"go.microsoft.com", do_office2007},
    {"ifc.wps.cn", do_wps},
    {"sdkapp.mobile.sina.cn", do_a_sinaweibo},
    {"dns.weixin.qq.com", do_a_weixin},
    {"aeventlog.beacon.qq.com:8080", do_a_qq},
    {"www.immomo.com", do_a_momo},
    {"download.dewmobile.net", do_a_kuaiya},
    {"updateplf.yy.com", do_a_yy},
    {"input.shouji.sogou.com", do_a_sougoupinying},
    {"r6.mo.baidu.com", do_a_baiduinput},
    {"imupdate.3g.cn:8888", do_a_goinput},
    {"shouji.wn51.com", do_a_wannengwubi},
    {"ime.cdn.service.cootek.com", do_a_chubaoinput},
    {"dl.baofeng.com", do_a_baofengvideo},
    {"api.9xiu.com", do_a_jijivideo},
    {"s.p.youku.com", do_a_youku},
    {"tcconfig.1kxun.com", do_a_qianxunvideo},
    {"app.bilibili.com", do_a_bilibili},
    {"ichannel.snssdk.com", do_a_xiguavideo},
    {"ib.snssdk.com", do_a_toutiaovideo},
    {"android.api.360kan.com", do_a_360video},
    {"api.vrbig.com", do_a_3Dbobo},
    {"apis.tudou.com", do_a_tudouvideo},
    {"app.video.baidu.com", do_a_baiduvideo},
    {"policy.video.iqiyi.com", do_a_aiqiyi},
    {"config.video.51togic.com", do_taijievideo},
    {"s.webp2p.letv.com", do_a_kuaikanvideo},
    {"upgrade.m.xunlei.com", do_a_xunleivideo},
    {"t.live.cntv.cn", do_a_cctvvideo},
    {"apple.www.letv.com", do_a_letv},
    {"stat.funshion.net", do_a_fengxingvideo},
    {"s1.api.tv.itc.cn", do_a_56video},
    {"zs25.cnzz.com", do_a_xfplay},
    {"sdksp.video.qq.com", do_a_tencentvideo},
    {"update.mobile.kugou.com", do_a_kugou},
    {"music.163.com", do_a_163music},
    {"client.ctmus.cn", do_aimusic},
    {"hispaceclt.hicloud.com:8080", do_a_huaweimusic},
    {"iting.music.189.cn:9101", do_a_aiting4G},
    {"apphy.jyw8.com", do_a_DJmusic},
    {"www.8zhuayule.com", do_a_nitingmusic},
    {"woif.10155.com", do_a_womusic},
    {"commdata.v.qq.com", do_a_qqmusic},
    {"mobilead.kuwo.cn", do_a_kuwomusic},
    {"login.audiocn.org", do_a_tianlaiKge},
    {"oc.umeng.com", do_a_tiantiandongting},
    {"gmota.g188.net:8080", do_a_duomimusic},
    {"rprsv.richpush.cn:7700", do_a_migumusic},
    {"alog.umeng.com", do_a_DJduoduo},
    {"pic.xiami.net", do_a_xiamimusic},
    {"api.changba.com", do_a_changba},
    {"update.camera360.com", do_a_360camera},
    {"cdn.adapi.fotoable.com", do_a_wantu},
    {"phtj.poco.cn", do_a_pococamera},
    {"appops.multimedia.netease.com", do_a_loftcam},
    {"au.umeng.com", do_a_lvjinggezi},
    {"cc.naver.jp", do_a_linecamera},
    {"adapter.shouji.360.cn", do_a_360safe},
    {"p.spam.shouji.360.cn", do_a_360jike},
    {"www.lbesec.com", do_a_LBEsafe},
    {"s.360.cn", do_a_360jijiu},
    {"up.cm.ksmobile.com", do_a_liebaosafe},
    {"dl.sj.ijinshan.com", do_a_jinshanshoujiduba},
    {"java.yinshenxia.cn", do_a_yinshenxia},
    {"adv.sec.miui.com", do_a_xiaomisafe},
    {"hmma.baidu.com", do_a_baidusafe},
    {"vectormap0.bdimg.com", do_a_baiduditu},
    {"m5.amap.com", do_a_gaodeditu},
    {"m.ctrip.com", do_a_zhixingtrain_xiechengtravel},
    {"conf.diditaxi.com.cn", do_a_uber},
    {"client.qunar.com", do_a_qunaer},
    {"mobile-api2011.elong.com", do_a_yilongtravel},
    {"api.tuniu.com", do_a_tuniutravel},
    {"mobile.12306.cn", do_a_12306},
    {"allot.twosixonesix.com:443", do_a_coco},
    {"ace.naver.com", do_a_LINE},
    {"www.googleadservices.com", do_a_Qtalk},
    {"mobileads.nimbuzz.com", do_a_nimbuzz},
    {"shop.zalo.me", do_a_zalo},
    {"www.mytalkbox.com", do_a_talkbox},
    {"ec.androiddown.com", do_a_viber},
    {"facilitator.tango.me", do_a_tango},
};

/**************************************************************************************
Function Name:      app_statistics_map_init
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        初始化app统计模块对应的map里面的各成员
***************************************************************************************/
void app_statistics_map_init()
{
    int i;
    for(i = 0; i < sizeof(appnode) / sizeof(statistics_mapnode); i++)
    {
        appstatistics_fun.insert(pair<std::string, common_app>(appnode[i].hostname, appnode[i].function));
    }
}


int do_qq(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /queryversionupdate HTTP", 29))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_weixin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /cgi-bin/micromsg-bin/getupdateinfo HTTP", 45))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WEIXIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_yy(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /check4update?", 18))
    {
        *pc_mb = WINDOWS_APP;
        *proto = YY;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_aliwangwang(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /redirect?ver=", 18))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ALIWANGWANG;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_wangyipopo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /popo_2011/update/popo/v0/ServerVersion.xml HTTP", 52))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WANGYIPOPO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_wangyicc(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /verinfo?type=wonderful&version=", 36))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WANGYICC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_feixin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /email/subscribe/v1/tel:", 29))
    {
        *pc_mb = WINDOWS_APP;
        *proto = FEIXIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_renrendesk(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /wap/figure", 15))
    {
        *pc_mb = WINDOWS_APP;
        *proto = RENRENDESK;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_baiduhi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /search/error.html HTTP", 27))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAIDU_HI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqpinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /update HTTP", 17))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_PINYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /QQinput/pc/pydictid?", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_WUBI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_sougoupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /config.gif?", 16))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SOUGOU_PINYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_sougouwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /wbversion.txt?", 19))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SOUGOU_WUBI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_wannengwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "HEAD /updatev1.dat HTTP", 23))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WANNENG_WUBI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_binpinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /updatecheck.aspx?", 22))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BIN_PINYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_ifly(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "Content-Type: text/xml", 22))
    {
        *pc_mb = WINDOWS_APP;
        *proto = IFLY;
    }
    else if(!strncmp(uri, "POST /ossp/do.aspx?", 19))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_IFLY;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_huayupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /wordlib HTTP", 17))
    {
        *pc_mb = WINDOWS_APP;
        *proto = HUAYU_PINYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_shouxininput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update_result.htm?", 23))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SHOUXIN_INPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_dongfanginput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "HEAD /updatev1.dat HTTP", 23))
    {
        *pc_mb = WINDOWS_APP;
        *proto = DONGFANG_INPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_2345wangpai(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /check_new_version.php HTTP", 32))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WANGPAI2345;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_baidupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /dict.html HTTP", 19))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAIDU_PINYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_xiaoyaoinput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /xybclient.php?mod=broadcast", 32))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XIAOYAO_INPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_xunlei(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /pc?peerid=", 15))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XUNLEI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqxuanfeng(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /?name=qqdownload", 21))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_XUANFENG;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_bingdianwenku(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/\\?p=\\d+&id=\\d&ver=.+ HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BINGDIAN_WENKU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_shuoshuflv(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /bigrats_update/bigratesupdate.ini HTTP", 43))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SHUOSHU_FLV;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_dianlv(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /mini/win32/beta HTTP", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = DIANLV;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_uTorrent(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /utorrent-onboarding/welcome-upsell.btapp?", 46))
    {
        *pc_mb = WINDOWS_APP;
        *proto = UTORRRNT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_bitspirit(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /bsspu.php?", 15))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BITSPIRIT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_flashget(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /irt?_iwt_id=", 17))
    {
        *pc_mb = WINDOWS_APP;
        *proto = FLASHGET;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_youku(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update/upgrade.php?", 24))
    {
        *pc_mb = WINDOWS_APP;
        *proto = YOUKU;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_vagaa(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /text-ad.xml HTTP", 21))
    {
        *pc_mb = WINDOWS_APP;
        *proto = VAGAA;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_xfplay(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /pagead/ads?", 16) && strstr(uri, "www.xfplay.com"))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XFPLAY;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_baiduyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/BDPlayer\\/.+\\.xml HTTP\\/");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAIDU_YINGYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_baofengyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /GetUpgradeXml.php?", 23))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAOFENGYINGYIN;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_jijiyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET //ver.ini HTTP", 18))
    {
        *pc_mb = WINDOWS_APP;
        *proto = JIJIYINGYIN;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_qvod(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /hot.xml?", 13))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QVOD;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_xiguatv(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/.+\\/update\\.ini HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XIGUATV;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_xunleikankan(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /xmp5/onlinemd.lua HTTP", 27))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XUNBO;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_purecode(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /media_ver?ver=", 19))
    {
        *pc_mb = WINDOWS_APP;
        *proto = PURECODE;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_potplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /checksvc HTTP", 18))
    {
        *pc_mb = WINDOWS_APP;
        *proto = POTPLAYER;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_qqyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/\\?os=\\d&platform=\\d&app_platform=\\d");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_YINGYIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_souhuplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /client/c5?", 15))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SOUHU_PLAYER;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_kmplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /kmp?env=", 13) && strstr(uri, "update="))
    {
        *pc_mb = WINDOWS_APP;
        *proto = KMPLAYER;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_kugou(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/\\?actiontype=\\d&version=\\d+&");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = KUGOU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /fcgi-bin/fcg_access_express.fcg?", 37))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_baidumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /v1/restserver/ting?method=baidu.ting.user.checkSuggestVersion", 66))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAIDU_MUSIC;
    }
    else if(!strncmp(uri, "GET /v1/restserver/ting?from=android&version", 44))
    {
        *pc_mb = WINDOWS_APP;
        *proto = A_BAIDU_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0; 
}

int do_kuwomusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /api/pc/upgrade/info?", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = KUWO_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_foobar2000(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update-core?version=", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = FOOBAR2000;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qianqianjingting(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /dll/ttp_ver.asp?ver=", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QIANQIANJINTING;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_sougoumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /minipage/html/index.html HTTP", 34))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SOUGOU_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_jiukumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /client/upcfginstaller.xml HTTP", 35))
    {
        *pc_mb = WINDOWS_APP;
        *proto = JIUKU_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_yitingmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update/TTingUpCfg.ini HTTP", 31))
    {
        *pc_mb = WINDOWS_APP;
        *proto = YITING_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_duomimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /__utm.gif?", 15) && strstr(uri, "utmhn=www.duomiyy.com"))
    {
        *pc_mb = WINDOWS_APP;
        *proto = DUOMI_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_tiantianmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /release/get.do?", 20))
    {
        *pc_mb = WINDOWS_APP;
        *proto = TIANTIAN_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_xiamimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /pc?mid=", 12))
    {
        *pc_mb = WINDOWS_APP;
        *proto = XIAMI_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_wangyiyunmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET", 3) && strstr(uri, "ymusic"))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WANGYIYUN_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_meituxiuxiu_paipai(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /run.php?software=MTXX&version=", 35))
    {
        *pc_mb = WINDOWS_APP;
        *proto = MEITUXIUXIU;
    }
    else if(!strncmp(uri, "GET /run.php?software=MTPP&version=", 35))
    {
        *pc_mb = WINDOWS_APP;
        *proto = MEITUPAIPAI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_guangyinkantu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update/neo_viewer_stat_new.xml HTTP", 40))
    {
        *pc_mb = WINDOWS_APP;
        *proto = GUANGYINKANTU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_keniuimage(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /start_new.html?", 20))
    {
        *pc_mb = WINDOWS_APP;
        *proto = KENIU_IMAGE;
    }
    else
    {
        return -1;
    }

    return 0;
}


int do_inpaint(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /order.html HTTP", 20))
    {
        *pc_mb = WINDOWS_APP;
        *proto = INPAINT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_isee(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /iSee/update/cnfg.htm?", 26))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ISEE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_eosmsg(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /hips/popwnd/feedback.do?", 29))
    {
        *pc_mb = WINDOWS_APP;
        *proto = EOSMSG;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqimage(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/GetRoute\\?UIN=\\d+&type=xml&version=\\d HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_IMAGE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_winrar(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /show_2.html?", 17))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WINRAR;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_kuaiya(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /n/update/kb.xml HTTP", 25))
    {
        *pc_mb = WINDOWS_APP;
        *proto = KUAIYA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_360zip(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /v3/360zipupd_manual.cab HTTP", 33))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ZIP_360;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_2345haoya(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /check_new_version.php HTTP", 32))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ZIP_2345HAOYA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_winzip(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /cgi-bin/ipsc.cgi?ver=", 26))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WINZIP;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_winmount(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /xiazai.html HTTP", 21))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WINMOUNT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_webzip(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /webzip/start.asp HTTP", 27))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WEBZIP;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_360safe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /safe/checkupdate.ini?", 26))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SAFE_360;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_360shadu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/lib\\/\\d+/sdupbd\\.cab HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SHADU_360;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_jinshanduba(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/duba\\/\\d{4}\\/kcomponent\\/kcom_khackfix\\/\\w+\\.datx HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = JINSHANDUBA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_jinshanweishi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /safe/ksafeupdate.ini HTTP", 30))
    {
        *pc_mb = WINDOWS_APP;
        *proto = JINSHANWEISHI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_ruixing_shadu_safe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/rs\\d{4}\\/RssaVer\\.xml HTTP");
    if(!strncmp(uri, "GET /viruslib/vlstdver.xml HTTP", 31))
    {
        *pc_mb = WINDOWS_APP;
        *proto = RUIXINGSHADU;
    }else if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = RUIXINGSAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_2345safe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /check_new_version.php HTTP", 32))
    {
        *pc_mb = WINDOWS_APP;
        *proto = SAFE_2345;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_avira(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update/idx/master.idx HTTP", 31))
    {
        *pc_mb = WINDOWS_APP;
        *proto = AVIRA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qushikeji(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /iau_server.dll", 19))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QUSHIKEJI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_nod32(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "HEAD /v1/com/eset/apps/home/eav/windows/metadata2 HTTP", 54))
    {
        *pc_mb = WINDOWS_APP;
        *proto = NOD32;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_avast(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /cgi-bin/iavsevents.cgi HTTP", 33))
    {
        *pc_mb = WINDOWS_APP;
        *proto = AVAST;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_nuodun(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /minitri.flg HTTP", 21))
    {
        *pc_mb = WINDOWS_APP;
        *proto = NUODUN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_qqguanjia(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /q.cgi HTTP", 16))
    {
        *pc_mb = WINDOWS_APP;
        *proto = QQ_GUANJIA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_baidudefender(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /wspf/list?version=", 23))
    {
        *pc_mb = WINDOWS_APP;
        *proto = BAIDU_DEFENDER;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_youdaodirectory(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /apps/update5/fdictupdate.xml?ver=", 38))
    {
        *pc_mb = WINDOWS_APP;
        *proto = YOUDAO_DIRECTORY;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_youdaonote(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/update\\/manualupdateAfter\\d\\.\\d\\.xml\\?");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = WINDOWS_APP;
        *proto = YOUDAO_NOTE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_jinshanciba(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /updateserver/update?", 26))
    {
        *pc_mb = WINDOWS_APP;
        *proto = JINSHANCIBAO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_foxmail(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /cgi-bin/foxmailupdate?f=xml HTTP", 38))
    {
        *pc_mb = WINDOWS_APP;
        *proto = FOXMAIL;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_endnote(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /updates/18.0/EN18WinUpdates.xml HTTP", 41))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ENDNOTE;
    }
    else
    {
        return -1;
    }

    return 0;
}


int do_adobe_acrobat_reader(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /chcservices/services/redirect?", 35))
    {
        *pc_mb = WINDOWS_APP;
        *proto = ADOBE_ACROBAT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_caj_word(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /api/login HTTP", 20))
    {
        *pc_mb = WINDOWS_APP;
        *proto = CAJ_WORD;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_edrawmax(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update/getlatestversion.php HTTP", 37))
    {
        *pc_mb = WINDOWS_APP;
        *proto = EDRAW_MAX;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_ppt_word(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /stat.htm?", 14))
    {
        *pc_mb = WINDOWS_APP;
        *proto = PPT_WORD;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_office2007(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /fwlink/?linkid=", 20))
    {
        *pc_mb = WINDOWS_APP;
        *proto = OFFICE2007;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_wps(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /wpstracker/collection.do?WPS_Version=", 43))
    {
        *pc_mb = WINDOWS_APP;
        *proto = WPS;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_sinaweibo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /interface/sdk/sdkad.php HTTP", 34))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_SINAWEIBO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_weixin(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /cgi-bin/micromsg-bin/newgetdns?", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_WEIXIN;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_qq(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /analytics/upload?mType=beacon?", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_QQ;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_momo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /m/inc/androidupdate/?", 26))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_MOMO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_kuaiya(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /z/KuaiYa20_daily_release_zh.xml HTTP", 41))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_KUAIYA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_yy(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /check4update?", 18))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_YY;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_sougoupinying(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /SogouServlet?cmd=softwareupdate", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_SOUGOUPINYING;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_baiduinput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /v4/?c=vu&e=chkw", 21))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BAIDUINPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_goinput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /versions/check?", 20))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_GOINPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_wannengwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /Version/versionUpdate HTTP", 32))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_WANNENGWUBI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_chubaoinput(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /international/shop/v5870/default/resource/translation/zh_cn.json HTTP", 74))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_CHUBAOINPUT;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_baofengvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /mobile/user_check_update.xml HTTP", 38))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BAOFENGVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_jijivideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /v2/main?", 13))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_JIJIVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_youku(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /iku/log/acc HTTP", 22))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_YOUKU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_qianxunvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /api/configurations/yingshi_android_version.xml? HTTP", 57))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_QIANXUNVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_bilibili(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /si7/android/ver HTTP", 25))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BILIBILI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_xiguavideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /check_version/v6/?update_version_code", 42))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XIGUAVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_toutiaovideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /video/app/other/appupgrade/?os=android&version=", 52))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TOUTIAOVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_360video(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /upgrade/?", 14))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_360VIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_3Dbobo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /system/version?", 20))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_3DBOBO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tudouvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /config/v1/configuration/get_startup_configuration.json?platform=android", 76))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TUDOUVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_baiduvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /version/?appname=videoandroid&version=", 43))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BAIDUVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_aiqiyi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /policy.hcdnclient.qtpconfig.android.mobile.xml HTTP", 56))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_AIQIYI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_taijievideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /api/api_config?package=com_togic_livevideo&version_code", 60))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TAIJIEVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_kuaikanvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /upgrade?locVer=", 20))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_KUAIKANVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_xunleivideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /cgi-bin/upgrade?ver=", 25))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XUNLEIVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_cctvvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /livebeta/android/upxml.dll HTTP", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_CCTVVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_letv(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /op/?ver=", 13))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LETV;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_fengxingvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /ecom_mobile/bootstrap?", 27))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_FENGXINGVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_56video(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /mobile_user/version/checkver.json?", 39))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_56VIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_xfplay(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /stat.htm?", 14) && strstr(uri, "m.xfplay.com"))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XFPLAY;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tencentvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /getmfomat?model=", 21))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TENCENTVIDEO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_kugou(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /version/check?", 19))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_KUGOU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_163music(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /eapi/v1/android/version HTTP", 34))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_163_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_aimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /iting2/imusic/V2 HTTP", 27))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_AI_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_huaweimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /hwmarket/api/encryptApi2 HTTP", 35))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_HUAWEI_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_aiting4G(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /iting2/imusic/V2 HTTP", 27))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_AITING4G;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_DJmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /update.asp?UPversion=", 26))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_DJ_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_nitingmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /system.do?method=updVersion&version", 40))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_NITING_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_womusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("POST \\/interface\\/v\\d\\/client\\/version\\.do HTTP");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_WO_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_qqmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/commdatav2\\?cmd=\\d{2}&app_version_name=(\\d\\.){2}\\d");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_QQ_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_kuwomusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /MobileAdServer/getMotor.do?", 32))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_KUWO_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tianlaiKge(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /tian/user/tokenlogin.action?", 33))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TIANLAIkGE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tiantiandongting(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /check_config_update HTTP", 30))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TIANTAINDONGTING;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_duomimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /migusdk/verification/checkSdkUpdate HTTP", 46))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_DUOMIMUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_migumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /rsv/clientTag?", 20))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_GUMIMUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_DJduoduo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /app_logs HTTP", 19))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_DJDUODUO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_xiamimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /followhear", 15))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XIAMI_MUSIC;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_changba(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /ktvbox.php?ac=optionalconfigs_android", 42))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_CHANGBA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_360camera(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /VersionCheck/VersionCheck.aspx?", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_360_CAMERA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_wantu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /web/lwiv1?appid=com.wantu.activity&os=android", 50))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_WANTU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_pococamera(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/phone_tj\\.php\\?uid=\\d*&screen=(.*)&run_num=\\d&os=android");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_POCO_CAMERA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_loftcam(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /api/version/check HTTP", 28))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LOFTCAM;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_lvjinggezi(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /api/check_app_update HTTP", 31))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LVJINGGEZI;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_linecamera(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "GET /cc?nsc=androidapp.linecamera&a=exe.launchlog", 49))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LINE_CAMERA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_360safe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /Adapter HTTP", 18))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_360SAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_360jike(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /PersonalizedUpgrade HTTP", 18))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_360JIKE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_LBEsafe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /application_service2/manual-upgrade.action?", 49))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LBESAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_360jijiu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "GET /jijiu/mobi.html?", 21))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_360JIJIU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_liebaosafe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "GET /cmsecurity_cn/version_apk_new.php?", 38))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LIEBAOSAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_jinshanshoujiduba(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "GET /duba/update3/version_apk_initiative.ini HTTP", 49))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_JINSHANSHOUJIDUBA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_yinshenxia(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "GET /CheckVersion", 17))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_YINSHENXIA;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_xiaomisafe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /info/layout HTTP", 22))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XIAOMISAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_baidusafe(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{ 
    if(!strncmp(uri, "POST /app.gif HTTP", 18))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BAIDUSAFE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_baiduditu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /vecdata/?qt=version", 24))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_BAIDUDITU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_gaodeditu(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /ws/app/conf/app_update?", 29))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_GAODEDITU;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_zhixingtrain_xiechengtravel(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("POST \\/restapi\\/soa\\d\\/\\d+\\/json\\/GetStartPageADInfo HTTP");
    
    if(!strncmp(uri, "GET /restapi/buscommon/index.php?", 33))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_ZHIXINGTRAIN;
    }
    else if(boost::regex_search(uri, reg))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_XIECHENGTRAVEL;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_uber(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /api/update/index?", 22))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_UBER;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_qunaer(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /pitcher-proxy?qrt=p_login HTTP", 36))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_QUNAER;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_yilongtravel(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /user/userInfo?", 19))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_YILONGTRAVEL;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tuniutravel(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /apppack/config/monitor?", 28))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TUNIUTRAVEL;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_12306(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /otsmobile/pjsqj/plugin/5/version HTTP", 42))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_12306;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_coco(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /allot/mappings?cliver=", 27))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_COCO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_LINE(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /m?sn=initAndroid&t=st&app=linedeco", 39))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_LINE;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_Qtalk(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    boost::regex reg("GET \\/pagead\\/conversion\\/\\d+\\/\\?");
    
    if(boost::regex_search(uri, reg))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_QTALK;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_nimbuzz(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "GET /index.php?", 15))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_NUMBUZZ;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_zalo(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /market/do/getWelcomeMessage HTTP", 38))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_ZALO;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_talkbox(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /talkbox/api/availablePort?loginType", 41))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TALKBOX;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_viber(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /chat/app.php?cmd=login", 28))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_VIBER;
    }
    else
    {
        return -1;
    }

    return 0;
}

int do_a_tango(const char* uri, unsigned short* pc_mb, unsigned short* proto)
{
    if(!strncmp(uri, "POST /facilitator/rest/validation/v1/tango_validation", 53))
    {
        *pc_mb = ANDROID_APP;
        *proto = A_TANGO;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**************************************************************************************
Function Name:      store_db
Input Parameters:   void
Output Parameters:  void
Return Code:        void
Description:        存数据库
***************************************************************************************/
static void store_db(struct PacketInfo* packet, unsigned short pc_mb, unsigned short proto)
{
    struct in_addr addr;
    APPUSED_T tmp_data;

    memset(&tmp_data, 0, sizeof(tmp_data));
    tmp_data.p_data.readed = 0;
    addr.s_addr = packet->srcIpv4;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x\0", packet->srcMac[0]&0xff, packet->srcMac[1]&0xff, 
            packet->srcMac[2]&0xff, packet->srcMac[3]&0xff, packet->srcMac[4]&0xff, packet->srcMac[5]&0xff);
    
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, inet_ntoa(addr));
    sprintf(tmp_data.p_data.clientPort, "%d", packet->srcPort);
    addr.s_addr = packet->destIpv4;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", packet->destPort);
    tmp_data.p_data.captureTime = packet->pkt->ts.tv_sec;

    tmp_data.pc_mb = pc_mb;
    tmp_data.p_data.deleted = 0;
    tmp_data.p_data.proType = proto;
    
    msg_queue_send_data(APPUSED, (void *)&tmp_data, sizeof(tmp_data));
}

/**************************************************************************************
Function Name:          analyse_app_statistics
Input Parameters:       packet
    packet:             数据包的地址
Output Parameters:      void
Return Code:            -1:不是想要的数据包,0:是想要的数据包且处理ok
Description:            app统计模块解析的入口函数
**************************************************************************************/

int analyse_app_statistics(struct PacketInfo* packet)
{
    char* p1 = NULL,*p2 = NULL;
    std::string host_buf = "",uri_buf = "";
    unsigned short pc_mb = 0, proto = 0;
    
    if(packet->bodyLen == 0)
        return -1;

    p1 = strcasestr(packet->body, "Host:");
    if(p1)
    {
        p1 += strlen("Host: ");
        p2 = strstr(p1, "\r\n");
        if(p2)
        {
            host_buf.assign(p1, p2 - p1);
        }
        
        p1 = packet->body;
        p2 = strstr(p1, "\r\n");
        if(p2)
        {
            uri_buf.assign(p1, p2 - p1);
        }
    }
    else
    {
        return -1;
    }

    std::map<std::string, common_app>::iterator it = appstatistics_fun.find(host_buf);
    if(it != appstatistics_fun.end() && it->second && !it->second(uri_buf.c_str(), &pc_mb, &proto))
    {
        store_db(packet, pc_mb, proto);
    }
    else 
    {
        return -1;
    }
    
    return 0;
}
