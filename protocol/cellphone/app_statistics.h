/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : app_statistics.h
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
#ifndef  APP_STATISTICS_H
#define  APP_STATISTICS_H

#include <iostream>
#include <string>
#include <map>

typedef int (*common_app)(const char* uri, unsigned short* pc_mp, unsigned short* proto);

typedef struct statistics_code
{
    std::string hostname;
    common_app function;
}statistics_mapnode;

enum APP_TYPE
{
    WINDOWS_APP = 1,
    ANDROID_APP
};

enum app_number
{
    APP_STATISTICS = 25000,
	// windows app
    QQ = 25001,
    WEIXIN,
    YY,
    ALIWANGWANG,
    WANGYIPOPO,
    WANGYICC,
    FEIXIN,
    RENRENDESK,
    BAIDU_HI,
    QQ_PINYIN,
    SOUGOU_WUBI,
    SOUGOU_PINYIN,
    WANNENG_WUBI,
    BIN_PINYIN,
    IFLY,
    HUAYU_PINYIN,
    SHOUXIN_INPUT,
    DONGFANG_INPUT,
    WANGPAI2345,
    BAIDU_PINYIN,
    QQ_WUBI,
    XIAOYAO_INPUT,
    XUNLEI,
    QQ_XUANFENG,
    BINGDIAN_WENKU,
    SHUOSHU_FLV,
    DIANLV,
    UTORRRNT,
    BITSPIRIT,
    FLASHGET,
    YOUKU,
    VAGAA,
    XFPLAY,
    BAIDU_YINGYIN,
    BAOFENGYINGYIN,
    JIJIYINGYIN,
    QVOD,
    XIGUATV,
    XUNBO,
    PURECODE,
    POTPLAYER,
    QQ_YINGYIN,
    SOUHU_PLAYER,
    KMPLAYER,
    KUGOU,
    QQ_MUSIC,
    BAIDU_MUSIC,
    KUWO_MUSIC,
    FOOBAR2000,
    QIANQIANJINTING,
    SOUGOU_MUSIC,
    JIUKU_MUSIC,
    YITING_MUSIC,
    DUOMI_MUSIC,
    TIANTIAN_MUSIC,
    XIAMI_MUSIC,
    WANGYIYUN_MUSIC,
    MEITUXIUXIU,
    MEITUPAIPAI,
    GUANGYINKANTU,
    KENIU_IMAGE,
    INPAINT,
    ISEE,
    EOSMSG,
    QQ_IMAGE,
    WINRAR,
    KUAIYA,
    ZIP_360,
    ZIP_2345HAOYA,
    WINZIP,
    WINMOUNT,
    BANDIZIP,
    WEBZIP,
    SAFE_360,
    SHADU_360,
    JINSHANDUBA,
    JINSHANWEISHI,
    RUIXINGSHADU,
    RUIXINGSAFE,
    SAFE_2345,
    AVIRA,
    QUSHIKEJI,
    NOD32,
    AVAST,
    NUODUN,
    QQ_GUANJIA,
    BAIDU_DEFENDER,
    YOUDAO_DIRECTORY,
    YOUDAO_NOTE,
    JINSHANCIBAO,
    FOXMAIL,
    ENDNOTE,
    ADOBE_ACROBAT,
    CAJ_WORD,
    EDRAW_MAX,
    PPT_WORD,
    OFFICE2007,
    WPS,
	// android app
    A_SINAWEIBO,
    A_WEIXIN,
    A_QQ,
    A_MOMO,
    A_KUAIYA,
    A_YY,
    A_SOUGOUPINYING,
    A_BAIDUINPUT,
    A_IFLY,
    A_GOINPUT,
    A_WANNENGWUBI,
    A_CHUBAOINPUT,
    A_BAOFENGVIDEO,
    A_JIJIVIDEO,
    A_YOUKU,
    A_QIANXUNVIDEO,
    A_BILIBILI,
    A_XIGUAVIDEO,
    A_TOUTIAOVIDEO,
    A_360VIDEO,
    A_3DBOBO,
    A_TUDOUVIDEO,
    A_BAIDUVIDEO,
    A_AIQIYI,
    A_TAIJIEVIDEO,
    A_KUAIKANVIDEO,
    A_XUNLEIVIDEO,
    A_CCTVVIDEO,
    A_LETV,
    A_FENGXINGVIDEO,
    A_56VIDEO,
    A_XFPLAY,
    A_TENCENTVIDEO,
    A_KUGOU,
    A_163_MUSIC,
    A_BAIDU_MUSIC,
    A_AI_MUSIC,
    A_HUAWEI_MUSIC,
    A_AITING4G,
    A_DJ_MUSIC,
    A_NITING_MUSIC,
    A_WO_MUSIC,
    A_QQ_MUSIC,
    A_KUWO_MUSIC,
    A_TIANLAIkGE,
    A_TIANTAINDONGTING,
    A_DUOMIMUSIC,
    A_GUMIMUSIC,
    A_DJDUODUO,
    A_XIAMI_MUSIC,
    A_CHANGBA,
    A_360_CAMERA,
    A_WANTU,
    A_POCO_CAMERA,
    A_LOFTCAM,
    A_LVJINGGEZI,
    A_LINE_CAMERA,
    A_360SAFE,
    A_360JIKE,
    A_LBESAFE,
    A_360JIJIU,
    A_LIEBAOSAFE,
    A_JINSHANSHOUJIDUBA,
    A_YINSHENXIA,
    A_XIAOMISAFE,
    A_BAIDUSAFE,
    A_BAIDUDITU,
    A_GAODEDITU,
    A_ZHIXINGTRAIN,
    A_UBER,
    A_QUNAER,
    A_YILONGTRAVEL,
    A_XIECHENGTRAVEL,
    A_TUNIUTRAVEL,
    A_12306,
    A_COCO,
    A_LINE,
    A_QTALK,
    A_NUMBUZZ,
    A_ZALO,
    A_TALKBOX,
    A_VIBER,
    A_TANGO,
};

int analyse_app_statistics(struct PacketInfo* packet);
int do_qq(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_weixin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_yy(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_aliwangwang(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_wangyipopo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_wangyicc(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_feixin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_renrendesk(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baiduhi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqpinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_sougouwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_sougoupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_wannengwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_binpinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_ifly(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_huayupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_shouxininput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_dongfanginput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_2345wangpai(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baidupinyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xiaoyaoinput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xunlei(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqxuanfeng(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_bingdianwenku(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_shuoshuflv(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_dianlv(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_uTorrent(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_bitspirit(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_flashget(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_youku(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_vagaa(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xfplay(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baiduyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baofengyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_jijiyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qvod(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xiguatv(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xunleikankan(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_purecode(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_potplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqyingyin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_souhuplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_kmplayer(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_kugou(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baidumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_kuwomusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_foobar2000(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qianqianjingting(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_sougoumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_jiukumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_yitingmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_duomimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_tiantianmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_xiamimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_wangyiyunmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_meituxiuxiu_paipai(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_guangyinkantu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_keniuimage(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_inpaint(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_isee(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_eosmsg(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqimage(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_winrar(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_kuaiya(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_360zip(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_2345haoya(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_winzip(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_winmount(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_bandizip(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_webzip(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_360safe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_360shadu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_jinshanduba(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_jinshanweishi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_ruixing_shadu_safe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_2345safe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_avira(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qushikeji(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_nod32(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_avast(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_nuodun(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_qqguanjia(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_baidudefender(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_youdaodirectory(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_youdaonote(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_jinshanciba(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_foxmail(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_endnote(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_adobe_acrobat_reader(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_caj_word(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_edrawmax(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_ppt_word(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_office2007(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_wps(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_sinaweibo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_weixin(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_qq(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_momo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_kuaiya(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_yy(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_sougoupinying(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_baiduinput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_goinput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_wannengwubi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_chubaoinput(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_baofengvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_jijivideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_youku(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_qianxunvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_bilibili(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_xiguavideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_toutiaovideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_360video(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_3Dbobo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tudouvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_baiduvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_aiqiyi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_taijievideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_kuaikanvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_xunleivideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_cctvvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_letv(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_fengxingvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_56video(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_xfplay(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tencentvideo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_kugou(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_163music(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_aimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_huaweimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_aiting4G(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_DJmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_nitingmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_womusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_qqmusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_kuwomusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tianlaiKge(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tiantiandongting(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_duomimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_migumusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_DJduoduo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_xiamimusic(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_changba(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_360camera(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_wantu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_pococamera(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_loftcam(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_lvjinggezi(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_linecamera(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_360safe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_360jike(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_LBEsafe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_360jijiu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_liebaosafe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_jinshanshoujiduba(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_yinshenxia(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_xiaomisafe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_baidusafe(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_baiduditu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_gaodeditu(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_zhixingtrain_xiechengtravel(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_uber(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_qunaer(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_yilongtravel(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tuniutravel(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_12306(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_coco(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_LINE(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_Qtalk(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_nimbuzz(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_zalo(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_talkbox(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_viber(const char* uri, unsigned short* pc_mb, unsigned short* proto);
int do_a_tango(const char* uri, unsigned short* pc_mb, unsigned short* proto);
void app_statistics_map_init();

#endif
