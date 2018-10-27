#ifndef LUNTAN_H
#define LUNTAN_H

#include "basetalkspace.h"

enum
{
    BAIDU_TIEBA = 1,
    QIANGGUO,
    MAOPU,
    TIANYA,
    KAIDI_COMMUNITY,
    XINJIANG_MEDICAL_UNIVERSITY,
    XINJIANG_FINANCE_UNIVERSITY,
    XICIHUTONG,
};

class Luntan:public Basetalkspace
{
private:
	short luntan_type;
	
	std::string baidu_path;
	std::string qiangguo_path;
	std::string maopu_path;
	std::string tianya_path;
	std::string kaidi_path;
	std::string xjmu_path;
	std::string xjufe_path;
	std::string xicihutong_path;
    std::string store_path;

private:
    short get_luntan_type();
    std::string get_store_path(int type);
	
	int analyse_baidutieba();
	int analyse_qiangguoluntan();	
	int analyse_maopu();
	int analyse_tianya();
	int analyse_kaidicommunity();
	int analyse_Xinjiang_medical_university_luntan();
	int analyse_Xinjiang_finance_university_luntan();
	int analyse_xicihutong();
	
	int getluntan_content_title();
	int getluntan_reply_content();
	int getluntan_username();
    
    void decode_gbk(char** decode_content, int len);
    void clear_flag(char** addr,int len);
	void init();
	void storedb(int type);
	int store_file(int type);
	
public:
	Luntan();
	~Luntan();
	
	int analyse_luntan(common_tcp* tcp, common_http* http, int id);
};

#endif
