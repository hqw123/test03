#ifndef USERAGENT_M_H
#define USERAGENT_M_H

#include <string>
//#include <boost/regex.hpp>
#include "../PacketParser.h"

void analyse_useragent_m(const PacketInfo *pktInfo);

void analyse_research_info_m(const PacketInfo *pktInfo);

bool get_research_info_os_m(std::string& os);
bool get_research_info_browser_m(std::string& browser);
bool get_research_info_model_m(std::string& model);

bool is_os_android_m(std::string &os);
bool is_os_ios_m(std::string &os);

bool is_browser_uc_m(std::string& browser);
bool is_browser_safari_m(std::string& browser);

bool is_model_android_m(std::string& model);

void store_research_info_m(const PacketInfo *pktInfo, const int nType, const char *info);

#endif /* USERAGETN_H */
