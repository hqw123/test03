#ifndef USERAGENT_H
#define USERAGENT_H

#include <string>
//#include <boost/regex.hpp>
#include "../PacketParser.h"

int useragent_init(void);
void useragent_cleanup(void);

void analyse_useragent(const PacketInfo *pktInfo);
void analyse_research_info(const PacketInfo *pktInfo);

bool get_research_info_os(std::string& os);
bool get_research_info_browser(std::string& browser);

bool is_os_windows(std::string &os);
bool is_os_linux(std::string &os);
bool is_os_mac(std::string &os);

bool is_browser_msie(std::string& browser);
bool is_browser_firefox(std::string& browser);
bool is_browser_chrome(std::string& browser);
bool is_browser_safari(std::string& browser);
bool is_browser_opera(std::string& browser);
bool is_browser_maxthon(std::string &browser);
bool is_browser_360se(std::string &browser);
bool is_browser_sogou(std::string &browser);
bool is_browser_qqbrowser(std::string &browser);
bool is_browser_tencenttraveler(std::string &browser);
bool is_browser_theworld(std::string &browser);
bool is_browser_konqueror(std::string &browser);

void store_research_info(const PacketInfo *pktInfo, const int nType, const char *info);

#endif /* USERAGETN_H */
