#ifndef WLZ_SYS_INFO_H
#define WLZ_SYS_INFO_H

#define OS_WINDOWS_XP			100
#define OS_WINDOWS_7			101
#define OS_WINDOWS_VISTA		102
#define OS_WINDOWS_SERVER_2003		103
#define OS_WINDOWS_2000			104
#define OS_WINDOWS_NT			105
#define OS_WINDOWS_CE			106
#define OS_WINDOWS_ME			107
#define OS_WINDOWS_98			108
#define OS_WINDOWS_95			109
#define OS_LINUX			110
#define OS_IPHONE_OS			111
#define OS_MAC_OS_X			112

#define BROWSER_QQBROWSER		200
#define BROWSER_TENCENTTRAVELER		201
#define BROWSER_MAXTHON			202
#define BROWSER_360SE			203
#define BROWSER_SOGOU			204
#define BROWSER_THEWORLD		205
#define BROWSER_OPERA			206
#define BROWSER_KONQUEROR		207
#define BROWSER_CHROME			208
#define BROWSER_SAFARI			209
#define BROWSER_FIREFOX			210
#define BROWSER_MSIE			211

#define AV_360SD			300
#define AV_360SAFE			301
#define AV_KIS				302
#define AV_KSAVE			303
#define AV_JIANGMIN			304
#define AV_RISING			305
#define AV_KAV				306
#define AV_AVIRA			307
#define AV_NORTON			308
#define AV_NOD32			309

#define IME_SOGOU_PINYIN		400
#define IME_QQ_PINYIN			401

#define FILE_MAGIC_HORSE		1
#define FILE_MAGIC_SYSINFO		2

#define TROJAN_HORSE_PATH "/spy/bin/horseStat.data"
#define SYS_INFO_PATH "/spy/bin/sysinfo.data"


struct wTrojanHorse{
	unsigned int type;
	unsigned int status;
	unsigned int time;
};

struct wSysInfo{
	unsigned int os;
	unsigned int browser;
	unsigned int browserVersion;
	unsigned int antivirus;
	unsigned int antiVersion;
	unsigned int IME;
	unsigned int imeVerion;
};

#endif /* sysinfo.h */
