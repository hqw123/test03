#ifndef LZ_SITE_SWITCH_H
#define LZ_SITE_SWITCH_H

#define SWITCH_WANGYI 	(1<<16)
#define SWITCH_GOOGLE 	(2<<16)
#define SWITCH_MSN	(3<<16)
#define SWITCH_QQ	(4<<16)
#define SWITCH_SOHU	(5<<16)
#define SWITCH_YAHOO	(6<<16)
#define SWITCH_HANMAIL	(7<<16)
#define SWITCH_SINA	(9<<16)
#define SWITCH_MAX	512

#ifdef __cplusplus
extern "C" {
#endif

struct SSLswitch{
	int sslOn;
	int siteSwitch[SWITCH_MAX];
};
extern void* checkSwitch(void* path);
extern int isSwitchOn(int flag);
#ifdef __cplusplus
}
#endif

#endif
