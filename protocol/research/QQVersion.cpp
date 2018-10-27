
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
//#include <boost/regex.hpp>
#include <iostream>

#include "QQVersion.h"
// #include "../PacketParser.h"
#include "clue_c.h"
#include "db_data.h"

#define MIN_PKT_LEN 12
#define QQ_HEAD     0x02
#define QQ_END      0x03
#define QQ_COMMAND  4

#define QQ_LOGIN    0x22
#define QQ_LOGOUT   0x01
// #define QQ_SEND     0x16
// #define QQ_V09_SEND 0xcd
// #define QQ_V08_SENDLS 0xe1
// #define QQ_V10_SENDLS 0xe2
// #define QQ_RECV     0x17
// #define QQ_V10_RECV 0xce

#define QQ_2008TAG 0x2112       //QQ2008正式版

#define QQ_2010TAG 0x511c       //QQ2010正式版
#define QQ_2010TAG2 0x571f      //QQ2010正式版SP3.1

#define QQ_2011TAG 0x0721       //QQ2011beta1
#define QQ_2011TAG2 0x2722      //QQ2011beta2
#define QQ_2011TAG3 0x5d22      //QQ2011beta3
#define QQ_2011TAG4 0x1525      //QQ2011beta4
#define QQ_2011TAG4_2 0x1b25    //QQ2011beta4(QQProtect1.2)体验版
#define QQ_2011TAG5 0x2f26
#define QQ_2011TAG6 0x5128      //QQ2011正式版
#define QQ_2011TAG7 0x5f26      //QQ2011(QQProtect2.0)
#define QQ_2011TAG8 0x1d29      //QQ2011(QQProtect2.1) 2011-12-14
#define QQ_2011TAG9 0x2551      //QQ2011正式版 2012-01-31
#define QQ_2011TAGA 0x4129      //QQ2011(QQProtect2.1) 2012-02-02

#define Q_2011TAG 0x6328        //QQ2011正式版(Q+) 2011-11-22
#define Q_2011TAG2 0x5728       //QQ2011正式版(Q+) 2011-12-06
#define Q_2011TAG3 0x0529       //QQ2011正式版(Q+) 2012-1-5
#define Q_2011TAG4 0x3529       //QQ2011正式版(Q+) 2012-1-12 & 2012-02-01 & 2012-02-15

#define QQ_2011EXP 0x5926       //QQ2011实验版 2011-11-14——2012-1-14

#define QQ_2012TAG 0x212b       //QQ2012Beta1 2012-03-01
#define QQ_2012TAG2 0x272b      //QQ2011(QQProtect2.5) 2012-03-08
#define QQ_2012TAG3 0x3e65      //QQ2012Beta1 2012-03-16
#define QQ_2012TAG4 0x332b      //QQ2011(QQProtect2.5) 2012-03-21
#define QQ_2012TAG5 0x012d      //QQ2012Beta1 2012-03-29 & QQ2012 Beta1(Q+) 2012-03-31
#define QQ_2012TAG6 0x1f2d	//QQ2012Beta1 2012-04-12
#define QQ_2012TAG7 0x4b2b      //QQ2012Beta1(QQProtect2.6) 2012-04-18
#define QQ_2012TAG8 0x3d2d      //QQ2012Beta1 2012-04-26 QQ2012Beta1(Q+) 2012-04-28 05-07
#define QQ_2012TAG9 0x432d      //QQ2012Beta1(QQProtect2.6.1) 2012-05-15
#define QQ_2012TAGA 0x092e      //QQ2012Beta2 2012-05-24
#define QQ_2012TAGB 0x4f2d      //QQ2012Beta1(Q+) 2012-05-30 2012-06-08
#define QQ_2012TAGC 0x4b2e      //QQ2012Beta2 2012-06-04 2012-06-11
#define QQ_2012TAGD 0x512e      //QQ2012Beta2(QQProtect2.7) 2012-06-14
#define QQ_2012TAGE 0x5d2e      //QQ2012Beta2(Q+) 2012-06-20
#define QQ_2012TAGF 0x1d2f      //QQ2012Beta3体验版 2012-07-04
#define QQ_2012TAGG 0x232f      //QQ2012Beta3 2012-07-16
#define QQ_2012TAGH 0x352f      //QQ2012Beta3 2012-07-30
#define QQ_2012TAGI 0x292f      //QQ2012Beta3(QQProtect2.8) 2012-08-15
#define QQ_2012TAGJ 0x592f      //QQ2012正式版 2012-08-30
#define QQ_2012TAGK 0x1930      //QQ2012正式版(QQProtect3.0) 2012-10-30
#define QQ_2012TAGL 0x1330      //QQ2012正式版 2012-10-25
#define QQ_2013TAG 0x3730       //QQ2013Beta1 2012-11-29
#define QQ_2013TAG2 0x0331      //QQ2013Beta2 2013-01-08 QQ2013新春版 2013-04-15
#define QQ_2013TAG3 0x1732      //QQ2013新春版 2013-01-22
#define QQ_2013TAG4 0x3b32      //QQ2013新春版 2013-02-28
#define QQ_2013TAG5 0x4132      //QQ2013新春版 2013-03-21 2013-03-28 2013-04-08
#define QQ_2013TAG6 0x4d32      //QQ2013轻聊版 2013-04-22(Beta3)
#define QQ_2013TAG7 0x5932      //QQ2013轻聊版 2013-05-20(Beta4)
#define QQ_2013TAG8 0x0133      //QQ2013轻聊版 2013-06-07(Beta5)
#define QQ_2013TAG9 0x0334      //QQ2013轻聊版 2013-07-09(Beta6)
#define QQ_2013TAG10 0x0f34      //QQ2013正式版
#define QQ_2013TAG11 0x1034      //QQ2013网吧安全版(QQProtect3.4.3.2) 2013-08-13
#define QQ_2013TAG12 0x1b34      //QQ2013正式版SP1 2013-08-21 2013-08-28
#define QQ_2013TAG13 0x2734      //QQ2013正式版SP2 2013-09-09
#define QQ_2013TAG14 0x3334      //QQ2013正式版SP3 2013-10-10
#define QQ_2013TAG15 0x3f34      //QQ2013正式版SP4 2013-10-31
#define QQ_2013TAG16 0x4b34      //QQ2013正式版SP5 2013-11-21
#define QQ_2013TAG17 0x5134      //QQ2013正式版SP6 2013-12-12 2014-01-03
#define QQ_2014TAG 0x5734       //QQ5.0 2014-01-16
#define QQ_2014TAG2 0x0535       //QQ5.1 2014-02-19
#define QQ_2014TAG3 0x0b35       //QQ5.2 2014-03-17
#define QQ_2014TAG4 0x1135       //QQ5.3 2014-04-09
#define QQ_2014TAG5 0x1d35       //QQ5.4 2014-05-06
#define QQ_2014TAG6 0x2335       //QQ5.5 2014-06-05
#define QQ_2014TAG7 0x2935       //QQ6.0 2014-07-03
#define QQ_2014TAG8 0x2f35       //QQ6.1 2014-07-16
#define QQ_2014TAG9 0x3535       //QQ6.2 2014-08-13

using namespace std;


static char *ParseMac(const u_char *packet, char *mac);

QQVersion::QQVersion()
{

}


bool QQVersion::Match(const PacketInfo *pktInfo)
{ 
	bool isMatched = false;
	u_short minLen = 0;

	if (pktInfo->pktType == TCP) 
	{
		minLen = MIN_PKT_LEN + 2;
		offside_ = 2;
	}
	else
	{
		minLen = MIN_PKT_LEN;
		offside_ = 0;
	}
	
	if (pktInfo->bodyLen > minLen &&
		pktInfo->destPort == 8000 &&
		   *(pktInfo->body + offside_) == QQ_HEAD &&
		   *(pktInfo->body + pktInfo->bodyLen - 1) == QQ_END) 
	{
		qqCommand_ = *reinterpret_cast<const u_char*>(pktInfo->body + offside_ + QQ_COMMAND);
		switch (qqCommand_) 
		{
//	    	case QQ_V08_RL:
//	    	case QQ_RL:
// 			case QQ_SEND:
// 			case QQ_V09_SEND:
// 			case QQ_V08_SENDLS:
// 			case QQ_V10_SENDLS:
			case QQ_LOGOUT:
			case QQ_LOGIN:
// 				if (!ntohs(pktInfo->ip->id)) {
// 					//cout<<"IP-id : "<<ntohs(pktInfo_->ip->id)<<endl;
// 					break;
// 				}

				SetResearchInfo(pktInfo);
				isMatched = true;
				break;
// 			case QQ_RECV:
// 			case QQ_V10_RECV:
// 				if (ntohs(pktInfo->ip->id)) {
// 					break;
// 				}
//          
// 				SetResearchInfo(pktInfo);
//                 
// 				isMatched = true;
// 				break;
		}
	}
	
	return isMatched;
}

void QQVersion::Store()
{
	/*write research_host data to shared memory, by zhangzm*/
	struct in_addr addr;
	RESEARCH_HOST_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = objectId_;
	tmp_data.p_data.readed = 0;
	addr.s_addr = clientIp_;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	ParseMac(clientMac_, tmp_data.p_data.clientMac);
	sprintf(tmp_data.p_data.clientPort, "%d", clientPort_);
	addr.s_addr = serverIp_;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", serverPort_);

	tmp_data.p_data.captureTime = timeVal_;
	strncpy(tmp_data.osinfo, objectInfo_.c_str(), 1999);
	tmp_data.p_data.proType = type_;
	tmp_data.p_data.deleted = 0;
	
	msg_queue_send_data(RESEARCH_HOST, (void *)&tmp_data, sizeof(tmp_data));
}

void QQVersion::SetResearchInfo(const PacketInfo *pktInfo)
{
	char strMac[20] = {0};

	readFlag_ = 0;
	type_ = 705;
	char version[100] = {0};
	objectInfo_ = GetVersion(pktInfo, version);
	clientIp_ = pktInfo->srcIpv4;
	serverIp_ = pktInfo->destIpv4;
	clientPort_ = pktInfo->srcPort;
	serverPort_ = pktInfo->destPort;
	timeVal_ = (unsigned int)pktInfo->pkt->ts.tv_sec;
	
	memcpy(clientMac_, pktInfo->srcMac, 6);
	ParseMac(pktInfo->srcMac, strMac);
#ifdef VPDNLZ
	objectId_ = GetObjectId2(clientIp_,pppoe_);
#else
	//objectId_ = GetObjectId(strMac);
	struct in_addr addr;
	addr.s_addr = pktInfo->srcIpv4;
	objectId_ = get_clue_id(strMac, inet_ntoa(addr));
#endif

//	}
}

char* QQVersion::GetVersion(const PacketInfo *pktInfo,char* ver)
{
	qqVersion_ = *reinterpret_cast<const u_short*>(pktInfo->body + 1 + offside_);
	switch (qqVersion_) {
		case QQ_2008TAG:
			ver="QQ2008正式版";
			break;
		case QQ_2010TAG:
			ver="QQ2010正式版";
			break;
		case QQ_2010TAG2:
			ver="QQ2010正式版SP3.1";
			break;
		case QQ_2011TAG:
			ver="QQ2011Beta1";
			break;
		case QQ_2011TAG2:
			ver="QQ2011Beta2";
			break;
		case QQ_2011TAG3:
			ver="QQ2011Beta3";
			break;
		case QQ_2011TAG4:
			ver="QQ2011Beta4";
			break;
		case QQ_2011TAG4_2:
			ver="QQ2011Beta4(安全防护1.2)";
			break;	
		case QQ_2011TAG7:
			ver="QQ2011(安全防护2.0)";
			break;
		case QQ_2011TAG5:
		case QQ_2011TAG6:
		case QQ_2011TAG9:
			ver="QQ2011正式版";
			break;
		case QQ_2011TAG8:
		case QQ_2011TAGA:
			ver="QQ2011(安全防护2.1)";
			break;
		case Q_2011TAG:
		case Q_2011TAG2:
		case Q_2011TAG3:
		case Q_2011TAG4:
			ver="QQ2011正式版(Q+)";
			break;
		case QQ_2011EXP:
			ver="QQ2011实验版";
			break;
		case QQ_2012TAG:
		case QQ_2012TAG3:
		case QQ_2012TAG5:
		case QQ_2012TAG6:
		case QQ_2012TAG8:
		case QQ_2012TAGB:
			ver="QQ2012Beta1";
			break;
		case QQ_2012TAG2:
		case QQ_2012TAG4:
			ver="QQ2011(安全防护2.5)";
			break;
		case QQ_2012TAG7:
			ver="QQ2012Beta1(安全防护2.6)";
			break;
		case QQ_2012TAG9:
			ver="QQ2012Beta1(安全防护2.6.1)";
			break;
		case QQ_2012TAGA:
		case QQ_2012TAGC:
		case QQ_2012TAGE:
			ver="QQ2012Beta2";
			break;
		case QQ_2012TAGD:
			ver="QQ2012Beta2(安全防护2.7)";
			break;
		case QQ_2012TAGF:
			ver="QQ2012Beta3体验版";
			break;
		case QQ_2012TAGG:
		case QQ_2012TAGH:
			ver="QQ2012Beta3";
			break;
		case QQ_2012TAGI:
			ver="QQ2012Beta3(安全防护2.8)";
			break;
		case QQ_2012TAGJ:
		case QQ_2012TAGL:
			ver="QQ2012正式版";
			break;
		case QQ_2012TAGK:
			ver="QQ2012正式版(安全防护3.0)";
			break;
		case QQ_2013TAG:
			ver="QQ2013Beta1";
			break;
		case QQ_2013TAG2:
			ver="QQ2013Beta2";
			break;
		case QQ_2013TAG3:
		case QQ_2013TAG4:
		case QQ_2013TAG5:
			ver="QQ2013新春版(Beta2)";
			break;
		case QQ_2013TAG6:
			ver="QQ2013轻聊版(Beta3)";
			break;
		case QQ_2013TAG7:
			ver="QQ2013轻聊版(Beta4)";
			break;
		case QQ_2013TAG8:
			ver="QQ2013轻聊版(Beta5)";
			break;
		case QQ_2013TAG9:
                        ver="QQ2013轻聊版(Beta6)";
                        break;
                case QQ_2013TAG10:
                        ver="QQ2013正式版";
                        break;
                case QQ_2013TAG11:
                        ver="QQ2013网吧安全版";
                        break;
                case QQ_2013TAG12:
                        ver="QQ2013正式版SP1";
                        break;
                case QQ_2013TAG13:
                        ver="QQ2013正式版SP2";
                        break;
                case QQ_2013TAG14:
                        ver="QQ2013正式版SP3";
                        break;
                case QQ_2013TAG15:
                        ver="QQ2013正式版SP4";
                        break;
                case QQ_2013TAG16:
                        ver="QQ2013正式版SP5";
                        break;
                case QQ_2013TAG17:
                        ver="QQ2013正式版SP6";
                        break;
                case QQ_2014TAG:
                        ver="QQ5.0";
                        break;
                case QQ_2014TAG2:
                        ver="QQ5.1";
                        break;
		case QQ_2014TAG3:
                        ver="QQ5.2";
                        break;
		case QQ_2014TAG4:
                        ver="QQ5.3";
                        break;
		case QQ_2014TAG5:
			ver="QQ5.4";
			break;
		case QQ_2014TAG6:
			ver="QQ5.5";
			break;
		case QQ_2014TAG7:
			ver="QQ6.0";
			break;
		case QQ_2014TAG8:
			ver="QQ6.1";
			break;
		case QQ_2014TAG9:
			ver="QQ6.2";
			break;
// 		default:
// 			ver="其它版本";
// 			break;
	}
	return ver;
}

static char *ParseMac(const u_char *packet, char *mac)
{
	if (packet == 0 || mac == 0)
		return mac;

	sprintf(mac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x", 
		*reinterpret_cast<const u_char *>(packet),
		*reinterpret_cast<const u_char *>(packet + 1),
		*reinterpret_cast<const u_char *>(packet + 2),
		*reinterpret_cast<const u_char *>(packet + 3),
		*reinterpret_cast<const u_char *>(packet + 4),
		*reinterpret_cast<const u_char *>(packet + 5));

	return mac;
}

//end of file
