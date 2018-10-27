#ifndef OFOCOPE_H
#define OFOCOPE_H
#include "PacketParser.h"

typedef int OFOC_t; // 乱序处理器的句柄
typedef int PIRS_t; // 结果集的句柄

#ifdef __cplusplus
extern "C"{
#endif

	OFOC_t ofoCreate(); //创建句柄
	PIRS_t pirsCreate(); //创建句柄
	int registerPacketInfo(OFOC_t,PIRS_t ,PacketInfo *);//把PacketInfo提交给OFO
	void unregisterPacketInfo(OFOC_t,PacketInfo *);//卸载
	int resultSetNext(PIRS_t,PacketInfo *);//从结果集中取packetInfo
	void clearResultSet(PIRS_t pt);
	void closeResultSet(PIRS_t);//关闭结果集句柄
	void closeOFO(OFOC_t); //关闭乱序句柄
	

#ifdef __cplusplus
}
#endif


#endif
