//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     AvResearcher.h
//
//------------------------------------------------------------------------
// Notes:
//		Anti-virus Researcher
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101228 ZhengLin    Initial
//
//------------------------------------------------------------------------

#ifndef AVRESEARCHER_H
#define AVRESEARCHER_H

#include <string>
#include <boost/regex.hpp>
#include "../PacketParser.h"

class AvResearcher
{
public:
	AvResearcher();

	int Match(const boost::regex &, const PacketInfo*, const std::string&);
	void Store();

private:
	void SetResearchInfo(const PacketInfo *, const std::string&);

	unsigned int objectId_;
	int readFlag_;
	int type_;
	unsigned int timeVal_;
	unsigned int clientIp_;
	unsigned int serverIp_;
	unsigned short clientPort_;
	unsigned short serverPort_;
	unsigned char clientMac_[6];
	std::string objectInfo_;
	char pppoe_[60];
};

#endif /* AVRESEARCHER_H */
