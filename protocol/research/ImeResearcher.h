//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     ImeResearcher.h
//
//------------------------------------------------------------------------
// Notes:
//		Input Method Researcher
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 110221 ZhengLin    Initial
//
//------------------------------------------------------------------------

#ifndef ImeResearcher_H
#define ImeResearcher_H

#include <string>
#include <boost/regex.hpp>
#include "../PacketParser.h"

class ImeResearcher
{
public:
	ImeResearcher();

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

#endif /* ImeResearcher_H */
