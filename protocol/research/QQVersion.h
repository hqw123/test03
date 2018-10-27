#ifndef QQVERSION_H
#define QQVERSION_H

#include <string>
//#include <boost/regex.hpp>
#include "../PacketParser.h"

class QQVersion
{
	public:
		QQVersion();
		bool Match(const PacketInfo*);
		void Store();

	private:
		void SetResearchInfo(const PacketInfo *);
		char* GetVersion(const PacketInfo *,char* ver);

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
		u_char qqCommand_;
		u_short qqVersion_;
		u_short offside_;
		char pppoe_[60];
};

#endif /* QQVERSION_H */
