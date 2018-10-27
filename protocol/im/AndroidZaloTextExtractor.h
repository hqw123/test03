#ifndef ZALO_TEXT_EXTRACTOR
#define ZALO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidZaloTextExtractor : public BaseTextExtractor
{
public:
	AndroidZaloTextExtractor();
	virtual ~AndroidZaloTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif

