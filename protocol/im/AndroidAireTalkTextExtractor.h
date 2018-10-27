#ifndef AIRETALK_TEXT_EXTRACTOR
#define AIRETALK_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidAireTalkTextExtractor:public BaseTextExtractor
{
public:
	AndroidAireTalkTextExtractor();
	virtual ~AndroidAireTalkTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif



