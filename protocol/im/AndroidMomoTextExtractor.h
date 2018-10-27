#ifndef MOMO_TEXT_EXTRACTOR
#define MOMO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidMomoTextExtractor:public BaseTextExtractor
{
public:
	AndroidMomoTextExtractor();
	virtual ~AndroidMomoTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

