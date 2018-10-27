#ifndef TELEGRAM_TEXT_EXTRACTOR
#define TELEGRAM_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidTelegramTextExtractor:public BaseTextExtractor
{
public:
	AndroidTelegramTextExtractor();
	virtual ~AndroidTelegramTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif


