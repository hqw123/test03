#ifndef VIBER_TEXT_EXTRACTOR
#define VIBER_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidViberTextExtractor: public BaseTextExtractor
{
public:
	AndroidViberTextExtractor();
	virtual ~AndroidViberTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif

