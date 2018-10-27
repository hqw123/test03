#ifndef HI_TEXT_EXTRACTOR
#define HI_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidHiTextExtractor:public BaseTextExtractor
{
public:
	AndroidHiTextExtractor();
	virtual ~AndroidHiTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif
