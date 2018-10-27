#ifndef BBM_TEXT_EXTRACTOR
#define BBM_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidBBMTextExtractor:public BaseTextExtractor
{
public:
	AndroidBBMTextExtractor();
	virtual ~AndroidBBMTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};
#endif



