#ifndef NUMBUZZ_TEXT_EXTRACTOR
#define NUMBUZZ_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidNimbuzzTextExtractor:public BaseTextExtractor
{
public:
	AndroidNimbuzzTextExtractor();
	virtual ~AndroidNimbuzzTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

