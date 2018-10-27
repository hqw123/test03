#ifndef TANGO_TEXT_EXTRACTOR
#define TANGO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidTangoTextExtractor:public BaseTextExtractor
{
public:
	AndroidTangoTextExtractor();
	virtual ~AndroidTangoTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

