#ifndef OOVOO_TEXT_EXTRACTOR
#define OOVOO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidOovooTextExtractor:public BaseTextExtractor
{
public:
	AndroidOovooTextExtractor();
	virtual ~AndroidOovooTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

