#ifndef COCO_TEXT_EXTRACTOR
#define COCO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidCocoTextExtractor:public BaseTextExtractor
{
public:
	AndroidCocoTextExtractor();
	virtual ~AndroidCocoTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif
