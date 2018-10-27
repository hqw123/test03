#ifndef VOXER_TEXT_EXTRACTOR
#define VOXER_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidVoxerTextExtractor: public BaseTextExtractor
{
public:
	AndroidVoxerTextExtractor();
	virtual ~AndroidVoxerTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif
