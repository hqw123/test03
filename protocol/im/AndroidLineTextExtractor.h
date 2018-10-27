#ifndef LINE_TEXT_EXTRACTOR
#define LINE_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidLineTextExtractor:public BaseTextExtractor
{
public:
	AndroidLineTextExtractor();
	virtual ~AndroidLineTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};
#endif

