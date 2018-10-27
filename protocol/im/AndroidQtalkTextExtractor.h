
#ifndef QTALK_TEXT_EXTRACTOR
#define QTALK_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidQtalkTextExtractor : public BaseTextExtractor
{
public:
	AndroidQtalkTextExtractor();
	virtual ~AndroidQtalkTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif

