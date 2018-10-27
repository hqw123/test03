#ifndef TALKBOX_TEXT_EXTRACTOR
#define TALKBOX_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidTalkboxTextExtractor : public BaseTextExtractor
{
public:
	AndroidTalkboxTextExtractor();
	virtual ~AndroidTalkboxTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};

#endif

