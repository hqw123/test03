
#ifndef A_SKYPE_TEXT_EXTRACTOR
#define A_SKYPE_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidSkypeTextExtractor : public BaseTextExtractor
{
public:
	AndroidSkypeTextExtractor();
	virtual ~AndroidSkypeTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif

