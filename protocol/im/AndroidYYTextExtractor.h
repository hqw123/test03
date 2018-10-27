#ifndef YY_TEXT_EXTRACTOR
#define YY_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidYYTextExtractor : public BaseTextExtractor
{
public:
	AndroidYYTextExtractor();
	virtual ~AndroidYYTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif
