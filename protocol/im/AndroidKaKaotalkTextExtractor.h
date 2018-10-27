#ifndef KAKAOTALK_TEXT_EXTRACTOR
#define KAKAOTALK_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidKaKaotalkTextExtractor:public BaseTextExtractor
{
public:
	AndroidKaKaotalkTextExtractor();
	virtual ~AndroidKaKaotalkTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

