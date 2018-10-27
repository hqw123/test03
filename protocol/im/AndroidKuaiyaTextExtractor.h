#ifndef KUAIYA_TEXT_EXTRACTOR
#define KUAIYA_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidKuaiyaTextExtractor:public BaseTextExtractor
{
public:
	AndroidKuaiyaTextExtractor();
	virtual ~AndroidKuaiyaTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif

