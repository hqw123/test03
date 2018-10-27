#ifndef KEECHAT_TEXT_EXTRACTOR
#define KEECHAT_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidKeechatTextExtractor:public BaseTextExtractor
{
public:
	AndroidKeechatTextExtractor();
	virtual ~AndroidKeechatTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};
#endif

