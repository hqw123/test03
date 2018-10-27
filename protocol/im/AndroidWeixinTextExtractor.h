#ifndef WEIXIN_TEXT_EXTRACTOR
#define WEIXIN_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"
class AndroidWeixinTextExtractor : public BaseTextExtractor
{
public:
	AndroidWeixinTextExtractor();
	virtual ~AndroidWeixinTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();	
};
#endif
