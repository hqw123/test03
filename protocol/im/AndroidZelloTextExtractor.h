#ifndef ZELLO_TEXT_EXTRACTOR
#define ZELLO_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidZelloTextExtractor : public BaseTextExtractor
{
public:
	AndroidZelloTextExtractor();
	virtual ~AndroidZelloTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif

