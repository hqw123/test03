
#ifndef WHATSAPP_TEXT_EXTRACTOR
#define WHATSAPP_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidWhatsappTextExtractor:public BaseTextExtractor
{
public:
	AndroidWhatsappTextExtractor();
	virtual ~AndroidWhatsappTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};

#endif



