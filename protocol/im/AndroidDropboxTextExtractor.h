#ifndef DROPBOX_TEXT_EXTRACTOR
#define DROPBOX_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

class AndroidDropboxTextExtractor:public BaseTextExtractor
{
public:
	AndroidDropboxTextExtractor();
	virtual ~AndroidDropboxTextExtractor();
	bool IsImText(PacketInfo* pktInfo);	
	void  Push_Action_Message();
};
#endif
