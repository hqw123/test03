#ifndef QQ_TEXT_EXTRACTOR
#define QQ_TEXT_EXTRACTOR
#include "BaseTextExtractor.h"

//using namespace std;

class AndroidQQTextExtractor : public BaseTextExtractor
{
public:
	AndroidQQTextExtractor();
	virtual ~AndroidQQTextExtractor();
	bool IsImText(PacketInfo* pktInfo);
	void  Push_Action_Message();
};
#endif


