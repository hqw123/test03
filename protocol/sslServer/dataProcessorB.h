#ifndef HTTPS_DATA_PROCESSOR_H
#define HTTPS_DATA_PROCESSOR_H
#include "serverInfo.h"

#define MAX_HEAD_FUNC	4
int getContentType(void* data,int len,int status);
int getTransferencode(void* data,int len,int status);
int isHeadComplete(void* data,int len,int status);
int getDataType(void* data,int len,int status);

int getContentLen(char* data,int len,int status);
int rhWangyiEncode(void* data,int len);
int rcWangyiLoginUrl(void* data,int len);
int sWangyi(void* data,int len);
struct DataOperation* getWangyiOps();
int rhMsnEncode(void* data,int len);
int rhMsnLocation(void* data,int len);
int rcMsnLogin(void* data,int len);
int sMsn(void* data,int len);
struct DataOperation* getMsnOps();
int rhGugoSecure(void* data,int len);
int rhGugoEncode(void* data,int len);
int rhGugoLocationA(void* data,int len);
int rhGugoLocationB(void* data,int len);
int rhGugoLocationA2(void* data,int len);
int rhGugoUrlA(void* data,int len);
int rhGugoUrlB(void* data,int len);
int rcGugoUrlA(void* data,int len);
int rcGugoUrlB(void* data,int len);
int sGugoA(void* data,int len);
int sGugoB(void* data,int len);
struct DataOperation* getGugoOps();
int rhQqEncode(void* data,int len);
int rcQqUrl(void* data,int len);
int rcQqSsl(void* data,int len);
int sQqA(void* data,int len);
int sQqB(void* data,int len);
struct DataOperation* getQqOps();
int rhSohuEncode(void* data,int len);
int rcSohuUrlA(void* data,int len);
int rcSohuUrlB(void* data,int len);
int sSohuA(void* data,int len);
int sSohuB(void* data,int len);
struct DataOperation* getSohuOps();
int rhYahooEncode(void* data,int len);
int rhYahooSecure(void* data,int len);
int rcYahooUrlA(void* data,int len);
int rcYahooUrlB(void* data,int len);
int sYahooA(void* data,int len);
int sYahooB(void* data,int len);
struct DataOperation* getYahooOps();
int rhHanmailEncode(void* data,int len);
int rhHanmailSecure(void* data,int len);
int rcHanmailUrlA(void* data,int len);
int rcHanmailUrlD(void* data,int len);
int rcHanmailUrlE(void* data,int len);
int sHanmailA(void* data,int len);
int sHanmailD(void* data,int len);
int sHanmailE(void* data,int len);
struct DataOperation* getHanmailOps();

//////////////////////////////
//return value x:
//	if x<0:
//  something error
//	else
// x>>24:replace times
// x>>16&0xff: split
// x&0xfff: split offset
 
 
//163
//replace FUNCTIONS

#endif
