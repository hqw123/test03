#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

#ifndef PROCESS_STOP
#define PROCESS_STOP 0
#endif
#ifndef PROCESS_GO
#define PROCESS_GO	1
#endif

#define DAT_STAT_MSK 0x000000F0
#define DAT_LEN_CHAN 0x00000010
#define DAT_CON_CHAN 0x00000020
#define DAT_CON_VIEW 0x00000040

#ifndef HTTP_PROXY_SEND_MODE
#define HTTP_PROXY_SEND_MODE
#define MODE_RCV 		0x00000001
#define MODE_CON 		0x00000002
#define MODE_URGENT  0x00000004
#endif

#ifdef __cplusplus
extern "C"{
#endif

int dataProcessFuncPubA(int mode,void* data);
int dataProcessFuncPubB(int mode,void* data);
int dataProcessFuncMsnC(int mode,void* data);
int dataProcessFuncMsnD(int mode,void* data);
int dataProcessFunc163E(int mode,void* data);
int dataProcessFuncAccount(int mode,void* data);
int dataProcessFuncGG(int mode,void* data);
int dataProcessFuncGH(int mode,void* data);
int dataProcessFuncGI(int mode,void* data);
int dataProcessFuncGJ(int mode,void* data);
//int dataProcessFuncK(int mode,void* data);
//int dataProcessFuncL(int mode,void* data);
int dataProcessFuncGM(int mode,void* data);
int dataProcessFuncGN(int mode,void* data);
int dataProcessFuncGO(int mode,void* data);
int dataProcessFuncGP(int mode,void* data);
int dataProcessFuncMsnQ(int mode,void* data);
int dataProcessFuncGR(int mode,void* data);
int dataProcessFuncS(int mode,void* data);


int dataProcessFuncYAHOO(int mode,void *data);
int dataProcessFuncYAHOO_B(int mode, void *dat);
int dataProcessFuncYAHOO_C(int mode, void *dat);

int dataProcessFuncSOHU(int mode,void *data);
int dataProcessFuncSOHU_GET_POST(int mode, void *dat);

int dataProcessFuncQQ(int mode,void *data);
int dataProcessFuncQQ_B(int mode, void *dat);



#ifdef __cplusplus
}
#endif


#endif



