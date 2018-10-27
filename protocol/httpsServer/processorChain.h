#ifndef DATA_PROCESSOR_CHAIN_H
#define DATA_PROCESSOR_CHAIN_H

#ifndef PROCESS_STOP
#define PROCESS_STOP 0
#endif
#ifndef PROCESS_GO
#define PROCESS_GO	1
#endif


#define CHAIN_MOD_MSK    0xF0000000
#define CHAIN_MOD_HD     0x80000000
#define CHAIN_MOD_CNT    0x40000000
#define CHAIN_MOD_SND    0x20000000
#define PARA_MOD_MSK     0x03000000
#define PARA_MOD_PUB     0x01000000
#define PARA_MOD_PRI     0x02000000
#define PRO_MOD_MSK      0x00F00000
#define PRO_MOD_SND_PAUS 0x00800000
#define PRO_MOD_AP_SET   0x00400000

#ifndef HTTPS_PACK_MOD_TYPE
#define HTTPS_PACK_MOD_TYPE
#define PACK_MOD_MSK         0x000F0000
#define PACK_MOD_GET         0x00010000
#define PACK_MOD_PST         0x00020000
#define PACK_MOD_REP         0x00040000
#define PACK_MOD_SET         0x00080000
#define PACK_TYPE_MSK        0x0C00F000
#define PACK_TYPE_TXT        0x00001000
#define PACK_TYPE_JS         0x00002000
#define PACK_TYPE_STRM       0x00004000
#define PACK_TYPE_SET        0x00008000
#define PACK_TYPE_ATT        0x08000000
#define PACK_TYPE_MUL        0x04000000
#define PACK_CONT_LEN_MSK    0x00000F00
#define PACK_CONT_LEN_SET    0x00000800
#define PACK_CONT_LEN_CHUNK  0x00000100
#define PACK_CONT_LEN_COM    0x00000200
#define PACK_CONT_LEN_UNKNOW 0x00000400

#endif

#ifndef PROCESSOR_STR
#define PROCESSOR_STR

struct ProcessorChainStr{
	int tmode;
	unsigned int sitMsk;
	void* data;
	int len;
	int clen;
	int crlen;
	int rlen;

	int processID;
	int (*processFunc)(int,void*);	
	int mode;
	char* rbuf;
	struct ProcessorChainStr* next;
	struct ProcessorChainStr* buddy;
};

typedef struct ProcessorChainStr ProcessorChain;

#endif

#ifdef __cplusplus
extern "C"{
#endif

ProcessorChain* getProcessorChain(int f,int mod,int (*func)(int,void*));
int process(ProcessorChain* proce,int mode,void* data,int len);
int addProcessor(ProcessorChain* pro,int mod,int (*func)(int,void*),void* dat);
int removeProcessor(ProcessorChain* process,int processid);
int releaseProcessorList(ProcessorChain* chain);
int resetChainHead(ProcessorChain* chain,char* dataaddr,int tmod);
#ifdef __cplusplus
}
#endif

#endif

 
