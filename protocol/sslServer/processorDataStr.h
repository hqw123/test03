#ifndef PROCESSOR_PRI_DATA_H
#define PROCESSOR_PRI_DATA_H

struct ProcessorParaStr{
	void* pub;
	void* pri;
};

typedef struct ProcessorParaStr ProcessorPara;

struct ConnectInfoStr{
	unsigned int ipCli;
	unsigned short portCli;
	unsigned int ipSer;
	unsigned short portSer;
};

typedef struct ConnectInfoStr ConnectInfo;
#endif 
