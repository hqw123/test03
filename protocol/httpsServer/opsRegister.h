#ifndef HTTPS_OPS_REGISTER_H
#define HTTPS_OPS_REGISTER_H

//ops index
#define OPS_INDEX_WANGYI	1
#define OPS_INDEX_GUGO		3
#define OPS_INDEX_MSN		5
#define OPS_INDEX_YAHOO		7
#define OPS_INDEX_SOHU		9
#define OPS_INDEX_QQ		11
#define OPS_INDEX_HANMAIL	13
#define OPS_INDEX_SINA		15


typedef int (*replaceContentFunc)(void* data,int len);
typedef int (*replaceHeadFunc)(void* data,int len);
typedef int (*headFunc)(void* data, int len,int status);
typedef int (*splitFunc)(void* data,int len);

#define MAX_DATA_OPERATIONS	0x100
struct DataOperation{	
	int hnum;
	headFunc *hOps;
	int rhnum;
	replaceHeadFunc *rhOps;
	int rcnum;
	replaceContentFunc *rcOps;
	int snum;
	splitFunc *sOps;
};

/* global variable*/
extern int pubHeadOpsNum;
extern headFunc* pubHeadOps;
extern struct DataOperation* dataOperations[MAX_DATA_OPERATIONS];
/*****/

int initPublicHeadOps();
int initPublicOps();
int registerOps(int index,struct DataOperation* ops);
struct DataOperation* getRequestOps(int simsk);
struct DataOperation* getResponseOps(int simsk);
struct DataOperation* getPublicHeadOps(int flag);

int initOps();


#endif
 
