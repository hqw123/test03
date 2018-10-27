#include "proxyUnit.h"
#include "maskFlags.h"
#include <pthread.h>

#define NR_MAX_PROXYUNIT	0x100

//#define PU_PAUSE_FRAM_FIRST(x) do{x->flags&~FIRST_FRAM_OK;}while(0)
//#define PU_PAUSE_FRAM_SECOND(x) do{x->flags&~SECOND_FRAM_OK;}while(0)

struct ProxyUnitCache{
#ifdef PU_CACHE_LOCK
	pthread_spinlock_t lock;
#endif
	int count;
	struct ProxyUnit* head;	
};

struct ProxyUnitCache puCache;

int initProxyUnitCache(){
	puCache.count=0;
	puCache.head=0;
#ifdef PU_CACHE_LOCK
	pthread_spin_init(&puCache.lock,PTHREAD_PROCESS_PRIVATE);//PTHREAD_PROCESS_PRIVATE
#endif
	return 1;
}

int initProxyUnit(struct ProxyUnit* pu){
	if(!pu)
		return 0;
	pu->fd=0;
	pu->ffd=0;
	pu->tryTimes=0;
	pu->sitMask=0;
	pu->status=0;
	pu->cflags=0;
	pu->flags=0;
	pu->contentLen=0;
	pu->contentSend=0;
	pu->ops=0;
	pu->next=pu->data;
	pu->first=pu->data;
	pu->nextLen=PU_BUF_MAX_LEN;
	return 1;
}

int freeProxyUnit2(struct ProxyUnit* pu){
	if(!pu)
		return 0;
	int i=0;
#ifdef PU_CACHE_LOCK
	i=pthread_spin_lock(&puCache.lock);
#endif
	if(!i){
		if(puCache.count<NR_MAX_PROXYUNIT){
			pu->buddy=puCache.head;
			puCache.head=pu;
			puCache.count++;
			pu=NULL;
		}
#ifdef PU_CACHE_LOCK
		pthread_spin_unlock(&puCache.lock);
#endif
		if(!pu)
			return 0;			
	}
	freeProxyUnit(pu);
		return 0;
}

struct ProxyUnit* mallocProxyUnit2(void* data,int flg){
	int i=0;
	struct ProxyUnit* tmp=NULL;
#ifdef PU_CACHE_LOCK
	i=pthread_spin_lock(&puCache.lock);
#endif
	if(!i){
		if(puCache.count>0){
			tmp=puCache.head;
			puCache.count--;
			puCache.head=tmp->buddy;
		}
#ifdef PU_CACHE_LOCK
		pthread_spin_unlock(&puCache.lock);
#endif	
	}
	if(!tmp)
		tmp=mallocProxyUnit(flg);
	if(tmp)
		initProxyUnit(tmp);
	return tmp;
}




int  resetProxyunitData(struct ProxyUnit* pu,int len,int m){
	
	return 1;
}


int resetProxyunit(struct ProxyUnit* p){

	return 0;
}

int freeProxyUnit(struct ProxyUnit* pu){
	if(!pu)
		return 0;
	if(pu->data)
		free(pu->data);
	free(pu);
	return 0;
}

struct ProxyUnit* mallocProxyUnit(int flg){
	struct ProxyUnit* tmp=(struct ProxyUnit*)malloc(sizeof(struct ProxyUnit));
	if(tmp){
		memset(tmp,0,sizeof(*tmp));
		tmp->data=malloc(PU_BUF_MAX_LEN+8);
		if(tmp->data){
			tmp->next=tmp->data;
			tmp->nextLen=PU_BUF_MAX_LEN;
			return tmp;
		}
		freeProxyUnit(tmp);
	}
	return tmp;	
}
	
	
int recvProxyData(struct ProxyUnit* pu){
	int rlen=0;
	rlen=recvData(pu->ffd,pu->next,pu->nextLen,0,pu->fd);
	if(rlen>0){
		pu->next[rlen]=0;
		pu->first=pu->data;
		pu->firstLen+=rlen;	
		pu->next+=rlen;
		pu->rec++;
	}
	return rlen;
}	
	
int sendProxyData(struct ProxyUnit* pu){
	
	if(!(pu->flags&FLAG_FIRST_FRAM_OK))
		return 0;
	int len=0;
	int rt;
	while(len<pu->firstSend){
		rt=sendData(pu->buddy->ffd,pu->first+len,pu->firstSend-len,0);
		if(rt>0)
			len+=rt;
		if(rt<0){
			LOG_ERROR("SEND FAIL\n");
			return -1;
		}
	}
	pu->first=pu->data;
	pu->firstLen=0;
	if(pu->second){
		memcpy(pu->first,pu->second,pu->secondLen);
		pu->firstLen+=pu->secondLen;
	}
	pu->second=NULL;
	pu->secondLen=0;
	pu->next=pu->first+pu->firstLen;
	pu->nextLen=PU_BUF_MAX_LEN-pu->firstLen;
	return 1;
}


int splitHead(struct ProxyUnit* pu){
	char* splitaddr=strstr(pu->first,"\r\n\r\n");
	if(!splitaddr){
		LOG_WARN("BAD REQUEST OR RESPONSE HEAD\n");
		return -1;
	}
////////////////////////////////////
	pu->headLen=splitaddr-pu->first+4;
	return 1;
////////////////////////////////////
	splitaddr+=4;
	pu->second=splitaddr;
	int tmp=pu->firstLen;
	pu->firstLen=splitaddr-pu->first;
	pu->secondLen=tmp-pu->firstLen;
	if(pu->secondLen==0)
		pu->second=NULL;
	return 1;
}


int processData(struct ProxyUnit* pu){
	pu->flags&=~FLAG_FIRST_FRAM_OK;
	int rt=0;
	if(!(pu->status&DATA_HDR_COMPLET)){
		headFunc headProcess;
		int i=0;
		int status;
		while(i<pu->ops->hnum){
			headProcess=pu->ops->hOps[i];
			status=headProcess(pu->first,pu->firstLen,pu->status);
			pu->status|=status;
			i++;
		}
		if(pu->status&DATA_HDR_COMPLET){
			int clen=getContentLen(pu->first,pu->firstLen,pu->status);
			pu->contentLen=clen;
			pu->contentSend=0;
			pu->status|=CONTENT_LEN_SET;
			splitHead(pu);
		}	
		if(pu->status&DATA_HDR_COMPLET){
			replaceHeadFunc headReplace;
			i=0;
			int rhrt=0;
			while(i<pu->ops->rhnum){
				headReplace=pu->ops->rhOps[i];
				rhrt=headReplace(pu->first,pu->firstLen);
				if(rhrt){
					pu->firstLen-=rhrt;
					pu->next=pu->first+pu->firstLen;
					pu->nextLen=PU_BUF_MAX_LEN-pu->firstLen;			
				} 
				i++;
			}
			PU_HEAD_FRAM_READY(pu);
			SET_CLI_TRANS_FLAG(pu);
			SET_SER_TRANS_FLAG(pu);
#ifdef PROXY_DEBUG
			pu->reqs++;
#endif
			pu->buddy->status=0;	
		}
	}
	if(pu->flags&FLAG_CT_CLI){
		PU_FIRST_FRAM_READY(pu);
		PU_SECOND_FRAM_READY(pu);
		SET_CLI_TRANS_FLAG(pu);
	}
	if(pu->status&DATA_HDR_COMPLET && pu->flags&FLAG_CT_SER){
		if(IS_BYTE_STREAM_FRAM(pu)){
			PU_FIRST_FRAM_READY(pu);
			PU_SECOND_FRAM_READY(pu);
			SET_SER_TRANS_FLAG(pu);
		}
 
		else{
			if(!(IS_FIRST_FRAM_READY(pu))||1){
				replaceContentFunc contReplace;
				int rcrt=0;
				int i=0;
				while(i<pu->ops->rcnum){
					contReplace=pu->ops->rcOps[i];
//////////////////////////////////////////////////
rcrt=contReplace(pu->first+pu->headLen,pu->firstLen-pu->headLen);
///////////////////////////////////////////////////
					//rcrt=contReplace(pu->first,pu->firstLen);
					i++;
				}
				splitFunc needSplit;
				int maxS=0;
				int prt=0;
				i=0;
				while(i<pu->ops->snum){
					needSplit=pu->ops->sOps[i];
///////////////////////////////////////////////////
prt=needSplit(pu->first-pu->headLen,pu->firstLen-pu->headLen);
///////////////////////////////////////////////////
					//prt=needSplit(pu->first,pu->firstLen);
					if(prt>maxS)
						maxS=prt;
					i++;
				}
///////////////////////////////////////////////////////////
pu->headLen=0;
////////////////////////////////////////////////////////////
				if(maxS>0){
					pu->firstLen-=maxS;
					pu->firstSend=pu->firstLen;
					pu->secondLen=maxS;
					pu->second=pu->first+pu->firstLen;
////////////////////////////////////////////////////////
					pu->next=pu->second+pu->secondLen;
////////////////////////////////////////////////////////
				}
				PU_FIRST_FRAM_READY(pu);
				if(pu->flags&FLAG_FIRST_FRAM_OK)
				SET_CLI_TRANS_FLAG(pu);
				SET_SER_TRANS_FLAG(pu);
			}
		}
	}
	return 0;	
}





