#include "PacketParser.h"
#include "ofo_cope.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************************
*使乱序的包按顺序返回的方法是：
*有一个包来，如果没有对这个tcp跟踪，就创建它的跟踪
*比如依次来到的包是p1,p2,p6,p4,p5,p3
*根据p1,建立它的跟踪，p1算作是正常的包
*p2在p1之后没有乱序，p2算作是正常的包
*p6是乱序，先保存起来，p4,p5也如此,乱序的包按顺序保存p4,p5,p6
*p3到来后，p4,p5,p6一齐返回
*
*创建tcp跟踪时，初始化两个方向上的“下一个渴求”的包的序列号,根据seq和ack_seq
*0方向跟用来创建tcp跟踪的包的方向一致，1方向是相反的方向
*
******************************************/

//存放乱序包的链表
struct ofo_packet_node
{
	char * body;
	int bodyLen;
	unsigned int seq;
	struct ofo_packet_node * next;
};

//存放tcp跟踪的链表
struct ofo_entry_node
{
	unsigned short int srcPort;
	unsigned short int destPort;
	unsigned int srcIpv4;
	unsigned int destIpv4;
	unsigned int flags[2];
	unsigned int nextSeq[2]; // 2个方向的下一个包的序列号
	struct ofo_packet_node * heads[2]; //存放两个方向上的乱序包的链表
	struct ofo_entry_node * next;
};

class OFOCope;

//前面的包到齐后，返回乱序包的结果集
class PacketInfoResultSet 
{
private:
	struct ofo_entry_node * entry;//tcp跟踪条目
	struct ofo_packet_node * head;
	int si; //表示方向
public:
	friend class OFOCope;
	PacketInfoResultSet();
	//从结果集中取出packetInfo，和数据库查询的结果集类似:返回1还有下一个元素,0没有了
	int next(PacketInfo * packetInfo);
	void close(); //关闭结果集:释放乱序包占用的空间
};

class OFOCope // 乱序处理类
{
private:
	struct ofo_entry_node * head;
	int count;

protected:
	void removeEntry(struct ofo_entry_node * entry);
	void removeAllPacket(struct ofo_packet_node * head);
	struct ofo_packet_node * malloc_packet(PacketInfo * packetInfo);
	void travel(struct ofo_entry_node * entry,int si);
	void insertPacket(struct ofo_packet_node ** head,PacketInfo * packetInfo);
	void length();
public:
	OFOCope();
	int registerPacketInfo(PacketInfo * packetInfo,PacketInfoResultSet * resultSet);
	void unregisterPacketInfo(PacketInfo * packetInfo);
	
};

PacketInfoResultSet::PacketInfoResultSet()
{
	entry=NULL;
	head=NULL;
}

//所谓将乱序的包在合适的时候取出，是要去判断下一个渴求的包的序列是否等于乱序表中包的序列
int PacketInfoResultSet::next(PacketInfo * packetInfo)
{
//printf("luan xu da begin --------------\n");
	if(!entry || !entry->heads[si] || entry->nextSeq[si]!=entry->heads[si]->seq) return 0;
//printf("luan xu da end ------------------\n");	
	//get_packet_info(packetInfo,entry->heads[si]->packet,entry->heads[si]->pkthdr);
	packetInfo->body=entry->heads[si]->body;
	packetInfo->bodyLen=entry->heads[si]->bodyLen;
	entry->nextSeq[si]+=packetInfo->bodyLen;
	entry->heads[si]=entry->heads[si]->next;
	return 1;
}
void PacketInfoResultSet::close()
{
	if(!head) return;
	while(head!=entry->heads[si])
	{
		struct ofo_packet_node * tmp=head;
		head=head->next;
		free(tmp->body);
		tmp->body = NULL;
		free(tmp);
		tmp = NULL;
	}
	head=NULL;
	entry=NULL;
}

OFOCope::OFOCope()
{
	head=NULL;
	count=0;
}

void OFOCope::travel(struct ofo_entry_node * entry,int si)
{
	struct ofo_packet_node * tmp= entry->heads[si];
	int i=0;
	while(tmp)
	{
		i++;
		//printf("seq:%u  ",tmp->seq);
		tmp=tmp->next;
	}
	//printf("\nsize : %d\n",i);
}
void OFOCope::length()
{
	struct ofo_entry_node * tmp= head;
	int i=0;
	while(tmp)
	{
		i++;
		tmp=tmp->next;
	}
	//printf("\ncount : %d\n",i);
}

//返回值0xAB, A:1表示要从结果集中去取，0表示不要；B：1表示当前包自己该怎么办就怎么办，0表示当前包丢弃
int OFOCope::registerPacketInfo(PacketInfo * packetInfo,PacketInfoResultSet * resultSet)
{
	if(packetInfo->tcp->syn || (packetInfo->bodyLen==0&&!packetInfo->tcp->fin&&!packetInfo->tcp->rst)) 
		return 0x01;

	struct ofo_entry_node * tmp=head, *tmp2=head;
//length();
	while(tmp)
	{
		int si=-1;
		if(packetInfo->srcPort==tmp->srcPort && packetInfo->destPort==tmp->destPort \
			&&packetInfo->srcIpv4==tmp->srcIpv4 && packetInfo->destIpv4==tmp->destIpv4)
		{
			si=0;
		}
		else if(packetInfo->srcPort==tmp->destPort && packetInfo->destPort==tmp->srcPort \
			&&packetInfo->srcIpv4==tmp->destIpv4 && packetInfo->destIpv4==tmp->srcIpv4)
		{
			si=1;
		}
		if(si!=-1)
		{
			//遇到fin,rst包，把对应的tcp跟踪条目从表中删除
			/*if(packetInfo->tcp->fin||packetInfo->tcp->rst)
			{
				if(tmp==head)
				{
					head=tmp->next;
				}
				else
					tmp2->next=tmp->next;
				removeEntry(tmp);
				return 0x01;
			}*/
			unsigned int seq=ntohl(packetInfo->tcp->seq);
			/*
			在包的长度等于1时的情形比较复杂，因为，1:可能是对方把窗口大小设置为0后，这一方发送的ZeroWindowProbe，这一个字节无效
			2：还可能是正常情况下就本来长度是1。
			*/
			if(seq==tmp->nextSeq[si])
			{
//printf("==\n");
				if(tmp->flags[si])
				{
					if(packetInfo->bodyLen!=1)
					{
						removeAllPacket(tmp->heads[si]);
						tmp->nextSeq[si]+=packetInfo->bodyLen;
						tmp->heads[si]=NULL;
						tmp->flags[si]=0;
						return 0x01;
					}
					return 0;
				}
				if(packetInfo->bodyLen!=1 || tmp->heads[si])
				{
					tmp->nextSeq[si]+=packetInfo->bodyLen;
					resultSet->entry=tmp;
					resultSet->si=si;
					resultSet->head=tmp->heads[si];
					return 0x11;	
				}
				tmp->flags[si]=1;
				insertPacket(&tmp->heads[si],packetInfo);
//printf("srcport:%d,destport:%d,nextseq:%u,seq:%u\n",packetInfo->srcPort,packetInfo->destPort,tmp->nextSeq[si],seq);
//fflush(stdout);
//travel(tmp,si);
	
				return 0;
				
			}
			else if(seq<tmp->nextSeq[si])
			{
//printf("<<\n");
				return 0;
			}
			else
			{
//printf(">>\n");
				insertPacket(&tmp->heads[si],packetInfo);
//printf("srcport:%d,destport:%d,nextseq:%u,seq:%u\n",packetInfo->srcPort,packetInfo->destPort,tmp->nextSeq[si],seq);
//fflush(stdout);
//travel(tmp,si);
				if(tmp->flags[si])
				{
//printf("flags to 00---------------\n");
					tmp->flags[si]=0;
					resultSet->entry=tmp;
					resultSet->si=si;
					resultSet->head=tmp->heads[si];
					return 0x10;
				}
				return 0;
			}
			break;
		}
		tmp2=tmp;
		tmp=tmp->next;
	}
	if(NULL==tmp && !packetInfo->tcp->fin && !packetInfo->tcp->rst)
	{
//printf("add a tcp\n");
//count++;
		struct ofo_entry_node * node = (struct ofo_entry_node *)malloc(sizeof(struct ofo_entry_node));
		if(node==NULL) return 0;
		node->srcPort=packetInfo->srcPort;
		node->destPort=packetInfo->destPort;
		node->srcIpv4=packetInfo->srcIpv4;
		node->destIpv4=packetInfo->destIpv4;
		node->flags[0]=node->flags[1]=0;
		node->nextSeq[0]=ntohl(packetInfo->tcp->seq)+packetInfo->bodyLen;
		node->nextSeq[1]=ntohl(packetInfo->tcp->ack_seq);
		node->heads[0]=node->heads[1]=NULL;
		node->next=head;
		head=node;
	}
	return 0x01;
}

void OFOCope::unregisterPacketInfo(PacketInfo * packetInfo)
{
	struct ofo_entry_node ** tmp=&head;
	while(*tmp)
	{
		int si=-1;
		if(packetInfo->srcPort==(*tmp)->srcPort && packetInfo->destPort==(*tmp)->destPort \
			&&packetInfo->srcIpv4==(*tmp)->srcIpv4 && packetInfo->destIpv4==(*tmp)->destIpv4)
		{
			si=0;
		}
		else if(packetInfo->srcPort==(*tmp)->destPort && packetInfo->destPort==(*tmp)->srcPort \
			&&packetInfo->srcIpv4==(*tmp)->destIpv4 && packetInfo->destIpv4==(*tmp)->srcIpv4)
		{
			si=1;
		}
		if(si!=-1)
		{
			struct ofo_entry_node * tmp2=*tmp;
			*tmp=(*tmp)->next;
			removeEntry(tmp2);
			break;
		}
		tmp=&(*tmp)->next;
		
	}
	
}
void OFOCope::insertPacket(struct ofo_packet_node ** head,PacketInfo * packetInfo)
{
	struct ofo_packet_node ** pp=head;
	unsigned int seq=ntohl(packetInfo->tcp->seq);
	//按顺序存放乱序的包
	while(*pp)
	{
		if(seq < (*pp)->seq)
		{
			struct ofo_packet_node * node = malloc_packet(packetInfo);
			if(!node) return;
			node->next=*pp;
			*pp=node;
			return;
		}
		else if((*pp)->seq==seq) return;
		pp=&(*pp)->next;
	}
	if(*pp==NULL)
	{
		struct ofo_packet_node * node = malloc_packet(packetInfo);
		if(!node) return;
		*pp=node;
	}
}
struct ofo_packet_node * OFOCope::malloc_packet(PacketInfo * packetInfo)
{
	char * body = (char *)malloc(packetInfo->bodyLen+1);
	if(body == NULL)
	{
		printf("malloc error in ofo malloc packet\n");
		return NULL;
	}
	struct ofo_packet_node * node = (struct ofo_packet_node*)malloc(sizeof(struct ofo_packet_node));
	if(node == NULL)
	{
		printf("malloc error in ofo malloc packet\n");
		free(body);
		body = NULL;
		return NULL;
	}
	memcpy(body,packetInfo->body,packetInfo->bodyLen);
	body[packetInfo->bodyLen]=0;
	node->body=body;
	node->bodyLen=packetInfo->bodyLen;
	node->seq=ntohl(packetInfo->tcp->seq);
	node->next=NULL;
	return node;
}

void OFOCope::removeEntry(struct ofo_entry_node  * entry)
{
//printf("del a tcp--\n");
//count--;
	removeAllPacket(entry->heads[0]);
	removeAllPacket(entry->heads[1]);
	free(entry);
	entry = NULL;
}
void OFOCope::removeAllPacket(struct ofo_packet_node * head)
{
	struct ofo_packet_node * node=head;
	struct ofo_packet_node * node2;
	while(node)
	{
		node2=node->next;
		free(node->body);
		node->body = NULL;
		free(node);
		node = NULL;
		node=node2;
	}

}
OFOC_t ofoCreate()
{
	OFOCope * cope = new OFOCope();
	//return (OFOC_t)cope;
	return static_cast<OFOC_t>(reinterpret_cast<long>(cope));  //64bit dev, must be long
}
PIRS_t pirsCreate()
{
	PacketInfoResultSet * rset=new PacketInfoResultSet();
	//return (PIRS_t)rset;
	return static_cast<PIRS_t>(reinterpret_cast<long>(rset));  //64bit dev, must be long
}
int registerPacketInfo(OFOC_t ot,PIRS_t pt,PacketInfo * pi)
{
	OFOCope * cope = (OFOCope*)ot;
	PacketInfoResultSet * rset = (PacketInfoResultSet *)pt;
	return cope->registerPacketInfo(pi,rset);
}
void unregisterPacketInfo(OFOC_t ot,PacketInfo * pi)
{
	OFOCope * cope = (OFOCope*)ot;
	cope->unregisterPacketInfo(pi);
}
int resultSetNext(PIRS_t pt,PacketInfo * pi)
{
	PacketInfoResultSet * rset = (PacketInfoResultSet *)pt;
	return rset->next(pi);
}
void clearResultSet(PIRS_t pt)
{
	PacketInfoResultSet * rset=(PacketInfoResultSet *)pt;
	rset->close();
}
void closeResultSet(PIRS_t pt)
{
	delete (PacketInfoResultSet*)pt;
}
void closeOFO(OFOC_t ofo)
{
	delete (OFOCope*)ofo;
}
