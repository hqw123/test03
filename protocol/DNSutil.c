
#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <libxml/parser.h>

#include "DNSutil.h"
#include "Analyzer_log.h"

#define VLAN_MSK 0x0001
#define  PPP_MSK 0x0002
#define   IP_MSK 0x0004

extern struct ServerIP serverIP;
extern struct DnsPkt   dnsPkt;
extern const char* SSL_RUN;

int buildDns(){
	if(strlen(serverIP.domain)<1){
		LOG_ERROR("ERROR: DO NOT SET SERVER DOMAIN\n");
		return -1;
	}
	serverIP.transID==(unsigned short)time((time_t*)NULL);	
	memcpy(&(dnsPkt.dns),&(serverIP.transID),2);
	dnsPkt.dns.data[2]=1;
	dnsPkt.dns.data[3]=0;
	dnsPkt.dns.data[4]=0;
	dnsPkt.dns.data[5]=1;
	memset(dnsPkt.dns.data+6,0,6);
	int domainLen=strlen(serverIP.domain);
	memcpy(dnsPkt.dns.data+13,serverIP.domain,domainLen);
	int i=0;
	int j=12;
	int k=1;
	while(k<=domainLen){
		if(dnsPkt.dns.data[12+k]=='.'){
			dnsPkt.dns.data[j]=i;
			j=12+k;
			i=0;
		}
		else
			i++;
		k++;
	}
	dnsPkt.dns.data[j]=i;
	dnsPkt.dns.len=18+domainLen;
	dnsPkt.dns.data[dnsPkt.dns.len]=0;
	dnsPkt.dns.data[dnsPkt.dns.len-1]=1;
	dnsPkt.dns.data[dnsPkt.dns.len-2]=0;
	dnsPkt.dns.data[dnsPkt.dns.len-3]=1;
	dnsPkt.dns.data[dnsPkt.dns.len-4]=0;
	dnsPkt.dns.data[dnsPkt.dns.len-5]=0;
	return 0;
}

int buildUdp(unsigned int ipsrc,unsigned int ipdst,int index){
	index=index&1;
	unsigned short port=(unsigned short)time((time_t*)NULL);
	serverIP.port=port;
	//port=(unsigned short)(port>>8&0xff|port<<8&0xff00);
	memcpy(dnsPkt.udp.data[index],&port,2);
	dnsPkt.udp.data[index][2]=0;
	dnsPkt.udp.data[index][3]=0x35;
	dnsPkt.udp.len[index]=dnsPkt.dns.len+8;
	dnsPkt.udp.data[index][4]=dnsPkt.udp.len[index]>>8;
	dnsPkt.udp.data[index][5]=dnsPkt.udp.len[index];
	dnsPkt.udp.data[index][6]=0;
	dnsPkt.udp.data[index][7]=0;
	unsigned int sum=dnsPkt.udp.len[index]>>8&0xff|dnsPkt.udp.len[index]<<8&0xff00;
	unsigned short* tmp=(unsigned short*)&ipsrc;
	sum+=*tmp++;
	sum+=*tmp;
	tmp=(unsigned short*)&ipdst;
	sum+=*tmp++;
	sum+=*tmp;
	sum+=0x1100;
	
	tmp=(unsigned short*)dnsPkt.dns.data;
	while((char*)tmp<dnsPkt.dns.data+dnsPkt.dns.len)
		sum+=*tmp++;
	sum=(sum&0xffff)+(sum>>16);
	sum=~sum;
	dnsPkt.udp.data[index][6]=sum&0xff;
	dnsPkt.udp.data[index][7]=sum>>8&0xff;
	memcpy(dnsPkt.udp.data[index]+8,dnsPkt.dns.data,dnsPkt.dns.len);
	dnsPkt.udp.effective++;
	return 0;
}


int buildIp(unsigned int ipsrc,unsigned int ipdst,int index){
	
	index=index&1;
	serverIP.dnsIP=ipdst;
	dnsPkt.ip.len[index]=20+dnsPkt.udp.len[index];
	dnsPkt.ip.data[index][0]=0x45;
	dnsPkt.ip.data[index][1]=0;
	dnsPkt.ip.data[index][2]=dnsPkt.ip.len[index]>>8;
	dnsPkt.ip.data[index][3]=dnsPkt.ip.len[index];
	dnsPkt.ip.data[index][6]=0;
	dnsPkt.ip.data[index][7]=0;
	dnsPkt.ip.data[index][8]=0x80;
	dnsPkt.ip.data[index][9]=0x11;
	dnsPkt.ip.data[index][10]=0;
	dnsPkt.ip.data[index][11]=0;
	unsigned int* tmp=(unsigned int*)(dnsPkt.ip.data[index]+12);
	*tmp=ipsrc;
	tmp++;	
	*tmp=ipdst;
	unsigned int sum=0;
	unsigned short* tmps=(unsigned short*)dnsPkt.ip.data[index];
	while((char*)tmps<(char*)dnsPkt.ip.data[index]+20)
		sum+=*tmps++;
	sum=(sum&0xffff)+(sum>>16);
	sum=~sum;
	dnsPkt.ip.data[index][10]=sum;
	dnsPkt.ip.data[index][11]=sum>>8;
	memcpy(dnsPkt.ip.data[index]+20,dnsPkt.udp.data[index],dnsPkt.udp.len[index]);
	dnsPkt.ip.effective++;
	return 0;
}


int buildLink(const struct Address* address,char* src,char* dst,int index){
	index&=1;
	if(!address)
		return -1;
	memcpy(dnsPkt.link.data[index],address->data,address->len);
	memcpy(dnsPkt.link.data[index],dst,6);
	memcpy(dnsPkt.link.data[index]+6,src,6);
	memcpy(dnsPkt.link.data[index]+address->len,dnsPkt.ip.data[index],dnsPkt.ip.len[index]);
	if(address->offset){
		unsigned short len=dnsPkt.ip.len[index]+2;
		char* tmp=dnsPkt.link.data[index]+address->offset;
		*tmp=len>>8;
		tmp++;
		*tmp=len;
	}
	dnsPkt.link.len[index]=address->len+dnsPkt.ip.len[index];	
	return 0;
}


void* runA(void* dat){
	char errbuf[256];
	char errbufB[256];
	pcap_t* cap=pcap_open_live(serverIP.devOUT,1518,1,1,errbuf);
	libnet_t* snd=libnet_init(LIBNET_LINK,serverIP.devOUT,errbufB);
	if(!cap){
		LOG_ERROR("PCAP_OPEN_LIVE: FAIL !!!\n");
		return (void*)-1;
	}
	if(!snd){
		LOG_ERROR("LIBNET_INIT : FAIL !!!\n");
		return (void*)-1;
	}
	struct pcap_pkthdr_n* caphdr;
	char* capdata;
	struct Address address;
	int rt;
	int frt;
	int run=1;
	int haveSent=0;
	while(run){
		rt=pcap_next_ex(cap,&caphdr,(const u_char**)&capdata);
		if(rt==1 && !haveSent){		
			frt=fillAddress(capdata,caphdr->caplen,&address);
			if(frt&IP_MSK){
				buildDns();
				buildUdp(address.ipSrc,serverIP.dnsIP,0);
				buildUdp(address.ipDst,serverIP.dnsIP,1);
				buildIp(address.ipSrc,serverIP.dnsIP,0);
				buildIp(address.ipDst,serverIP.dnsIP,1);
				buildLink(&address,address.macSrc,address.macDst,0);
				buildLink(&address,address.macDst,address.macSrc,1);
				printf("SEND DNS REQUEST !!!\n");
				libnet_write_link(snd,dnsPkt.link.data[0],dnsPkt.link.len[0]);
				libnet_write_link(snd,dnsPkt.link.data[1],dnsPkt.link.len[1]);
				libnet_write_link(snd,dnsPkt.link.data[0],dnsPkt.link.len[0]);
				libnet_write_link(snd,dnsPkt.link.data[1],dnsPkt.link.len[1]);
				libnet_write_link(snd,dnsPkt.link.data[0],dnsPkt.link.len[0]);
				libnet_write_link(snd,dnsPkt.link.data[1],dnsPkt.link.len[1]);
				haveSent=1;
			}
		}
		if(rt==1 && haveSent){
			int rt=fillServerIP(capdata,caphdr->caplen);
			if(rt==3){
				sleep(3000);
				haveSent=0;
			}
		
		}	
	}

}

int fillAddress(char* dat,int len,struct Address* adr){
	if(!dat || len<35)
		return 0;
	memset(adr,0,sizeof(struct Address));
	int rt=0;
	char* point=dat;
	memcpy(adr->macDst,point,6);
	point+=6;
	memcpy(adr->macSrc,point,6);
	point+=6;
	unsigned short* type;
	while(!(rt&IP_MSK)){
		type=(unsigned short*)point;
		switch(*type){
			case 0x0081 :{
				rt|=VLAN_MSK;
				point+=4;
				break;
			}
			case 0x6488 :{
				rt|=PPP_MSK;
				point+=8;
				adr->offset=point-dat-2;
				break;		 
			}
			case 0x2100 :
			case 0x0008 :{
					rt|=IP_MSK;
					point+=2;
					adr->len=point-dat;
					memcpy(adr->data,dat,adr->len);
					adr->ipSrc=*(unsigned int*)(point+12);
					adr->ipDst=*(unsigned int*)(point+16);
					LOG_INFO("IP ADDR: %d.%d.%d.%d  %d.%d.%d.%d\n",
						   adr->ipSrc&0xff,adr->ipSrc>>8&0xff,adr->ipSrc>>16&0xff,adr->ipSrc>>24&0xff,
						   adr->ipDst&0xff,adr->ipDst>>8&0xff,adr->ipDst>>16&0xff,adr->ipDst>>24&0xff);
					break;	
			}
			default:     {
				//printf("SOMETHING IS WRONG : !!!\nTYPE:%04x\n",*type);
					return 0;	 
			}	 
		}	
	}
	return rt;	
}

int fillServerIP(char* data,int len){
	if(!data || len<35)
		return 0;
	char* point=data+12;
	unsigned short* type;
	while(point < data+len){
		type=(unsigned short*)point;
		switch(*type){
			case 0x0081 :{
				point+=4;
				break;
			}
			case 0x6488 :{
				point+=8;
				break;		 
			}
			case 0x2100 :
			case 0x0008 :{
					point+=2;
					//printf("find the ip\n");
					if(serverIP.dnsIP==*(unsigned int*)(point+12) && *(point+9)==0x11){
						//printf("find the dns ip\n");
						point+=20;
						if(*(unsigned short*)point !=0x3500 || *(unsigned short*)(point+2) !=serverIP.port)
							return 0;
						//printf("find the dns port\n");
						point+=8;
						if(*(unsigned short*)point !=serverIP.transID){
							LOG_WARN("TRANSID IS NOT THE ONE\n");
							return 0;
						}
						//printf("find the dns dns response\n");
						if(*(unsigned short*)(point+2)!=0x8081){
							LOG_WARN("DNS RESPONSE : FAIL :%04x\n",*(unsigned short*)(point+2));
							return 1;
						}
						point+=12;
						while(*point)
							point++;
						point+=5;
						point+=2;
						unsigned short* dnsT;
						unsigned short* tmpl;
						//printf("begin analyze the ip \n");
						while(point<data+len){
							dnsT=(unsigned short*)point;
							switch(*dnsT){
								case 0x0500:{
										point+=8;
										tmpl=(unsigned short*)point;
										point+=*tmpl>>8&0xff | *tmpl<<8&0xff00;
										point+=2;
										break;
									}
								case 0x0100:{
										point+=10;
										serverIP.effective=1;
										serverIP.ip[0]=*(unsigned int*)point;
										LOG_INFO("SERVER IP: %08x\n",serverIP.ip[0]);
										return 3;
									}	
								default:return 2;
							}
						
						}
							
					
					}
					return 0;	
				}
			default:     {
					//printf("SOMETHING IS WRONG : !!!\nTYPE:%04x\n",*type);
					return 0;	 
				}	 
		
		}
	
	
	}

}



int getSSLstatus(){
	int rt=0;
	const char* configfile = "/spy/config/sslConfig.xml";
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	char* SSL_RUN="0";
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if(!doc){
		LOG_ERROR("READ CONFIGURE FILE FAIL\n");
		return rt;
	}
	curNode = xmlDocGetRootElement(doc);
	if(!curNode){
		LOG_ERROR("EMPTY CONFIGURE FILE\n");
		xmlFreeDoc(doc);
		return rt;
	}
	if(xmlStrcmp(curNode->name, BAD_CAST "DeviceInfo")){
		LOG_ERROR("BAD ROOT ELEMENT\n");
		xmlFreeDoc(doc);
		return rt;
	}
	xmlChar* xsslRun=NULL;
	itemNode = curNode->xmlChildrenNode;
	while(itemNode){
		if(itemNode->type != XML_ELEMENT_NODE){
			itemNode = itemNode->next;
			continue;
		}
		if(!xmlStrcmp (itemNode->name, BAD_CAST "sslRunning")){
			xsslRun = xmlNodeGetContent(itemNode);
			SSL_RUN=(char *)xsslRun;
		} 
		itemNode = itemNode->next;
	}
	if(!strcmp(SSL_RUN,"1"))
		rt=1;
	xmlFree(xsslRun);	
	xmlFreeDoc(doc);
	return rt;
}


void* runB(void* dat){
	int run=1;
	int sslRun=0;
	while(run){
		sslRun=getSSLstatus();
		if(sslRun)
			SSL_RUN="1";
		else
			SSL_RUN="0";
		LOG_INFO("FUCK THE DNS STATUS IN THREAD RUNB: %s\n",SSL_RUN);
		sleep(300);
	} 
	
}





