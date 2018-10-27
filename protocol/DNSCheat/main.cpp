
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <pthread.h>

#include "PacketParser.h"
#include "Public.h"
#include "DNSSpoof.h"
#include "DNSserver.h"
#include "DNSutil.h"
#include "siteSwitch.h"
//#include "Analyzer_log.h"
//#include "macIpTab.h"

#define LZ_DNS_PORT 53

//DNS
char serverIp[16];
char senddev[DEV_LENTH];
//MacIpPair* array=NULL;

int startTime_;

char path[20];
//for getting the ip of the special domain
struct ServerIP serverIP;
struct DnsPkt  dnsPkt;



pcap_t * pt;

static char errbuf[256];
void sigproc( int sig );
int getlocalip(char ip[16], char* card);
void* writeServerIp(void*);




int main( int argc, char* argv[] )
{

	memset(path,0,20);
	memcpy(path,"a.txt",5);
	//public
	Public * pub = new Public;
	//pub->CreateDir();
	pub->ReadConfig();
	pub->ReadSysConfig();






	cout<<"start ..."<<endl;


	PacketParser pktParser;


	DNSserver* dnsServer=NULL;
	
	if(strcmp("remoteip",SSL_PROXY_MODE)==0)
	{
		int tip=inet_aton(SSL_DOMAIN_NAME, (in_addr *)serverIP.ip);
		//printf(".................severip: %08x\n",serverIP.ip[0]);
	}			
	else if(strcmp("local",SSL_PROXY_MODE)){ 
		//printf("Proxy mode: %s\n",SSL_PROXY_MODE);
		dnsServer = new DNSserver();
		dnsServer->setDomain(SSL_DOMAIN_NAME,0);
		dnsServer->setDev(A_OUT_ETH,1);
		dnsServer->run(0);
	}
	else
	{
		//printf("Proxy mode: %s\n",SSL_PROXY_MODE);
		if(getlocalip(serverIp,(char*)C_PROXY_ETH)!=1)
		{
			LOG_WARN("BAD NEWS : INVALID PROXY NET DEVICE !!!\n");
			if(!strcmp(SSL_RUN,"1"))
			{
				LOG_ERROR("BAD NEWS : SYSTEM WILL EXIT \n");
				exit(-2);
			}
				
		}
	}
	
	pthread_t tidchck;
	int rt2=pthread_create(&tidchck,0,checkSwitch,NULL);
	if(rt2){
		LOG_ERROR("OH,NO GOOD NEWS: SOMETHING WRONG HAPPENDED WHEN \
				CREATE NEW THREAD FOR CHECK STATUS !!!\n");
		return -2;
	}	


	/* write server ip into file dns.ini */
	pthread_t wpid;
	int wps=pthread_create(&wpid,0,writeServerIp,0);
	if(!wps)
		LOG_INFO("OK WRITE SERVERIP THREAD IS RUNNING !!!\n");
	else{
		LOG_ERROR("OH BAD NEWS ,SOMETHING WRONG HAPPEND WHEN CREATE THREAD FOR WRITING SERVERIP INTO DNS.INI !!!\n");
		exit(3);
	}
	/*end write server ip into file dns.ini */
	
	
	
	/* regise signal ctrl+c stop capture */
	signal( SIGINT, sigproc ) ;
	char * capDev;




	//init DNSSpoof

	strcpy(senddev,(char*)B_IN_ETH);	
	//strcpy(senddev,(char*)C_PROXY_ETH);
	memset(serverIp,0,16);
	DNSSpoof dnsSpoof;
	
	
    //init libpcap
	//capDev = (char *)A_OUT_ETH;	//for LZ_B
	capDev = (char *)B_IN_ETH;
	LOG_INFO("capDev is : '%s'  \n", capDev );
	
	
	printf("pcap_open_live ...\n");
	pt = pcap_open_live( capDev, 8000, 1, 500, errbuf );
	if( pt == NULL )
	{
		LOG_ERROR("pcap_open_live:%s \n", errbuf );
		exit(0);
	}

	while(true)
	{
		const u_char * pkt;
		struct pcap_pkthdr_n * hdr;
		pcap_next_ex(pt, &hdr, &pkt);

		pktParser.GetPktInfo((const char *)pkt,hdr);

		if(!strcmp("1",SSL_RUN) && g_packetinfo.pktType==UDP&&g_packetinfo.destPort==LZ_DNS_PORT)
		{//printf("OK COMING INTO DNS ANALYZER\n");	//no clueid
		//printf("FUCK THE DNS STATUS IN MAIN THREAD: %s\n",SSL_RUN);
			dnsSpoof.ParseDNSQueries(&g_packetinfo);
					
		}

	}

	return 0;
}


// single processing function 
void sigproc( int sig )
{
	pcap_close(pt);
	LOG_INFO("DNSCheat is exited!\n");
	exit(0);
}

// get ip by ether-card name
int getlocalip(char ip[16], char* card)
{	
	memset(ip,0,16);
	int sockfd; 
	if (-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0))) 
	{
		perror( "socket" );
		return -1;
	}
  
	struct ifreq req;
	struct sockaddr_in *host;
  
	bzero(&req, sizeof(struct ifreq));
	strcpy(req.ifr_name, card);
	if(ioctl(sockfd, SIOCGIFADDR, &req))
		return -1;
	host = (struct sockaddr_in*)&req.ifr_addr;
	strcpy(ip, inet_ntoa(host->sin_addr));
	close(sockfd);
	serverIP.ip[0]=(unsigned int)host->sin_addr.s_addr;	
	LOG_INFO("PROXY SERVER IP: %d.%d.%d.%d\n",
	       serverIP.ip[0]>>24&0xff,serverIP.ip[0]>>16&0xff,
	       serverIP.ip[0]>>8&0xff,serverIP.ip[0]&0xff);
	return 1;
}


void* writeServerIp(void*){
	int r=1;
	int r2=1;
	while(r){
		r2=1;
		while(r2){
			if(serverIP.ip[0]){
				//write file here
				int fd=open("dns.ini",O_RDWR|O_CREAT|O_TRUNC,S_IRWXU);
				if(fd==-1){
					LOG_ERROR("OH BAD NEWS,CREATE FILE FAIL!!!\n");
					exit(2);
				}
				int ri=write(fd,serverIP.ip,4);
				close(fd);
				if(ri!=4){
					LOG_ERROR("OH BAD NEWS ,WRITE FIAL FAIL !!!\n");
					exit(3);
				}
				LOG_INFO("OK,THE SERVER IP HAS BEEN WRITEN INTO FILE DNS.INI !!!\n");
				r2=0;
				// maybe there is no needing to loop
				r=0;
				continue;
			}
			sleep(30);
		}
		sleep(60*60);
	}
}

//end of file
