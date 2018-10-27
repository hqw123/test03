#include <fstream>
#include <assert.h>
#include <sys/stat.h> 
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "analyse_domain.h"
#include "clue_c.h"
#include "db_data.h"
#define INDIR_MASK	0xc0


int dn_expand (const u_char *msg, const u_char *eom_orig,
               const u_char *comp_dn, char *exp_dn, int length)
{
    const u_char *cp;
    char *dn, *eom;
    int   c, n, len = -1, checked = 0;
    
    dn  = exp_dn;
    cp  = comp_dn;
    eom = exp_dn + length;
    
    /* Fetch next label in domain name
     */
    while ((n = *cp++) != 0) {
        /* Check for indirection */
        switch (n & INDIR_MASK) {
            case 0:
                if (dn != exp_dn) {
                    if (dn >= eom)
                        return (-1);
                    *dn++ = '.';
                }
                if (dn+n >= eom)
                    return (-1);
                checked += n + 1;
                while (--n >= 0) {
                    int c = *cp++;
                    if ((c == '.') || (c == '\\')) {
                        if (dn + n + 2 >= eom)
                            return (-1);
                        *dn++ = '\\';
                    }
                    *dn++ = c;
                    if (cp >= eom_orig)  /* out of range */
                        return (-1);
                }
                break;
                
            case INDIR_MASK:
                if (len < 0)
                    len = cp - comp_dn + 1;
                cp = msg + (((n & 0x3f) << 8) | (*cp & 0xff));
                if (cp < msg || cp >= eom_orig)  /* out of range */
                    return (-1);
                checked += 2;
                /*
                 * Check for loops in the compressed name;
                 * if we've looked at the whole message,
                 * there must be a loop.
                 */
                if (checked >= eom_orig - msg)
                    return (-1);
                break;
                
            default:
                return (-1);   /* flag error */
        }
    }
    
    *dn = '\0';
    
    for (dn = exp_dn; (c = *dn) != '\0'; dn++)
        if (isascii(c) && isspace(c))
            return (-1);
        
        if (len < 0)
            len = cp - comp_dn;
        return (len);
}

ANALYSEDOMAIN::ANALYSEDOMAIN()
{ 
    sprintf(DIRECTORY,"%s%s",lzDataPath,"/spyData/moduleData/DOMAIN");
    
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    
}

ANALYSEDOMAIN::~ANALYSEDOMAIN()
{
    
}

bool ANALYSEDOMAIN::IsDomain(PacketInfo* pktInfo)
{
    assert(pktInfo != NULL);
    bool isDomain = false;
    pktInfo_ = pktInfo;
    
    
    isDomain = Match();
    
    if (isDomain) {
        pktInfo_ = NULL;
    }
    
    return isDomain;
}

bool ANALYSEDOMAIN::Match()
{
    bool matched = false;
    if (( pktInfo_->bodyLen >0) && !memcmp(pktInfo_->body + 2,  "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",10)&&  !memcmp(pktInfo_->body + pktInfo_->bodyLen -4 ,  "\x00\x01\x00\x01",4))
    {
        dnsHdr=(struct DNShdr *)pktInfo_->body;
        //cout<<"DNS series:"<<ntohs(dnsHdr->id)<<endl;
        unsigned char* data ,*end;
        int name_len;
        char domainName[1024];
        data = (unsigned char *)pktInfo_->body +sizeof(DNShdr);	
        end = (unsigned char *)pktInfo_->body + pktInfo_->bodyLen;
        //extract the name from the packet 
        name_len = dn_expand((unsigned char *)dnsHdr, end, data, domainName, sizeof(domainName)); 
       // cout<<"Requst Domain is : "<<domainName<<endl;
        //store data to DB
        HTTP_T tmp_data;
        memset(&tmp_data, 0, sizeof(tmp_data));
       
        u_long clueId=0;
        char strmac[20] = {0};
         sprintf(strmac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\0", 
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac),
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac + 1),
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac + 2),
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac + 3),
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac + 4),
            *reinterpret_cast<const u_char*>(pktInfo_->srcMac + 5));
         
        struct in_addr addr;
        addr.s_addr = pktInfo_->srcIpv4;
        clueId = get_clue_id(strmac, inet_ntoa(addr));
        char tmp[256];	
        /*
             strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&(ext_url_stream.addr.saddr)));
             strncpy(tmp_data.p_data.clientMac, (char *)ext_url_stream.srcMac, 17);
             sprintf(tmp_data.p_data.clientPort, "%d", ext_url_stream.addr.sport);
             strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&(ext_url_stream.addr.daddr)));
             sprintf(tmp_data.p_data.serverPort, "%d", ext_url_stream.addr.dport);
             tmp_data.p_data.captureTime = ext_url_stream.tv_sec;
        */

        strncpy(tmp_data.p_data.clientMac, strmac, 17);
        strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
        addr.s_addr = pktInfo_->destIpv4;
        strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
        sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
        sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
        tmp_data.p_data.captureTime = pktInfo_->pkt->ts.tv_sec;
        strncpy(tmp_data.url, domainName, 1024);
        tmp_data.p_data.proType = 101;
        tmp_data.p_data.deleted = 0;
        msg_queue_send_data(HTTP, (void *)&tmp_data, sizeof(tmp_data));        
        matched = true;
    }
    return matched;
}



//end of file

