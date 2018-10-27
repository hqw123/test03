
#include <iostream>

#include "analyse_pppoe.h"
#include "clue_c.h"
#include "Analyzer_log.h"
#include "db_data.h"
#include "function_def.h"

using namespace std;

ParsePPPOE::ParsePPPOE()
{
	sum_count = 0;
}

ParsePPPOE::~ParsePPPOE()
{
	map_session_accountInfo.clear();
}

void  ParsePPPOE::analyse_pppoe(PacketInfo* pktInfo)
{
    pppoeHeader = (pppoe_hdr *)pktInfo->body;
    unsigned short int sessionId = ntohs(pppoeHeader->sid);  //session id
    unsigned short int payload = ntohs(pppoeHeader->length); //len
    memcpy(accountInfo_.srcMac, pktInfo->srcMac, 6);//memcpy(g_packetinfo.srcMac,ethHeader->h_source,6);

    unsigned short *ppp;
    char *temp = pktInfo->body;
    temp += (sizeof(struct pppoe_hdr));
    ppp = (unsigned short *)temp;
    if(ntohs(*ppp) == 0xc023) //peer-id and password(pap)
    {
    	//cout<<"pap"<<endl;
    	char *ppppap;
    	ppppap= (char*) (temp +2);
    	char *request;
    	request=(char *) ppppap;
    	if ((int)request[0] == 0x01)
    	{
    		char *data = (char*) (ppppap + 4);
    		payload -= 6;
    		
    		int peeridlen;
    		peeridlen = (int)(*data);
    		
    		char peerid[peeridlen + 1];
    		memset(peerid, 0, peeridlen + 1);
    		memcpy(peerid, (data + 1), peeridlen);
    		
    		char password[payload - peeridlen - 2 + 1];
    		memset(password, 0, payload - peeridlen - 2 + 1);
    		memcpy(password, (data + 1 + peeridlen + 1), (payload - peeridlen - 2));

    		accountInfo_.account = peerid;
    		accountInfo_.pass = password;

#ifdef CONF_PPPOE_NEED_IPADDR
    		Map_session_accountInfo::iterator it = map_session_accountInfo.find(sessionId);
    		if (it == map_session_accountInfo.end())
    		{
    			map_session_accountInfo.insert(pair<uint16_t,pppoe_account_inf>(sessionId, accountInfo_));
    		}
#else
            // not need to get pppoe ip address, insert data to SQL immediately
            StoreData((unsigned int)pktInfo->pkt->ts.tv_sec);
#endif
    		
    	}
    }
    else if(ntohs(*ppp) == 0xc223)//chap
    {
    	char *pppchap;
    	pppchap = (char*) (temp + 2);
    	char *response;
    	response = pppchap;
    	if ((int)response[0] == 0x02)
    	{
    		char *data;
    		data = (char*)(pppchap+4);
    		
    		int valuelen;
    		valuelen = (int)data[0];
    		data = (char*)(data + 1 + valuelen);
    		payload = payload - 7;
    		
    		char username[payload - valuelen + 1];
    		memset(username, 0, payload - valuelen + 1);
    		memcpy(username, data, payload - valuelen);

    		accountInfo_.account = username;
    		accountInfo_.pass = "\0";

#ifdef CONF_PPPOE_NEED_IPADDR
    		Map_session_accountInfo::iterator it = map_session_accountInfo.find(sessionId);
    		if (it == map_session_accountInfo.end())
    		{
    			map_session_accountInfo.insert(pair<uint16_t,pppoe_account_inf>(sessionId, accountInfo_));
    		}
#else
            // not need to get pppoe ip address, insert data to SQL immediately
            StoreData((unsigned int)pktInfo->pkt->ts.tv_sec);
#endif
    	}
            
    }
#ifdef CONF_PPPOE_NEED_IPADDR
    else if (ntohs(*ppp) == 0x8021)
    {
    	struct in_addr * srcIpv4;
    	char *pppIPCP;
    	pppIPCP = (char*)(temp+2);
    	char *ack;
    	ack = pppIPCP;
    	if ((int)ack[0] == 0x02)
    	{
    		char *len;
    		len = (char*)(pppIPCP+3);
    		if (int(*len) == 22)
    		{
    			srcIpv4 = (struct in_addr *)(pppIPCP+6);
    			//cout<<"IP:"<<inet_ntoa(*srcIpv4)<<endl;
    			StoreData(*srcIpv4, sessionId, (unsigned int)pktInfo->pkt->ts.tv_sec);
    		}
     		//add at 2013-08-15
    		//begin
    		else if(int(*len)==10 && (int)ack[1]!=0x01)
    		{
    			srcIpv4=(struct in_addr *)(pppIPCP+6);
    			//cout<<"IP:"<<inet_ntoa(*srcIpv4)<<endl;
    			StoreData(*srcIpv4,sessionId,(unsigned int)pktInfo->pkt->ts.tv_sec);
    		}
       		//end
    	}
    }
#endif
}

void ParsePPPOE::StoreData(unsigned int cap_time)
{
    char strmac[18] = {0};
    strcpy(strmac, ParseMac(accountInfo_.srcMac));
    int clue_id = 0;
    clue_id = get_clue_id(strmac, "0.0.0.0");

    /*write webaccount data to shared memory, by zhangzm*/
    WEBACCOUNT_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));

    tmp_data.p_data.clueid = (unsigned int)clue_id;
    tmp_data.p_data.readed = 0;
    strcpy(tmp_data.p_data.clientIp, "0.0.0.0");
    strncpy(tmp_data.p_data.clientMac, strmac, 17);
    strcpy(tmp_data.p_data.clientPort, "0");
    strcpy(tmp_data.p_data.serverIp, "0.0.0.0");
    strcpy(tmp_data.p_data.serverPort, "0");

    tmp_data.p_data.captureTime = cap_time;
    strcpy(tmp_data.url, "pppoe");
    strncpy(tmp_data.username, accountInfo_.account.c_str(), 64);
    strncpy(tmp_data.password, accountInfo_.pass.c_str(), 64);

    tmp_data.p_data.proType = 204;
    tmp_data.p_data.deleted = 0;
    msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

void ParsePPPOE::StoreData(struct in_addr IP,unsigned short int sID,unsigned int cap_time)
{
    Map_session_accountInfo::iterator it = map_session_accountInfo.find(sID);
    if (it != map_session_accountInfo.end())
    {
        //time_t timeVal;
        //time(&timeVal);

        char strmac[18] = {0};
        strcpy(strmac, ParseMac(it->second.srcMac));
        int clue_id = 0;
        clue_id = get_clue_id(strmac, inet_ntoa(IP));
#if 0
        {
        	//write file
        	FILE *stream_dst;
        	string xmlFile = util_.set_xmlname("pppoe", sID);
        	string file_path = util_.mkdir_for_today("pppoe", xmlFile, "PPPOE");
        	stream_dst = fopen( file_path.c_str(), "rb+" ); // append info to file
        	if (stream_dst == NULL)
        	{
        		LOG_ERROR("The file pppoe*.xml was not opened correctly!\n");
        		return ;
        	}
        	fseek(stream_dst,-9,SEEK_END); // locate to </table>
        	fprintf( stream_dst, "%s\n", "<data>" );
        	fprintf( stream_dst, "%s%d%s\n", "	<dev>", 44, "</dev>");//devicenum
        	fprintf( stream_dst, "%s%d%s\n", "	<clueid>", 0, "</clueid>");
        	fprintf( stream_dst, "%s%d%s\n", "	<sessionid>", 	sID, "</sessionid>");
        	fprintf( stream_dst, "%s%s%s\n", "	<mac>", strmac, "</mac>");
        	fprintf( stream_dst, "%s%s%s\n", "	<userip>", inet_ntoa(IP),  "</userip>");
        	fprintf( stream_dst, "%s%ld%s\n", "	<time>", timeVal, "</time>");
        	fprintf( stream_dst, "%s%s%s\n", "	<user>", it->second.account.c_str(), "</user>");
        	fprintf( stream_dst, "%s%s%s\n", "	<pass>", it->second.pass.c_str(), "</pass>");
        	fprintf( stream_dst, "%s\n", "</data>" );
        	fprintf( stream_dst, "%s", "</table>\n");
        	fclose( stream_dst );
            // map_session_accountInfo.insert(pair<uint16_t,pppoe_account_inf>(sessionId, accountInfo_));

        	//cout<<"pppoe write in :"<<file_path.c_str()<<endl;
        	LOG_INFO("pppoe write in :%s\n",file_path.c_str());
        	++sum_count;
        	if(sum_count%3 == 0)
        	{
        		util_.HashXml("pppoe");
        	}

        }
#endif
        /*write webaccount data to shared memory, by zhangzm*/
        WEBACCOUNT_T tmp_data;
        memset(&tmp_data, 0, sizeof(tmp_data));

        tmp_data.p_data.clueid = (unsigned int)clue_id;
        tmp_data.p_data.readed = 0;
        strcpy(tmp_data.p_data.clientIp, inet_ntoa(IP));
        strncpy(tmp_data.p_data.clientMac, strmac, 17);
        strcpy(tmp_data.p_data.clientPort, "0");
        strcpy(tmp_data.p_data.serverIp, "");
        strcpy(tmp_data.p_data.serverPort, "0");

        tmp_data.p_data.captureTime = cap_time;
        strcpy(tmp_data.url, "pppoe");
        strncpy(tmp_data.username, it->second.account.c_str(), 64);
        strncpy(tmp_data.password, it->second.pass.c_str(), 64);

        tmp_data.p_data.proType = 204;
        tmp_data.p_data.deleted = 0;
        msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));

        map_session_accountInfo.erase(it);
           
    }
}

char *ParsePPPOE::ParseMac(const u_char* packet)
{
    if (packet == NULL)
    	return NULL;

    sprintf(mac_, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\0",
    		*reinterpret_cast<const u_char*>(packet),
    		*reinterpret_cast<const u_char*>(packet + 1),
    		*reinterpret_cast<const u_char*>(packet + 2),
    		*reinterpret_cast<const u_char*>(packet + 3),
    		*reinterpret_cast<const u_char*>(packet + 4),
    		*reinterpret_cast<const u_char*>(packet + 5));

    return mac_;
}


