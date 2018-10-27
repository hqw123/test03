
#include <fstream>
#include <assert.h>
#include <sys/stat.h> 
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "analyse_FTP.h"
#include "clue_c.h"
#include "db_data.h"
//#include "Analyzer_log.h"

#define USER 0x52455355
#define PASS 0x53534150
#define SIZE 0x455a4953
#define RETR 0x52544552     //download
#define MODE 0x20373232     //PASV response
#define STOR 0x524f5453     //upload

FTP::FTP()
{ 
	sprintf(DIRECTORY,"%s%s",lzDataPath,"/spyData/moduleData/FTP");
	sprintf(SUB_DIREC,"%s%s",lzDataPath,"/spyData/moduleData/FTP/File");
	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	sprintf(filePath_, "%s\0", SUB_DIREC);
 	attachSize_ = 100*1024*1024;
}

FTP::~FTP()
{
	
}

bool FTP::IsFTP(PacketInfo* pktInfo)
{
	bool isFTP = false;
	pktInfo_ = pktInfo;
	
    if (!pktInfo_->bodyLen && !pktInfo_->tcp->fin)
        return false;

	isFTP = IsFtpTcp();
	if (isFTP) 
	{
		pktInfo_ = NULL;
	}

	return isFTP;
}

bool FTP::IsFtpTcp()
{
	command = *reinterpret_cast<const u_int*>(pktInfo_->body);
	uint64_t key = this->makeHashkey(pktInfo_, false);//pktInfo_->srcIpv4+pktInfo_->srcPort+pktInfo_->destIpv4+pktInfo_->destPort;
	boost::unordered_map<uint64_t, USERINFO>::iterator it;
	it = UserMap.find(key);
	uint64_t keys = pktInfo_->srcIpv4 << 16 + pktInfo_->srcPort;//pktInfo_->srcIpv4+pktInfo_->srcPort;
	boost::unordered_map<uint64_t, FTPFILE>::iterator ite;
	ite = fileMap.find(keys);
	uint64_t keyd = pktInfo_->destIpv4 << 16 + pktInfo_->destPort;//pktInfo_->destIpv4+pktInfo_->destPort;
	boost::unordered_map<uint64_t, FTPFILE>::iterator iter;
	iter = fileMap.find(keyd);
    uint64_t m_key = 0;

    /*retr send data*/
	if(ite != fileMap.end())
	{
        ite->second.filedata.append(pktInfo_->body, pktInfo_->bodyLen);        
		ite->second.datalen += pktInfo_->bodyLen;
        
		if(ite->second.datalen > attachSize_)
		{
			//LOG_INFO("[FTP]  File over maxSize ,dorped\n");
            if(ite->second.filename)
            {
                delete[] ite->second.filename;
            }

			fileMap.erase(ite->first);
		}
        
		if (pktInfo_->tcp->fin == 1)
		{
			time_t currentTime;
			time(&currentTime);
			char* fileName_ = new char[512];
			sprintf(fileName_, "%s/%lu_%s\0", filePath_, currentTime, ite->second.filename);
    
			std::ofstream* file_= new ofstream(fileName_, ios::ate);
			if (!file_)
			{
				LOG_ERROR("Create file failed!\n");
			}
            else
            {
                file_->write(ite->second.filedata.c_str(), ite->second.datalen);
    			file_->close();
    			//LOG_INFO("[FTP]Write file end!\n");
    			
    			//store data to DB
    			struct in_addr addr;	 
    			char strmac[20] = {0};
    			ParseMac(pktInfo_->destMac, strmac);
    			addr.s_addr = pktInfo_->destIpv4;
    			u_int clueId = 0;
    			clueId = get_clue_id(strmac, inet_ntoa(addr));

    			/*write webaccount data to shared memory, by zhangzm*/
    			FILETRANSLATE_T tmp_data;
    			memset(&tmp_data, 0, sizeof(tmp_data));
    			
    			tmp_data.p_data.clueid = clueId;
    			tmp_data.p_data.readed = 0;
    			strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    			strncpy(tmp_data.p_data.clientMac, strmac, 17);
    			sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->destPort);
    			addr.s_addr = pktInfo_->srcIpv4;
    			strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    			sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->srcPort);
    			tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;

    			strncpy(tmp_data.username, ite->second.user, 49);
    			strncpy(tmp_data.password, ite->second.pass, 49);
    			strncpy(tmp_data.filename, fileName_, 511);
    			tmp_data.optype = 2;
    			tmp_data.filesize = ite->second.datalen;
    			
    			tmp_data.p_data.proType = 802;
    			tmp_data.p_data.deleted = 0;
    			msg_queue_send_data(FILETRANSLATE, (void *)&tmp_data, sizeof(tmp_data));
            }

			delete fileName_;
            if(ite->second.filename)
            {
                delete[] ite->second.filename;
            }
            
			fileMap.erase(ite->first);
		}
        
		return true;
	}

    /*stor send data!!*/
	if(iter != fileMap.end())
	{
        iter->second.filedata.append(pktInfo_->body, pktInfo_->bodyLen);        
		iter->second.datalen += pktInfo_->bodyLen;
        
		if(iter->second.datalen > attachSize_)
		{
			//LOG_WARN("[FTP]  File over maxSize ,dorped\n");
            if(iter->second.filename)
            {
                delete[] iter->second.filename;
            }
            
			fileMap.erase(iter->first);
		}
        
		if(pktInfo_->tcp->fin == 1)
		{
			time_t currentTime;
			time(&currentTime);
			char* fileName_ = new char[512];
			sprintf(fileName_, "%s/%lu_%s\0", filePath_, currentTime, iter->second.filename);
    
			std::ofstream* file_ = new ofstream(fileName_, ios::ate);
			if (!file_)
			{
				LOG_ERROR("Create file failed!\n");
			}
            else
            {
                file_->write(iter->second.filedata.c_str(), iter->second.datalen);
    			file_->close();
    			//LOG_INFO("[FTP]Write file end!\n");
    			
    			//store data to DB
    			struct in_addr addr;
    			char strmac[20] = {0};
    			ParseMac(pktInfo_->srcMac, strmac);
    			addr.s_addr = pktInfo_->srcIpv4;
    			u_int clueId = 0;
    			clueId = get_clue_id(strmac, inet_ntoa(addr));

    			/*write webaccount data to shared memory, by zhangzm*/
    			FILETRANSLATE_T tmp_data;
    			memset(&tmp_data, 0, sizeof(tmp_data));
    			
    			tmp_data.p_data.clueid = clueId;
    			tmp_data.p_data.readed = 0;
    			strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    			strncpy(tmp_data.p_data.clientMac, strmac, 17);
    			sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
    			addr.s_addr = pktInfo_->destIpv4;
    			strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    			sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
    			tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;

    			strncpy(tmp_data.username, iter->second.user, 49);
    			strncpy(tmp_data.password, iter->second.pass, 49);
    			strncpy(tmp_data.filename, fileName_, 511);
    			tmp_data.optype = 1;
    			tmp_data.filesize = iter->second.datalen;
    			
    			tmp_data.p_data.proType = 802;
    			tmp_data.p_data.deleted = 0;
    			msg_queue_send_data(FILETRANSLATE, (void *)&tmp_data, sizeof(tmp_data));
            }

			delete fileName_;
            if(iter->second.filename)
            {
                delete[] iter->second.filename;
            }
            
			fileMap.erase(iter->first);
		}
		return true;
	}
    
	if(it != UserMap.end() && pktInfo_->tcp->fin == 1)
	{
		//LOG_INFO("[FTP]connection break...\n");
    
        if(it->second.user)
        {
            delete[] it->second.user;
        }

        if(it->second.pass)
        {
            delete[] it->second.pass;
        }
            
        UserMap.erase(it->first);
		return true;
	}
    
	switch(command){
		case USER:
			if(pktInfo_->destPort == 21 && pktInfo_->bodyLen > 7)
			{
				//LOG_DEBUG("FTP LOGIN...\n");
				char* usr = new char[pktInfo_->bodyLen - 6];
				memset(usr, 0, pktInfo_->bodyLen - 6);
				memcpy(usr, pktInfo_->body + 5, pktInfo_->bodyLen - 7);
				//LOG_INFO("USER: %s\n", usr);
				USERINFO userinfo;
                memset(&userinfo, 0, sizeof(USERINFO));
				userinfo.user = usr;
             
				UserMap.insert(boost::unordered_map<uint64_t, USERINFO>::value_type(key, userinfo));
			}
			break;
            
		case PASS:
			if(pktInfo_->destPort == 21 && pktInfo_->bodyLen > 7 && it != UserMap.end())
			{
				char* pwd = new char[pktInfo_->bodyLen-6];
				memset(pwd, 0, pktInfo_->bodyLen - 6);
				memcpy(pwd, pktInfo_->body + 5, pktInfo_->bodyLen - 7);
				//LOG_INFO("PASS: %s\n", pwd);
				it->second.pass = pwd;
				
				//store data to DB
				struct in_addr addr;
				char strmac[20] = {0};
				ParseMac(pktInfo_->srcMac, strmac);
				addr.s_addr = pktInfo_->srcIpv4;
				u_int clueId = 0;
				clueId = get_clue_id(strmac, inet_ntoa(addr));

				/*write webaccount data to shared memory, by zhangzm*/
				FILETRANSLATE_T tmp_data;
				memset(&tmp_data, 0, sizeof(tmp_data));
				
				tmp_data.p_data.clueid = clueId;
				tmp_data.p_data.readed = 0;
				strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
				strncpy(tmp_data.p_data.clientMac, strmac, 17);
				sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
				addr.s_addr = pktInfo_->destIpv4;
				strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
				sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
				tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;
				
				strncpy(tmp_data.username, it->second.user, 49);
				strncpy(tmp_data.password, it->second.pass, 49);
				strcpy(tmp_data.filename, "");
				tmp_data.optype = 0;
				tmp_data.filesize = 0;
				
				tmp_data.p_data.proType = 802;
				tmp_data.p_data.deleted = 0;
				msg_queue_send_data(FILETRANSLATE, (void *)&tmp_data, sizeof(tmp_data));
			}
			break;
            
		case SIZE:
			/*if(pktInfo_->destPort==21 && it!=UserMap.end())
			{
				
			}*/
			break;
            
		case RETR:
			if(pktInfo_->destPort == 21 && pktInfo_->bodyLen > 7 && it != UserMap.end())
			{
				char* fname = new char[pktInfo_->bodyLen - 6];
				memset(fname, 0, pktInfo_->bodyLen-6);
				memcpy(fname, pktInfo_->body + 5, pktInfo_->bodyLen - 7);

				//LOG_INFO("RETR FILENAME: %s\n", fname);
				FTPFILE file;
				file.filename = fname;
                file.filedata = "";
				file.datalen = 0;
				file.user = it->second.user;
				file.pass = it->second.pass;
				fileMap.insert(boost::unordered_map<uint64_t, FTPFILE>::value_type(it->second.trans_port, file));
			}
			break;
            
		case STOR:
			if(pktInfo_->destPort == 21 && pktInfo_->bodyLen > 7 && it != UserMap.end())
			{
				char* fname = new char[pktInfo_->bodyLen - 6];
				memset(fname, 0, pktInfo_->bodyLen - 6);
				memcpy(fname, pktInfo_->body + 5, pktInfo_->bodyLen - 7);

				//LOG_INFO("STRO FILENAME: %s\n", fname);
				FTPFILE file;
				file.filename = fname;
                file.filedata = "";
				file.datalen = 0;
				file.user = it->second.user;
				file.pass = it->second.pass;
				fileMap.insert(boost::unordered_map<uint64_t, FTPFILE>::value_type(it->second.trans_port, file));
			}
			break;
            
		case MODE:
            m_key = this->makeHashkey(pktInfo_, true);
            it = UserMap.find(m_key);
            
			if(pktInfo_->srcPort == 21 && it != UserMap.end())
			{
				string packtinfo = (const char*)pktInfo_->body;
				int index1 = packtinfo.find('\r');
				int index2 = packtinfo.rfind(',');	            // the last dot
				int index3 = packtinfo.rfind(',', index2-1);	// dot before the last dot
		
				int port1 = atoi(packtinfo.substr(index3+1, index2-index3+1).c_str());
				int port2 = atoi(packtinfo.substr(index2+1, index1-index2+1).c_str());
				uint16_t port  = port1*256 + port2;
				//cout<<"PORT: "<<port<<endl;
				uint64_t key_s = pktInfo_->srcIpv4 << 16 + port;
				it->second.trans_port = key_s;
			}
			break;
            
		default:
			return false;
	}
    
	return true;
}

char* FTP::ParseMac(const u_char* packet, char* mac)
{
	//assert((packet || mac) != 0);
	if (packet == NULL || mac == NULL)
		return NULL;
	
	sprintf(mac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\0", 
		*reinterpret_cast<const u_char*>(packet),
		*reinterpret_cast<const u_char*>(packet + 1),
		*reinterpret_cast<const u_char*>(packet + 2),
		*reinterpret_cast<const u_char*>(packet + 3),
		*reinterpret_cast<const u_char*>(packet + 4),
		*reinterpret_cast<const u_char*>(packet + 5));

	return mac;
}

//end of file

