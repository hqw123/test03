
#include <fstream>
#include <sstream>
#include <netinet/in.h>		// For ntohl().
#include <sys/stat.h>		// For mkdir().
#include <arpa/inet.h>
#include <zlib.h>

#include "QQFileExtractor.h"
#include "clue_c.h"
#include "db_data.h"

using namespace std;

#define PORT_BITS          16

QQFileExtractor::QQFileExtractor()
{
	sprintf(DIRECTORY, "%s%s", LzDataPath, "/spyData/moduleData/QQ");
	sprintf(SUB_DIREC, "%s%s", LzDataPath, "/spyData/moduleData/QQ/File");
	isRunning_ = true;
	isDeepParsing_ = false;
	attachSize_ = 100 * 1024 * 1024;
	miniSize_ = 0;

	mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	sprintf(filePath_, "%s\0", SUB_DIREC);
}

QQFileExtractor::~QQFileExtractor()
{

}

bool QQFileExtractor::IsFile(PacketInfo * pktInfo)
{
	//assert(pktInfo != NULL);
	bool isQQFile = false;
	pktInfo_ = pktInfo;
	if (pktInfo_->pktType == UDP)
	{

		isQQFile = IsImFileUdp();
	}
	else
	{
		isQQFile = false;
	}
	if (isQQFile)
	{
		pktInfo_ = NULL;
	}

	return isQQFile;
}

#define BEGIN              0x522b
#define TRANS              0x632d
#define END                0x562b
#define GZIP               0x01

#define VER_09_TAG         0x05	//maybe at *(pktInfo_->body+31)
#define TRANS_HLEN         18
#define ADD_LEN            31

bool QQFileExtractor::IsImFileUdp()
{
	bool isQQFileUdp = false;
	if (pktInfo_->bodyLen <= TRANS_HLEN)
	{
		return false;
	}
    
	if (*pktInfo_->body == VER_09_TAG)
	{
		// cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ File Data!!!"<<endl;  
		isQQFileUdp = IsQQ09UdpFile();

	}
	else if (pktInfo_->bodyLen > TRANS_HLEN + ADD_LEN && *(pktInfo_->body + ADD_LEN) == VER_09_TAG)
	{
		pktInfo_->body += ADD_LEN;
		pktInfo_->bodyLen -= ADD_LEN + 1;
		//cout<< __FILE__ << ":" << __FUNCTION__ << ": " <<"QQ File Data!!!"<<endl;  
		isQQFileUdp = IsQQ09UdpFile();
	}

	return isQQFileUdp;
}

#define V09_FNAME_POS      23
#define V09_TRANS_SEQ_POS  10
#define V09_TRANS_HLEN     18

#define V09_END_SEQ_POS    14
#define V09_END_HLEN       18

bool QQFileExtractor::IsQQ09UdpFile()
{

	command = *reinterpret_cast < const u_short *>(pktInfo_->body + 4);

	uint64_t key = pktInfo_->srcIpv4 + pktInfo_->srcPort + pktInfo_->destIpv4 + pktInfo_->destPort;
	map < uint64_t, Files >::iterator it;
	it = my_map.find(key);
	u_int fileNum = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 6));
	u_int clueId = 0;
	switch (command)
	{
	case BEGIN:
		{

			char strmac[20] = {0};
			ParseMac(pktInfo_->srcMac, strmac);
			char strmac2[20] = {0};
			ParseMac(pktInfo_->destMac, strmac2);
#ifdef VPDNLZ
			char pppoe[60];
			clueId = GetObjectId2(pktInfo_->srcIpv4, pppoe);
#else
			//clueId = GetObjectId(strmac);
			struct in_addr addr;
			addr.s_addr = pktInfo_->srcIpv4;
			clueId = get_clue_id(strmac, inet_ntoa(addr));
#endif
			//cout << "(send)ObjectId: " << clueId << endl;
			if (!clueId)
			{
#ifdef VPDNLZ
				clueId = GetObjectId2(pktInfo_->destIpv4, pppoe);
#else
				//clueId = GetObjectId(strmac2);
				addr.s_addr = pktInfo_->destIpv4;
				clueId = get_clue_id(strmac2, inet_ntoa(addr));
#endif
				//cout << "(recv)ObjectId: " << clueId << endl;
				//if (!clueId)
				//{
				//	break;
				//}
			}
			//u_int fileNum = ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 6));
			u_int fileSize = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 11));

			if (fileSize < miniSize_ || fileSize > attachSize_)
			{
				break;
			}
			u_int pktSum = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 15));


			const u_short *ucs2 = reinterpret_cast < const u_short * >(pktInfo_->body + 23);
			char *fileName =::UCS2ToUTF8(ucs2);
			//cout << "FileNum: " << fileNum << "  FileSize: " << fileSize << "  PktSum: " << pktSum << "  fileName: " << fileName << endl;
			char c = '.';
			char *i = strrchr(fileName, c);

			if ((i == ".doc") || (i == ".xls") || (i == ".ppt") || (i == ".docx") || (i == ".xlsx"))
			{
				break;
			}
			else
			{

				if (it != my_map.end())
				{
					break;
				}
				else
				{
					Files file;
					file.filename = fileName;
					file.filesize = fileSize;
					my_map.insert(map < uint64_t, Files >::value_type(key, file));
					//numMap.insert(map<u_int,string>::value_type(fileNum,"file"));
				}
			}





		}
		break;
	case TRANS:
		{


			//u_int fileNum = ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 6));


			u_int pktNum = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 10));

			u_int bodyLen_ = pktInfo_->bodyLen - 18;
			//cout<<"FileNum: "<< fileNum<<"  PktNum: "<< pktNum<<"  bodyLen_: "<< bodyLen_ <<endl;




			if (it != my_map.end())
			{
				map < u_int, QQFile >::iterator ite;
				ite = fileMap.find(pktNum);
				if (ite != fileMap.end())
				{
					break;
				}
				char *bod = new char[bodyLen_ + 1];
				memcpy(bod, pktInfo_->body + 18, bodyLen_);
				if (*(pktInfo_->body + 17) == GZIP)
				{
					int result;
					char *dest = NULL;
					result = Decomp_gzip(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_1(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_2(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_3(bod, bodyLen_ - 2, &dest);
					if (result == 0)
					{
						LOG_INFO("decomp_zip return!\n");
						free(bod);
						bod = dest;
						string p = dest;
						bodyLen_ = p.size();
						dest = NULL;
					}
				}

				QQFile qqfile;
				qqfile.fileNum = fileNum;
				qqfile.fileData = bod;
				qqfile.fileDataLen = bodyLen_;
				//cout<<"FileNum: "<< fileNum<<"  PktNum: "<< pktNum<<"  bodyLen_: "<< bodyLen_ <<endl;
				fileMap.insert(map < u_int, QQFile >::value_type(pktNum, qqfile));
			}
		}
		break;
	case END:
		{

			//u_int fileNum = ntohl(*reinterpret_cast<const u_int*>(pktInfo_->body + 6));


			u_int pktNum = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 14));


			u_int bodyLen_ = ntohl(*reinterpret_cast < const u_int * >(pktInfo_->body + 10));
			//cout<<"FileNum: "<< fileNum<<"  PktNum: "<< pktNum<<"  bodyLen_: "<< bodyLen_ <<endl;


			/*map<uint64_t,Files>::iterator it;
			   char* fname;
			   u_int fsize;
			   for(it=my_map.begin();it!=my_map.end();it++)
			   {
			   fname=it->second.filename;
			   fsize=it->second.filesize;
			   }
			   map<uint64_t,Files>::iterator ite;
			   ite = my_map.find(key);
			   if(ite != my_map.end()) */
			if (it != my_map.end())
			{
				map < u_int, QQFile >::iterator ite;
				ite = fileMap.find(pktNum);
				if (ite != fileMap.end())
				{
					break;
				}

				char *fname;
				u_int fsize;
				fname = it->second.filename;
				fsize = it->second.filesize;

				char strmac[20] = {0};
				ParseMac(pktInfo_->srcMac, strmac);
				char strmac2[20] = {0};
				ParseMac(pktInfo_->destMac, strmac2);

				//clueId = GetObjectId(strmac);
				struct in_addr addr;
				addr.s_addr = pktInfo_->srcIpv4;
				clueId = get_clue_id(strmac, inet_ntoa(addr));
				
				u_int type = 0;
				if (!clueId)
				{
					addr.s_addr = pktInfo_->destIpv4;
					clueId = get_clue_id(strmac2, inet_ntoa(addr));
					type = 2;
					//cout<<"recv file..."<<endl;
				}
				else
				{
					type = 1;
					//cout<<"send file..."<<endl;
				}
				
				char *bod = new char[bodyLen_ + 1];
				memset(bod, 0, bodyLen_);
                int cp_len = (bodyLen_ > (pktInfo_->bodyLen-18))?(pktInfo_->bodyLen-18):bodyLen_;
				memcpy(bod, pktInfo_->body + 18, cp_len);
				if (*(pktInfo_->body + 17) == GZIP)
				{
					int result;
					char *dest = NULL;
					result = Decomp_gzip(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_1(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_2(bod, bodyLen_ - 2, &dest);
					if (result == -1)
						result = Decomp_gzip_3(bod, bodyLen_ - 2, &dest);
					if (result == 0)
					{
						LOG_INFO("decomp_zip return!\n");
						free(bod);
						bod = dest;
						string p = dest;
						bodyLen_ = p.size();
						dest = NULL;
					}
				}
				QQFile qqfile;
				qqfile.fileNum = fileNum;
				qqfile.fileData = bod;
				qqfile.fileDataLen = bodyLen_;
				//cout<<"FileNum: "<< fileNum<<"  PktNum: "<< pktNum<<"  bodyLen_: "<< bodyLen_ <<endl;
				fileMap.insert(map < u_int, QQFile >::value_type(pktNum, qqfile));
				CreatFile(fname);
				
				//cout << "Create file end,then begin write file..." << endl;
				LOG_INFO("Create file end,then begin write file...\n");
				map < u_int, QQFile >::iterator iter;
				for (iter = fileMap.begin(); iter != fileMap.end(); iter++)
				{
					//cout<<iter->first<<endl;
					StoreToFile(iter->second.fileData, iter->second.fileDataLen);
					delete iter->second.fileData;
					fileMap.erase(iter->first);
				}
				CloseFile();
				
				/*write webaccount data to shared memory, by zhangzm*/
				FILETRANSLATE_T tmp_data;
				memset(&tmp_data, 0, sizeof(tmp_data));
				
				tmp_data.p_data.clueid = clueId;
				tmp_data.p_data.readed = 0;
				addr.s_addr = pktInfo_->srcIpv4;
				strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
				if (type == 2)
				{
					ParseMac(pktInfo_->destMac, tmp_data.p_data.clientMac);
				}
				else
				{
					ParseMac(pktInfo_->srcMac, tmp_data.p_data.clientMac);
				}
				
				sprintf(tmp_data.p_data.clientPort, "%d", pktInfo_->srcPort);
				addr.s_addr = pktInfo_->destIpv4;
				strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
				sprintf(tmp_data.p_data.serverPort, "%d", pktInfo_->destPort);
				tmp_data.p_data.captureTime = (unsigned int)pktInfo_->pkt->ts.tv_sec;
				
				strcpy(tmp_data.username, "");
				strcpy(tmp_data.password, "");
				strncpy(tmp_data.filename, fileName_, 511);
				tmp_data.optype = type;
				tmp_data.filesize = fsize;
				
				tmp_data.p_data.proType = 801;
				tmp_data.p_data.deleted = 0;
				msg_queue_send_data(FILETRANSLATE, (void *)&tmp_data, sizeof(tmp_data));

				delete fileName_;
				my_map.erase(key);
			}
		}
		break;
	default:
		return false;
	}
	return true;
}

bool QQFileExtractor::CreatFile(char *fileName)
{
	time_t currentTime;
	time(&currentTime);
	fileName_ = new char[512];
	sprintf(fileName_, "%s/%lu_%s\0", filePath_, currentTime, fileName);

	file_ = new ofstream(fileName_, ios::ate);
	if (!file_)
	{
		cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file failed!" << endl;
		return false;
	}

	return true;
}
void QQFileExtractor::StoreToFile(char *body, u_int bodyLen)
{

	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Write file..." <<endl;
	file_->write(body, bodyLen);


}

void QQFileExtractor::CloseFile()
{
	file_->close();
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Write file end!" <<endl;
	//cout << "[QQ]Write file end!" << endl;
	LOG_INFO("[QQ]Write file end!\n");

}

void QQFileExtractor::StoreMsg2DB(MsgNode * msgNode)
{

}

int QQFileExtractor::Decomp_gzip(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip ...\n");
	int res;
	char tmp[201];
	int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Bytef *) src;
	d_stream.avail_in = len;

	do
	{
		d_stream.next_out = (Bytef *) tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK)
		{
			LOG_WARN("Decomp_gzip(): decompressing gzip error\n");
			has_error = 1;
			break;
		}
		else
		{
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first)
			{
				*dest = (char *) malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			}
			else
			{
				*dest = (char *) realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
				strcat(*dest, tmp);
			}
		}
	}
	while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error)
	{
		if (!is_first)
			free(*dest);
		*dest = NULL;
		return -1;
	}
	else
	{
		return 0;
	}
}

int QQFileExtractor::Decomp_gzip_1(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_1 ...\n");
	int res;
	char tmp[201];
	int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Bytef *) src;
	d_stream.avail_in = len;

	do
	{
		d_stream.next_out = (Bytef *) tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK)
		{
			LOG_WARN("Decomp_gzip_): decompressing gzip error\n");
			has_error = 1;
			break;
		}
		else
		{
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first)
			{
				*dest = (char *) malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			}
			else
			{
				*dest = (char *) realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
				strcat(*dest, tmp);
			}
		}
	}
	while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error)
	{
		//printf("decomp_gzip_1 complete Error ...\n");
		return -1;
	}
	else
	{
		//printf("decomp_gzip_1 complete Ok ...\n");
		return 0;
	}
}

int QQFileExtractor::Decomp_gzip_2(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_2 ...\n");
	int res;
	char tmp[201];
	int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Bytef *) src;
	d_stream.avail_in = len;

	do
	{
		d_stream.next_out = (Bytef *) tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END)
		{

			LOG_WARN("Decomp_gzip_2(): decompressing gzip error\n");
			has_error = 1;
			break;

		}
		else
		{
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first)
			{
				*dest = (char *) malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			}
			else
			{
				*dest = (char *) realloc(*dest, d_stream.total_out + 1);

				if (*dest == NULL)
					has_error = 1;
				strcat(*dest, tmp);


			}
		}
	}
	while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error)
	{
		//printf("decomp_gzip_2 complete Error ...\n");
		return -1;
	}
	else
	{
		//printf("decomp_gzip_2 complete Ok ...\n");
		return 0;
	}
}

int QQFileExtractor::Decomp_gzip_3(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_2 ...\n");
	int res;
	char tmp[201];
	int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;
	char *ptemp = NULL;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Bytef *) src;
	d_stream.avail_in = len;

	do
	{
		d_stream.next_out = (Bytef *) tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END)
		{

			LOG_WARN("Decomp_gzip_3(): decompressing gzip error\n");
			has_error = 1;
			break;

		}
		else
		{
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first)
			{
				*dest = (char *) malloc(n + 1);
				if (*dest == NULL)
				{
					has_error = 1;
					return 0;
				}
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			}
			else
			{
				//*dest = realloc(*dest, d_stream.total_out + 1);
				ptemp = (char *) realloc(*dest, d_stream.total_out + 1);
				if (ptemp == NULL)
				{
					has_error = 1;
					ptemp = *dest;
					return 0;
				}
				*dest = ptemp;
				strcat(*dest, tmp);
				//if (*dest == NULL)
				//      has_error = 1;
				//strcat(*dest, tmp);
			}
		}
	}
	while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error)
	{
		//printf("decomp_gzip_2 complete Error ...\n");
		return -1;
	}
	else
	{
		//printf("decomp_gzip_2 complete Ok ...\n");
		return 0;
	}
}

