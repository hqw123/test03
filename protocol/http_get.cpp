/*
*
*
*/

#include "db_data.h"
#include "http_get.h"
#include  <boost/filesystem.hpp>

int g_url_pos = 0;    //the position of url_stream[URL_HASH_POS]
int g_ext_pos = 0;    //the position of ext_url_stream[URL_POS]
int g_tmpmap_key = 0; // key of tmpmap;
//int g_css_key = 0;    // key of cssmap
int g_cook_key = 0;   //key of cookMap
extern const char * lzDataPath;

using namespace std;
using namespace boost;

#if 0
static int HashTime(char *path)
{
	time_t timeval;
	int dirnum;

	time(&timeval);
	dirnum = (timeval / 300) % 12;
	if (strncmp(lzDataPath,"/home",5) != 0)
	{
		sprintf(path, "/home/spyData/%d/httpget_%lu.xml", dirnum, timeval);
	}
	else
	{
		sprintf(path, "%s/spyData/%d/httpget_%lu.xml", lzDataPath, dirnum, timeval);
	}
	return 0;
}
#endif

/*
*-----------------------------------------------------------------------
* Func Name   : HttpGet
* Description : Constructor.
* Parameter   : void
* Return      : void
*-----------------------------------------------------------------------
*/
HttpGet::HttpGet()
{
    nContentLen = 0;
    memset(userAgent_, 0x00, sizeof(userAgent_));
    memset(strTitle, 0x00, sizeof(strTitle));
    memset(strCode, 0x00, sizeof(strCode));
    memset(strCharset, 0x00, sizeof(strCharset));
    memset(strTitle, 0x00, sizeof(strTitle));
    regex_init();
}

/*
*-----------------------------------------------------------------------
* Func Name   : ~HttpGet
* Description : Destructor.
* Parameter   : void
* Return      : void
*-----------------------------------------------------------------------
*/
HttpGet::~HttpGet()
{
    delete FiltRule;
    delete ChunkRule;
    delete expression_useragent;
	delete expression_host;
	delete expression_url;
	delete expression_html1;
    delete expression_html2;
	delete expression_html3;
	delete expression_html_title;
	delete expression_css;
	delete expression_css2;
	delete expression_charset;
	delete expression_charset2;
    delete expression_content_length;
	delete expression_chunk;
	delete expression_gzip;
	delete expression_deflate;
}

#if 0
/*
*-----------------------------------------------------------------------
* Func Name   : write_ext_xml
* Description : write extend data to xml
* Parameter   : void
* Return      : bool
*-----------------------------------------------------------------------
*/
void HttpGet::write_ext_xml(unsigned int lHash)
{
	char writepath[MAX_PATH_LEN + 1], path_str[MAX_PATH_LEN + 1],path_tmp[MAX_PATH_LEN + 1];
	memset(writepath, 0 , MAX_PATH_LEN + 1);
	memset(path_str, 0 , MAX_PATH_LEN + 1);
	memset(path_tmp, 0 , MAX_PATH_LEN + 1);
	
	struct tm *pt;
	time_t curtime;
	curtime=time(NULL);   
	pt=localtime(&curtime);
	if (strncmp(lzDataPath,"/home",5) != 0)
	{
		sprintf(path_str,"%s%d%d%d%s%d",HTML_DATA_PATH,pt->tm_year+1900,pt->tm_mon+1,pt->tm_mday,"/",pt->tm_hour);
	}
	else
	{
		char *p = (char *)HTML_DATA_PATH;
		p += 5;
		sprintf(path_str,"%s%s%d%d%d%s%d",lzDataPath,p,pt->tm_year+1900,pt->tm_mon+1,pt->tm_mday,"/", pt->tm_hour);
	}
	
	//boost::filesystem::path ps(path_str);
	boost::filesystem::create_directories(path_str);
	//sprintf(path_tmp,"%s %s %s","mkdir","-p",path_str);
	//system(path_tmp);
	snprintf(writepath, MAX_PATH_LEN, "%s/tmp_httpget_%d.xml", path_str,lHash);
	//cout<<"ext file path = "<<writepath<<endl;

	ofstream file(writepath, ios::ate);
	file << "<?xml version=\"1.0\"";
	file << " encoding=\"UTF-8\"?>\n";
	file << "<table name=\"HTTPGET\">\n";

	for (int i = 0;i <= g_ext_pos;i++)
	{
		file << "  <data>\n";
//		file << "    <devicenum>" << ext_url_stream[i]->dev_id << "</devicenum>\n";
		file << "    <objectid>" << ext_url_stream[i]->object_id << "</objectid>\n";
		file << "    <source_ip>" << inet_ntoa(*(struct in_addr *)&(ext_url_stream[i]->addr.saddr)) << "</source_ip>\n";
		file << "    <source_port>" << ext_url_stream[i]->addr.sport << "</source_port>\n";
		file << "    <dest_ip>" << inet_ntoa(*(struct in_addr *)&(ext_url_stream[i]->addr.daddr)) << "</dest_ip>\n";
		file << "    <dest_port>" << ext_url_stream[i]->addr.dport << "</dest_port>\n";
		file << "    <capture_time>" << ext_url_stream[i]->tv_sec << "</capture_time>\n";
		file << "    <client_mac>" << ext_url_stream[i]->srcMac << "</client_mac>\n";
		file << "    <url><![CDATA[" << ext_url_stream[i]->url_array << "]]></url>\n";
		file << "    <type>101</type>\n";
		file << "  </data>\n";
		delete[] ext_url_stream[i];
	}
	file << "</table>\n";
	file.close();
	
	char newpath[MAX_PATH_LEN + 1];
	memset(newpath,0,MAX_PATH_LEN + 1);
	snprintf(newpath, MAX_PATH_LEN, "%s/httpget_%d.xml", path_str,lHash);
	//cout<<"2222222"<<endl;
	char strTmpPath[MAX_PATH_LEN + 1];
	memset(strTmpPath,0,MAX_PATH_LEN + 1);
	//cout<<"333333"<<endl;
	memcpy(strTmpPath,newpath,strlen(newpath));
	//cout<<"strTmpPath == "<<strTmpPath<<endl;
	unlink(newpath);
	link(writepath, newpath);
	HashTime(newpath);
	rename(writepath, newpath);
		
	//char str[128] = {0};
	//sprintf(str,"%s %s %s","rm","-f",strTmpPath);
	//system(str);
	boost::filesystem::remove(strTmpPath);
	//cout<<"write ext xml over!"<<endl;
}
#endif

/*
*-----------------------------------------------------------------------
* Func Name   : write2db
* Description : write data to PublicOcci
* Parameter   : nPos:the position of url_stream[]
* Return      : void
*-----------------------------------------------------------------------
*/
void HttpGet::write2db(int nPos, unsigned int clue_id)
{
	/*write http data to shared memory, by zhangzm*/
	HTTP_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = clue_id;
	tmp_data.p_data.readed = 0;
    if(clue_id == 0)
    {
        strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&(ext_url_stream.addr.saddr)));
        strncpy(tmp_data.p_data.clientMac, (char *)ext_url_stream.srcMac, 17);
        sprintf(tmp_data.p_data.clientPort, "%d", ext_url_stream.addr.sport);
        strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&(ext_url_stream.addr.daddr)));
        sprintf(tmp_data.p_data.serverPort, "%d", ext_url_stream.addr.dport);
        tmp_data.p_data.captureTime = ext_url_stream.tv_sec;
        strncpy(tmp_data.url, ext_url_stream.url_array, 2047);
    }
    else
    {
	    strcpy(tmp_data.p_data.clientIp, inet_ntoa(*(struct in_addr *)&(url_stream[nPos]->addr.saddr)));
	    strncpy(tmp_data.p_data.clientMac, (char *)url_stream[nPos]->srcMac, 17);
	    sprintf(tmp_data.p_data.clientPort, "%d", url_stream[nPos]->addr.sport);
	    strcpy(tmp_data.p_data.serverIp, inet_ntoa(*(struct in_addr *)&(url_stream[nPos]->addr.daddr)));
	    sprintf(tmp_data.p_data.serverPort, "%d", url_stream[nPos]->addr.dport);
	    tmp_data.p_data.captureTime = url_stream[nPos]->tv_sec;
	    strncpy(tmp_data.url, url_stream[nPos]->url_array, 2047);
        if(strlen(url_stream[nPos]->html_title) > 0)
        {
            strncpy(tmp_data.title, url_stream[nPos]->html_title, 511);
        }
        if(strlen(url_stream[nPos]->file_path) > 0)
        {
	        strncpy(tmp_data.file_path, url_stream[nPos]->file_path, FILEPATH_MAXSIZE - 1);
        }
    }
    
    strncpy(tmp_data.environment, userAgent_, 511);
	tmp_data.p_data.proType = 101;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(HTTP, (void *)&tmp_data, sizeof(tmp_data));
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_http
* Description : �ж����ݰ�pPkt�Ƿ�ΪHTTP���ݰ�
* Parameter   : pPkt:struct PacketInfo
* Return      : �Ƿ���true��ʧ�ܷ���false
*-----------------------------------------------------------------------
*/
bool HttpGet::is_http(struct PacketInfo *pPkt)
{
    bool ret = false;

    if (pPkt->ip->ihl >= 5)
    {
        if (pPkt->ip->version == 4)
        {
            if (pPkt->ip->protocol == 6)
            {
                if ((pPkt->srcPort == 80) || (pPkt->destPort == 80))
                {
                    ret = true;
                }
            }
        }
    }

    return ret;
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_get_pkt
* Description : �ж��Ƿ�ΪHTTP��GET����
* Parameter   : pPkt:struct PacketInfo
* Return      : �����GET���ݰ�������0�����򷵻�-1
*-----------------------------------------------------------------------
*/
bool HttpGet::is_get_pkt(struct PacketInfo* pPkt)
{
    if (pPkt->bodyLen >= 4)
    {
        if ((strncmp(pPkt->body, "GET ", 4) == 0) && strstr(pPkt->body, "\r\n\r\n") )
        {
            return true;
        }
    }

    return false;
}

/*
*-----------------------------------------------------------------------
* Func Name   : delete_map
* Description : Erase the unused map space
* Parameter   : lHash:value of hash
* Return      : void
*-----------------------------------------------------------------------
*/
int HttpGet::delete_map(unsigned int lHash)
{    	
	map<int,tmpPos>::iterator iter;
	for (iter=mapNd.begin();iter!=mapNd.end();)
	{
		if (lHash == iter->second.hash)
		{
			
			if (url_stream[iter->second.urlPos] != NULL)
			{
				//cout<<"111111"<<endl;
				delete url_stream[iter->second.urlPos];
				url_stream[iter->second.urlPos] = NULL;
				//cout<<"2222222"<<endl;
			}
			//cout<<"33333"<<endl;
			mapNd.erase(iter++);
			//cout<<"44444444"<<endl;
			return 0;
		}
		else
		{
			iter++;
		}
	}
	return -1;
}

void HttpGet::erase_hash(unsigned int lHash)
{
	map<int,tmpPos>::iterator iter;
	for (iter=mapNd.begin();iter!=mapNd.end();)
	{
		if (lHash == iter->second.hash)
		{
			mapNd.erase(iter++);
			return;
		}
		else
		{
			iter++;
		}
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : delete_fail_file
* Description : delete the fail rebuild file or not the needed rebuild file
* Parameter   : lHash:value of hash
* Return      : void
*-----------------------------------------------------------------------
*/
/*void HttpGet::delete_fail_file(unsigned int lHash,char *url)
{
	//int nlen = 0;
	char strPath[128],strHost[32];
	memset(strPath,'\0',128);
	memset(strHost,'\0',32);
	struct tm *pt;
	time_t curtime;
	curtime=time(NULL);   
	pt=localtime(&curtime);

	//cout<<"host : "<<url<<endl;
	memcpy(strHost,url,strlen(url));
	sprintf(strPath,"%s %s %s%d%d%d%s%d%s%s%s%ld%s","rm","-rf",HTML_SEPCTRL_PATH,pt->tm_year+1900,pt->tm_mon+1,pt->tm_mday,"/",pt->tm_hour,"/",strHost,"/",lHash,".*");
	system(strPath);

}*/

/*
*-----------------------------------------------------------------------
* Func Name   : is_http_ok
* Description : �ж����ݰ��Ƿ�Ϊ��HTTP 200 OK�����ݰ�
* Parameter   : pPkt:struct PacketInfo
* Return      : void
*-----------------------------------------------------------------------
*/
void HttpGet::is_http_ok(struct PacketInfo *pPkt)
{
    bool is_html = false;
    struct tuple tp;

    tp.saddr = pPkt->ip->daddr;
    tp.sport = ntohs(pPkt->tcp->dest);
    tp.daddr = pPkt->ip->saddr;
    tp.dport = ntohs(pPkt->tcp->source);

    unsigned int lHash = mk_hash_index(tp); //,pPkt->pkt->ts.tv_sec);

    if (pPkt->bodyLen == 0 && pPkt->tcp->fin != 1)
    {
        return;
    }

    is_html = is_html_ok(pPkt);
	
    // �������HTTP 200 OK���ݰ���Ҳ����html���ݰ���ɾ��Ȼ�󷵻�
    if (!strncmp(pPkt->body, "HTTP/1.", 7)
        && ((!strncmp(pPkt->body + 9, "10", 2) || !strncmp(pPkt->body + 9, "30", 2)
            || !strncmp(pPkt->body + 9, "40", 2) || !strncmp(pPkt->body + 9, "50", 2)
            || !strncmp(pPkt->body + 9, "204", 3))|| (!strncmp(pPkt->body + 9, "200", 3) && !is_html)))
    {
        map<int, tmpPos>::iterator iter;
        for (iter = mapNd.begin(); iter != mapNd.end(); iter++)
        {
            if (lHash == iter->second.hash)
            {
                if (iter->second.nHCflag == 0)
                {
                    if (url_stream[iter->second.urlPos] != NULL)
                    {
						//add by hqw
						write2db(iter->second.urlPos, url_stream[iter->second.urlPos]->object_id);
                        delete url_stream[iter->second.urlPos];
                        url_stream[iter->second.urlPos] = NULL;
                    }
                }

                mapNd.erase(iter);
                break;
            }
        }

        return;
    }

    if (is_html)
    {
        deal_ok_pkt(pPkt);
    }
    else
    {
        analyse_rebuild_pkt(pPkt);
    }
}

/**
* ������: get_http_code
* ȫ��: HttpGet::get_http_code
* ��������: ��HTTPͷ����ȡHTTP���ݱ���
* ���ʿ���: private
* @param: const char * header  HTTPͷ���׵�ַ
* @param: unsigned int length  HTTPͷ������
* @return: int
*/
int HttpGet::get_http_code(const char* header, unsigned int length)
{
    boost::cmatch what;
    const char* begin = header;
    const char* end = header + length;
    memset(strCode, '\0', sizeof(strCode));

    if (boost::regex_search(begin, end, what, *expression_charset))
    {
        unsigned int len = what[0].length() - 9;
        const char* start = what[0].first + 8;

        len = (len < sizeof(strCode)) ? len : (sizeof(strCode) - 1);
        memcpy(strCode, start, len);
        strCode[len] = '\0';

        if (strCode[len - 1] == '\r')
        {
            strCode[len - 1] = '\0';
        }
    }
    else
    {
        strcpy(strCode, "");
    }
    
    if (strncasecmp(strCode, "gb2312", 6) == 0 || strncasecmp(strCode, "gbk", 3) == 0)
    {
        strcpy(strCode, "GB18030");
    }

    return 0;
}

/**
* ������: deal_ok_pkt
* ȫ��: HttpGet::deal_ok_pkt
* ��������: ����HTTP 200 OK���ݰ�
* ���ʿ���: private
* @param: struct PacketInfo * pPkt ���ݰ�
* @return: void
*/
void HttpGet::deal_ok_pkt(struct PacketInfo* pPkt)
{
    unsigned int lHash = 0;
    struct tuple tp;
    //char strTmpPath[128] = { 0 }, strFilePath[256] = { 0 };

    tp.saddr = pPkt->ip->daddr;
    tp.sport = ntohs(pPkt->tcp->dest);
    tp.daddr = pPkt->ip->saddr;
    tp.dport = ntohs(pPkt->tcp->source);
    lHash = mk_hash_index(tp); //,pPkt->pkt->ts.tv_sec);

    // ��ȡ���к�
    unsigned int lSeq = ntohl(pPkt->tcp->seq);

    map<int, tmpPos>::iterator iter;
    for (iter = mapNd.begin(); iter != mapNd.end(); iter++)
    {
        tmpPos& pckt = iter->second;
        if (lHash == pckt.hash)
        {
            // �ҵ���ǰ�Ự
            lSeq += pPkt->bodyLen;
            pckt.seq = lSeq;
            pckt.nOkFlag = 0;

            int lContLen = get_content_len(pPkt);
            pckt.lContentLen = lContLen;

            if (lContLen >= 0 && lContLen <= 512 && pckt.nHCflag == 0)
            {
                // Content-Length��0~512֮���HTML����
                delete_map(lHash);
                break;
            }
            else if (lContLen < 0)
            {
                // ����Content-Lengthʧ��
                pckt.lContentLen = 0;
            }
            else if (lContLen == 0 && pckt.nHCflag == 1)
            {
                // Content-LengthΪ0��CSS����
                erase_hash(lHash);
                break;
            }

            // �ж�Content-Encodingͷ��
            if (is_gzip(pPkt))
            {
                // gzip����
                pckt.nGzipFlag = 1;
            }
            else
            {
                // 3:deflate����
                // 2:δѹ������
                pckt.nGzipFlag = is_deflate(pPkt) ? 3 : 2;
            }

            // �ж��Ƿ����chunked��ʽ��������
            pckt.nChunkedFlag = is_chunk(pPkt) ? 1 : 2;

            // ��ȡHTTPͷ������
            int nPktEndLen = get_hdr_length(pPkt);
            if (nPktEndLen < 0)
            {
                // û�л�ȡ��HTTPͷ������
                if (pckt.nHCflag == 0)
                {
                    delete_map(lHash);
                }
                else
                {
                    erase_hash(lHash);
                }

                break;
            }
            else if (nPktEndLen == pPkt->bodyLen)
            {
                pckt.contLen = 0;
                pckt.nOkFlag = 0;
                // ��ȡ����
                get_http_code(pPkt->body, nPktEndLen);
                strcpy(pckt.strCd, strCode);
                break;
            }

            // ��ȡ����
            get_http_code(pPkt->body, nPktEndLen);
            strcpy(pckt.strCd, strCode);
            
            char* header = pPkt->body + nPktEndLen;

            if (pckt.lContentLen > 0)
            {
                pckt.strBuildData = new char[pckt.lContentLen + 1];
                memset(pckt.strBuildData, '\0', pckt.lContentLen + 1);
                memcpy(pckt.strBuildData, header, pPkt->bodyLen - nPktEndLen);
                pckt.contLen = pPkt->bodyLen - nPktEndLen;
            }
            else if (pckt.nChunkedFlag == 1)
            {
                pckt.strBuildData = NULL;
                pckt.lContentLen = 0;
                pckt.lDataSize = 0;
                int i = 0;

                while (i < pPkt->bodyLen - nPktEndLen)
                {
                    pckt.strData += header[i];
                    i++;
                }

                pckt.contLen = pPkt->bodyLen - nPktEndLen;
            }
            else
            {
                pckt.strBuildData = NULL;
                pckt.lDataSize = 0;
                int m = pPkt->bodyLen - nPktEndLen, i = 0;
                char* p = pPkt->body + nPktEndLen;

                while (i < m)
                {
                    pckt.strData += p[i];
                    i++;
                }

                pckt.contLen = pPkt->bodyLen - nPktEndLen;
            }

            if ((pckt.contLen >= (unsigned int)pckt.lContentLen && pckt.lContentLen > 0)
                || pPkt->tcp->fin == 1
                || memcmp(pPkt->body + pPkt->bodyLen - 5, "0\r\n\r\n", 5) == 0)
            {
                write_txt_file(lHash);
                //rebuild complished
                break;
            }

            break;
        }
    }
}

/**
* ������: get_hdr_length
* ȫ��: HttpGet::get_hdr_length
* ��������: ��ȡHTTPͷ������
* ���ʿ���: private
* @param: struct PacketInfo * pPkt
* @return: ��ȡ�ɹ�����HTTPͷ�����ȣ����򷵻�-1
*/
int HttpGet::get_hdr_length(struct PacketInfo* pPkt)
{
    int length = -1;

    if (pPkt->body == NULL)
    {
        return length;
    }

    const char* end = strstr(pPkt->body, "\r\n\r\n");
    if (NULL == end)
    {
        return length;
    }

    length = end - pPkt->body + 4;
    if (length < 0)
    {
        return -1;
    }

    if (length >= pPkt->bodyLen) {
        length = pPkt->bodyLen;
    }

    return length;
}

/**
* ������: analyse_rebuild_pkt
* ȫ��: HttpGet::analyse_rebuild_pkt
* ��������: �������
* ���ʿ���: private
* @param: struct PacketInfo * pPkt
* @return: int
*/
int HttpGet::analyse_rebuild_pkt(struct PacketInfo* pPkt)
{
    struct tuple tp;
    //char strFilePath[256] = { 0 };

    tp.saddr = pPkt->ip->daddr;
    tp.sport = ntohs(pPkt->tcp->dest);
    tp.daddr = pPkt->ip->saddr;
    tp.dport = ntohs(pPkt->tcp->source);
    unsigned int lHash = mk_hash_index(tp); //,pPkt->pkt->ts.tv_sec);

    unsigned int lSeq = ntohl(pPkt->tcp->seq);
    map<int, tmpPos>::iterator iter;

    for (iter = mapNd.begin(); iter != mapNd.end(); ++iter)
    {
        if (lHash == iter->second.hash)
        {
            tmpPos& session = iter->second;

            unsigned int nKey = lHash % MAX_LOST_POS;

            if ((session.seq < lSeq) && (pPkt->bodyLen != 0))
            {
                //!+ ���������ݰ��ǵ�ǰ�Ự���ڵ����ݰ�������bodyLen���Ȳ�Ϊ0
                //TODO ����ǰ���ݰ����浽tmpmap��
                tmpData tmpdata;

                session.nErrSeqFlag = 0;
                tmpdata.hash = lHash;
                tmpdata.seq = lSeq;
                tmpdata.bodyLen = pPkt->bodyLen;
                tmpdata.fin = pPkt->tcp->fin;

                memcpy(tmpdata.body, pPkt->body, pPkt->bodyLen);

                if (g_tmpmap_key == MAPMAXSIZE)
                {
                    g_tmpmap_key = 0;
                }

                tmpmap[nKey].insert(map<int, tmpData>::value_type(g_tmpmap_key, tmpdata));
                g_tmpmap_key++;
                return 0;
            }
            else if (pPkt->bodyLen != 0 && session.seq == lSeq)
            {
                //!+ ���������ݰ��պ��ǵ�ǰ�Ự����һ�����ݰ�

                lSeq += pPkt->bodyLen;
                session.seq = lSeq;     // ������һ�����ݰ������к�

                if (session.lContentLen > 0)
                {
                    //! ��Content-Length������
                    if (session.contLen == 0)
                    {
                        // û�п�ʼ��������
                        session.strBuildData = new char[session.lContentLen + 1];
                        memset(session.strBuildData, '\0', session.lContentLen + 1);
                        memcpy(session.strBuildData, pPkt->body, pPkt->bodyLen);
                        session.contLen = pPkt->bodyLen;
                    }
                    else if (session.contLen > 0)
                    {
                        // �Ѿ���ʼ��������ԭ���������£�
                        // 1. �ȷ���һ�������ڴ棻
                        // 2. ��ԭ�������ݺ͵�ǰ���ݰ������ݿ��������ڴ�
                        // 3. �ͷ�ԭ���ڴ�
                        if (session.strBuildData)
                        {
                            session.strBuildData = (char*)realloc(session.strBuildData, session.contLen + pPkt->bodyLen + 1);
                            if (!session.strBuildData)
                            {
                                LOG_ERROR("realloc error::%s", strerror(errno));
                                break;
                            }
                            memcpy(session.strBuildData + session.contLen, pPkt->body, pPkt->bodyLen);
                            session.contLen += pPkt->bodyLen;
                        }
                    }

                    if (!tmpmap[nKey].empty()) //rebuilt the lost packet
                    {
                        std::map<int, tmpData>::iterator _iter;

                        for (_iter = tmpmap[nKey].begin(); _iter != tmpmap[nKey].end(); )
                        {
                            if (_iter->second.seq == lSeq && lHash == _iter->second.hash)
                            {
                                if (session.strBuildData)
                                {
                                    session.strBuildData = (char*)realloc(session.strBuildData, session.contLen + _iter->second.bodyLen + 1);
                                    if (!session.strBuildData)
                                    {
                                        LOG_ERROR("realloc error::%s", strerror(errno));
                                        break;
                                    }
                                    memcpy(session.strBuildData + session.contLen, _iter->second.body, _iter->second.bodyLen);
                                }

                                tmpmap[nKey].erase(_iter++);

                                if (!tmpmap[nKey].empty())
                                {
                                    _iter = tmpmap[nKey].begin();//rebuilt again
                                    continue;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            else
                            {
                                _iter++;
                            }
                        }
                    }
                }
                else if (session.nChunkedFlag == 2 && session.lContentLen == 0 || session.nChunkedFlag == 1)
                {
                    //! chunked����
                    // 1. ����ǰ���ݰ����ݴ���strData�У�
                    // 2. ����������в�����һ�����ݰ�
                    //      ����ҵ����������ң�
                    //      ���û���ҵ����ȴ���һ�����ݰ�����
                    session.strData.append(pPkt->body, pPkt->bodyLen);
                    session.contLen += pPkt->bodyLen;

                    if (!tmpmap[nKey].empty()) //rebuilt the lost packet
                    {
                        std::map<int, tmpData>::iterator _iter;

                        for (_iter = tmpmap[nKey].begin(); _iter != tmpmap[nKey].end(); )
                        {
                            if (_iter->second.seq == lSeq && lHash == _iter->second.hash)
                            {
                                session.strData.append(_iter->second.body, _iter->second.bodyLen);

                                session.contLen += _iter->second.bodyLen;
                                session.seq += _iter->second.bodyLen;
                                lSeq += _iter->second.bodyLen;

                                // ʹ��++�������Ϊ�˷�ֹ������ʧЧ
                                tmpmap[nKey].erase(_iter++);

                                if (!tmpmap[nKey].empty())
                                {
                                    _iter = tmpmap[nKey].begin();//rebuilt again
                                    continue;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            else
                            {
                                ++_iter;
                            }
                        }
                    }
                }

                // �жϱ��λỰ�Ƿ����
                if ((session.contLen >= session.lContentLen && session.lContentLen > 0)
                    || (pPkt->tcp->fin == 1)
                    || (memcmp(pPkt->body + pPkt->bodyLen - 5, "0\r\n\r\n", 5) == 0 && session.nErrSeqFlag)
                    || (session.lContentLen > 0 && memcmp(session.strBuildData + session.contLen - 5, "0\r\n\r\n", 5) == 0)
                    || (session.strData.size() >= 5 && session.strData.compare(session.strData.size() - 5, 5, "0\r\n\r\n") == 0))
                {
                    write_txt_file(lHash);
                    return 0;//rebuild complished
                }

                return 0;
            }
            else if (pPkt->bodyLen == 0 && session.seq == lSeq)
            {
                // �жϱ��λỰ�Ƿ����
                if ((session.contLen >= session.lContentLen && session.lContentLen > 0)
                    || (pPkt->tcp->fin == 1)
                    || (memcmp(pPkt->body + pPkt->bodyLen - 5, "0\r\n\r\n", 5) == 0 && session.nErrSeqFlag)
                    || (session.lContentLen > 0 && memcmp(session.strBuildData + session.contLen - 5, "0\r\n\r\n", 5) == 0)
                    || (session.strData.size() >= 5 && session.strData.compare(session.strData.size() - 5, 5, "0\r\n\r\n") == 0))
                {
                    write_txt_file(lHash);
                    return 0;//rebuild complished
                }

                return 0;
            }

            return 0;
        }
    }

    return 0;
}


/**
* ������: write_txt_file
* ȫ��: HttpGet::write_txt_file
* ��������: ��������ɵ�HTTP�Ự����д���ļ�
* ���ʿ���: private
* @param: unsigned int lHash
* @return: int
*/
int HttpGet::write_txt_file(unsigned int lHash)
{
    char* dst = NULL;
    map<int, tmpPos>::iterator iter;

    for (iter = mapNd.begin(); iter != mapNd.end(); ++iter)
    {
        if (lHash == iter->second.hash)
        {
            tmpPos& session = iter->second;

            if (session.nHCflag == 0 && session.contLen <= 512)
            {
                delete_map(lHash);
                return -1;
            }

            const char* strHost = url_stream[session.urlPos]->host;
            
            char strTmpPath[MAX_PATH_LEN] = { 0 };
            char strFilePath[MAX_PATH_LEN] = { 0 };

            time_t curtime = time(NULL);
            struct tm* pt = localtime(&curtime);

            if (strncmp(lzDataPath, "/home", 5) != 0)
            {
                sprintf(strFilePath, "%s%d%02d%02d%s%d%s%s", HTML_SEPCTRL_PATH, pt->tm_year + 1900, pt->tm_mon + 1, pt->tm_mday, "/", pt->tm_hour, "/", strHost);
            }
            else
            {
                char* p = (char*)HTML_SEPCTRL_PATH;
                p += 5;
                sprintf(strFilePath, "%s%s%d%02d%02d%s%d%s%s", lzDataPath, p, pt->tm_year + 1900, pt->tm_mon + 1, pt->tm_mday, "/", pt->tm_hour, "/", strHost);
            }

            boost::filesystem::path ps(strFilePath);
            boost::filesystem::create_directories(ps);

            if (session.nHCflag == 0)
            {
                // html����
                sprintf(strTmpPath, "%s%s%d%s", strFilePath, "/", lHash, ".html");
            }
            else
            {
                // ȡhost
                char* p = strstr(session.strCss, "://");
                if (p == NULL)
                {
                    erase_hash(lHash);
                    return -1;
                }

                p = p + 3;
                char* p1 = strstr(p, "/");
                if (p1 == NULL)
                {
                    erase_hash(lHash);
                    return -1;
                }

                int len = p1 - p;
                char strTmp[MAX_PATH_LEN] = { 0 };
                memcpy(strTmp, p, len);

                if (memcmp(strTmp, strHost, strlen(strHost)) == 0)
                {
                    memset(strTmp, '\0', MAX_PATH_LEN);
                    memcpy(strTmp, p + strlen(strHost) + 1, strlen(p) - 4 - strlen(strHost) - 1);
                }
                else
                {
                    memset(strTmp, '\0', MAX_PATH_LEN);
                    memcpy(strTmp, p, strlen(p) - 4);
                }
                //css ����
                sprintf(strTmpPath, "%s%s%s%s", strFilePath, "/", strTmp, ".css");
                unsigned int nCount = 0;

                for (unsigned int i = 0; i < strlen(strTmpPath); i++)
                {
                    if (strTmpPath[i] == '/')
                    {
                        nCount = i;
                    }
                }

                if (nCount >= 128)
                {
                    erase_hash(lHash);
                    return 0;
                }

                char strMkDir[MAX_PATH_LEN], strDirPath[MAX_PATH_LEN];
                memset(strMkDir, 0, MAX_PATH_LEN);
                memset(strDirPath, 0, MAX_PATH_LEN);
                memcpy(strDirPath, strTmpPath, nCount);
                boost::filesystem::path ps(strDirPath);
                boost::filesystem::create_directories(ps);
                LOG_INFO("strMkDir = %s\n", strMkDir);
            }

            if (session.lContentLen == 0)
            {
                deal_chunk_data(lHash);
            }
            else 
            {
                session.lContentLen = session.contLen;
            }

            if (session.nGzipFlag != 2)
            {
                if (session.lContentLen > 0)
                {
                    int m = decomp_gzip(session.strBuildData, session.lContentLen, &dst, session.nGzipFlag);

                    if (m != 1)
                    {
                        if (session.strBuildData)
                        {
                            delete[] session.strBuildData;
                            session.strBuildData = NULL;
                        }

                        if (session.nHCflag == 0)
                        {
                            delete_map(lHash);
                        }
                        else
                        {
                            erase_hash(lHash);
                        }

                        return -1;
                    }
                    else
                    {
                        if (session.nHCflag == 0)
                        {
                            if (strlen(session.strCd) == 0)
                            {
                                if (get_charset(dst, strlen(dst)))
                                {
                                    memset(session.strCd, '\0', 64);
                                    strcpy(session.strCd, strCharset);
                                }
                                else
                                {
                                    if (session.strBuildData)
                                    {
                                        delete[] session.strBuildData;
                                        session.strBuildData = NULL;
                                    }

                                    if (session.nHCflag == 0)
                                    {
                                        delete_map(lHash);
                                    }
                                    else
                                    {
                                        erase_hash(lHash);
                                    }

                                    return -1;
                                }
                           }
                            
                            if (get_html_title(dst, strlen(dst), session.strCd, lHash))
                            {
                                memset(url_stream[session.urlPos]->html_title, '\0', TITLE_MAXSIZE);
                                memcpy(url_stream[session.urlPos]->html_title, strTitle, strlen(strTitle));
                            }
                            else
                            {
                                delete_map(lHash);
                                return -1;
                            }
                        }

                        LOG_INFO("strTmpPath = %s\n", strTmpPath);
                        ofstream fout(strTmpPath, ios::binary);
                        fout.write(dst, strlen(dst));
                        fout.close();
                        strncpy(url_stream[session.urlPos]->file_path, strTmpPath, strlen(strTmpPath));
                        if (session.strBuildData)
                        {
                            delete[] session.strBuildData;
                            session.strBuildData = NULL;
                        }
                    }
                }
            }
            else
            {
                if (session.lContentLen > 0)
                {
                    if (session.nHCflag == 0)
                    {
                        if (strlen(session.strCd) == 0)
                        {
                            if (get_charset(session.strBuildData, session.lContentLen))
                            {
                                memset(session.strCd, '\0', 64);
                                strcpy(session.strCd, strCharset);
                            }
                            else
                            {
                                if (session.strBuildData)
                                {
                                    delete[] session.strBuildData;
                                    session.strBuildData = NULL;
                                }

                                if (session.nHCflag == 0)
                                {
                                    delete_map(lHash);
                                }
                                else
                                {
                                    erase_hash(lHash);
                                }

                                    return -1;
                                }
                        }
                        if (get_html_title(session.strBuildData, session.lContentLen, session.strCd, lHash))
                        {
                            memset(url_stream[session.urlPos]->html_title, '\0', TITLE_MAXSIZE);
                            memcpy(url_stream[session.urlPos]->html_title, strTitle, strlen(strTitle));
                        }
                        else
                        {
                            delete_map(lHash);
                            return -1;
                        }
                    }

                    LOG_INFO("strTmpPath = %s\n", strTmpPath);
                    ofstream fout(strTmpPath, ios::binary);
                    fout.write(session.strBuildData, session.lContentLen);
                    fout.close();
                    strncpy(url_stream[session.urlPos]->file_path, strTmpPath, strlen(strTmpPath));
                    if (iter->second.strBuildData)
                    {
                        delete[] iter->second.strBuildData;
                        iter->second.strBuildData = NULL;
                    }
                }
            }

            write2db(session.urlPos, url_stream[session.urlPos]->object_id);
            release_node(lHash, strTmpPath);
            break;
        }
    }

    return 0;
}

/*
*-----------------------------------------------------------------------
* Func Name   : release_node
* Description : convert the code and release the data node
* Parameter   : lHash,strFilePath,nPos
* Return      : void
*-----------------------------------------------------------------------
*/
void HttpGet::release_node(unsigned int lHash,char *strTempPath)
{
	unsigned int nPos = 0;
	map<int,tmpPos>::iterator iter;
	for (iter = mapNd.begin();iter != mapNd.end();++iter)
	{
		if (lHash == iter->second.hash)
		{
            /*�ؿ�css����
            ֮ǰcss ���ݷ�utf-8���߷�utf-8��utf-8����ֱ�ӽ��ļ�����һ�ݣ���utf-8�����ת��
            ���ڵ�����css����Ҫ���ļ���ֱ�ӽ��ڵ�ɾ������
            */
			if (iter->second.nHCflag == 1)
			{
				erase_hash(lHash);
				break;
			}
			else
			{
              /*�ؿ�html����
                ֮ǰhtml���ݷ�utf-8���utf-8��utf-8���ļ�,��utf-8��Ҫ����ת��
                ����utf-8����֮ǰ�Ѿ�����ļ��������ﲻ��Ҫ����һ��,ֱ��ɾ����صĽڵ㼴��
              */			
				delete_map(lHash);
				if (iter->second.nErrSeqFlag == 0)
				{
					unsigned int nKey = lHash%MAX_LOST_POS;
					tmpmap[nKey].clear();
				}
				
				return;
			}
		}
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : filter_url
* Description : ���˵�һЩͼƬ��Flash����Ƶ��URL
* Parameter   : url
* Return      : ������Ϲ��˹��򣬷���true�����򷵻�false
*-----------------------------------------------------------------------
*/
bool HttpGet::filter_url(const char* url, int len)
{
    bool ret = false;
    boost::cmatch mth;
    char* strTmp = new char[len + 1];

    memcpy(strTmp, url, len);
    strTmp[len] = '\0';

    for (unsigned int i = 0; i < len; i++)
    {
        if (strTmp[i] >= 'A' && strTmp[i] <= 'Z')
        {
            strTmp[i] += 32;
        }
    }

    const char* begin = strTmp;
    const char* end = strTmp + len;

    if (boost::regex_search(begin, end, mth, *FiltRule))
    {
        ret = true;
    }

    delete[] strTmp;

    return ret;
}

/**
 * ������: get_http_url
 * ȫ��: HttpGet::get_http_url
 * ��������: ����URL
 * ���ʿ���: private 
 * @param: struct PacketInfo * pPkt
 * @return: bool
 */
bool HttpGet::get_http_url(struct PacketInfo *pPkt)
{
    bool ret = false;
    unsigned int lHash = 0;
    struct tuple this_addr;
    char url[MAX_PATH_LEN] = { 0 };
    char host[MAX_HOST_LEN] = { 0 };
    int hostLen = 0, urlLen = 0;
    
    // ƥ����
    boost::cmatch what;
    boost::cmatch mth;

    const char* begin = pPkt->body;
    const char* end = pPkt->body + pPkt->bodyLen;

    strcpy(url, "http://");
    urlLen = 7;

    // ƥ��host��������
	if (boost::regex_search(begin, end, what, *expression_host))
    {
        hostLen = what[0].length() - 8;         // host�ĳ���
        const char* start = what[0].first + 6;  // host�Ŀ�ʼλ��

        hostLen = (hostLen < sizeof(host)) ? hostLen : (sizeof(host) - 1);
        strncpy(host, start, hostLen);
        strcpy(url + urlLen, host);
        urlLen += hostLen;
	}
	else
    {
        return ret;
	}

    // ƥ�����·��uri
    if (boost::regex_search(begin, end, mth, *expression_url))
    {
        int len = mth[0].length() - 12;         // ����·���ĳ���
        const char* start = mth[0].first + 4;   // ����·���Ŀ�ʼλ��

        if (urlLen + len >= MAX_PATH_LEN)
        {
            LOG_WARN("url is too long!!\n");
        }
        else
        {
            strncpy(url + urlLen, start, len);
            urlLen += len;
        }
    }
    else
    {
        return ret;
    }

    // �˴�URL�Ľ����Ѿ����
    // ���˵�һЩͼƬ��Flash����Ƶ��URL
    if (filter_url(url, urlLen))
    {
        return true;
    }

    // ��ȡMac��ַ
    char Mac_Str[20] = { 0 };
    unsigned char* strMac = pPkt->srcMac;
    sprintf(Mac_Str, "%02x-%02x-%02x-%02x-%02x-%02x", strMac[0], strMac[1], strMac[2], strMac[3], strMac[4], strMac[5]);

    struct in_addr addr;
    addr.s_addr = pPkt->srcIpv4;
    unsigned int object_id = get_clue_id(Mac_Str, inet_ntoa(addr));

    this_addr.saddr = pPkt->srcIpv4;
    this_addr.daddr = pPkt->destIpv4;
    this_addr.dport = ntohs(pPkt->tcp->dest);
    this_addr.sport = ntohs(pPkt->tcp->source);

    //����ʱ��Ϊ��ģ�±���Ϊ�ؿض���ֱ�Ӹ�object_id��ֵ���磺object_id = 111��
    if (object_id == 0)
    {
        // ��������
        memset(&ext_url_stream, 0, sizeof(ext_url_stream));

        ext_url_stream.addr = this_addr;
        strcpy(ext_url_stream.url_array, url);
        ext_url_stream.tv_sec = pPkt->pkt->ts.tv_sec;
        strcpy((char*)ext_url_stream.srcMac, Mac_Str);
        ext_url_stream.object_id = object_id;

        //store DB
        write2db(0, object_id);
        return true;
    }

    bool is_css_url = is_css(url, urlLen);

    // ���˵�css��ʽ��url
    if (is_css_url)
    {
        return true;
    }

    // ������Ԫ��
    lHash = mk_hash_index(this_addr);

    // �ؿ�����
    if (g_url_pos >= MAPMAXSIZE)
    {
        mapNd.clear();
        g_url_pos = 0;
    }

    if (is_css_url)
    {
        // ����CSS����
        if (!deal_get_css(lHash, url, pPkt, g_url_pos))
        {
            return true;
        }
    }
    else
    {
        // ����HTML����
        url_stream[g_url_pos] = new hash_url;
        memset(url_stream[g_url_pos], '\0', sizeof(hash_url));

        url_stream[g_url_pos]->addr = this_addr;    // ��Ԫ��
        url_stream[g_url_pos]->nPos = g_url_pos;    // URL��URL���е�����
        memcpy(url_stream[g_url_pos]->url_array, url, urlLen);
        strcpy(url_stream[g_url_pos]->host, host);  // ���һ��host�ֶα���
        url_stream[g_url_pos]->object_id = object_id;
        url_stream[g_url_pos]->hash = lHash;
        url_stream[g_url_pos]->tv_sec = pPkt->pkt->ts.tv_sec;
        strcpy((char*)url_stream[g_url_pos]->srcMac, Mac_Str);

        //write2db(g_url_pos, object_id);

        tmpPos tmppos;
        tmppos.urlPos = g_url_pos;
        tmppos.hash = lHash;
        memcpy(tmppos.referrer, url, urlLen);

        mapNd.insert(map<int, tmpPos>::value_type(g_url_pos, tmppos));
    }

    g_url_pos++;

    return true;
}

/**
* ������: is_css
* ȫ��: HttpGet::is_css
* ��������: �ж�http get�Ƿ�Ϊcss����
* ���ʿ���: private
* @param: const char * url
* @param: int len
* @return: �ǵĻ�����true�����򷵻�false
*/
bool HttpGet::is_css(const char* url, int len)
{
    bool ret = false;
    char* strTmp = new char[len + 1];

    memcpy(strTmp, url, len);
    strTmp[len] = '\0';

    // Сд�ַ�ȫ��ת��Ϊ��д
    for (int i = 0; strTmp[i] != '\0'; i++)
    {
        if (strTmp[i] <= 'z' && strTmp[i] >= 'a')
        {
            strTmp[i] -= 32;
        }
    }
    
    boost::cmatch what;
    const char* begin = strTmp;
    const char* end = strTmp + len;

    if (boost::regex_search(begin, end, what, *expression_css))
    {
        ret = true;
    }

    delete[] strTmp;

    return ret;
}

/*
*-----------------------------------------------------------------------
* Func Name   : get_content_len
* Description : ��ȡContent-Lengthֵ
* Parameter   : pPkt:struct PacketInfo
* Return      : ������-1���ɹ��򷵻�Content-Lengthֵ
*-----------------------------------------------------------------------
*/
int HttpGet::get_content_len(struct PacketInfo* pPkt)
{
    int length = -1;
  
    boost::cmatch what;
    const char* begin = pPkt->body;
    const char* end = pPkt->body + pPkt->bodyLen;

    if (boost::regex_search(begin, end, what, *expression_content_length))
    {
        int len = what[0].length() - 16;
        if (len <= 0)
        {
            return length;
        }

        char str[20] = { 0 };
        const char* start = what[0].first + 15;
        len = len >= sizeof(str) ? (sizeof(str) - 1) : len;
        memcpy(str, start, len);

        length = atol(str);
    }

    return length;
}

/**
* ������: get_charset
* ȫ��: HttpGet::get_charset
* ��������: ��html�л�ȡ��������
* ���ʿ���: private
* @param: char * str��html����
* @param: unsigned int lLen��HTML���볤��
* @return: bool
*/
bool HttpGet::get_charset(char* str, unsigned int lLen)
{
    bool ret = false;
    boost::cmatch what;
    const char* begin = str;
    const char* end = str + lLen;
    const char* p1 = str; // ָ����������ַ�����ָ��

    int nlen = 0;

    if (boost::regex_search(begin, end, what, *expression_charset2))
    {
        nlen = what[2].length();
        p1 = what[2].first;
    }
    else if ((p1 = strstr(begin, "charset=")) != NULL)
    {
        p1 += 8;
        const char* p2 = strstr(p1, ">");
        nlen = p2 - p1;
    }
    else if ((p1 = strstr(begin, "encoding=")) != NULL)
    {
        p1 += 9;
        const char* p2 = strstr(p1, ">");
        nlen = p2 - p1;
    }

    if (p1 == NULL || nlen <= 0)
    {
        return false;
    }
    else if (nlen >= 15)
    {
        boost::scoped_array<char> strTmp(new char[nlen + 1]);
        memcpy(strTmp.get(), p1, nlen);
        strTmp[nlen] = '\0';

        if (strncasecmp(strTmp.get(), "utf-8", 5) == 0)
        {
            strcpy(strCharset, "utf-8");
        }
        else if (strncasecmp(strTmp.get(), "gb2312", 6) == 0 || strncasecmp(strTmp.get(), "gbk", 3) == 0)
        {
            strcpy(strCharset, "GB18030");
        }
    }
    else
    {
        int n_len = 0;
        boost::scoped_array<char> strTmp(new char[nlen + 1]);

        // ���������ͱ��浽strTmp��
        memcpy(strTmp.get(), p1, nlen);

        if (strTmp[0] == '\"')
        {
            char* p = strstr(strTmp.get() + 1, "\"");
            if (p == NULL)
            {
                return false;
            }

            n_len = p - strTmp.get();
            memset(strCharset, '\0', 64);
            memcpy(strCharset, strTmp.get() + 1, n_len - 1);
        }
        else
        {
            char* p = strstr(strTmp.get(), "\"");

            if (p == NULL)
            {
                char* p1 = strstr(strTmp.get(), "\'");

                if (p1 == NULL)
                {
                    n_len = nlen - 1;
                }
                else
                {
                    n_len = p1 - strTmp.get();
                }

                memset(strCharset, '\0', 64);
                memcpy(strCharset, strTmp.get(), n_len);
            }
            else
            {
                n_len = p - strTmp.get();
                memset(strCharset, '\0', 64);
                memcpy(strCharset, strTmp.get(), n_len);
            }
        }

        if (strcasecmp(strCharset, "gb2312") == 0 || strcasecmp(strCharset, "gbk") == 0)
        {
            memset(strCharset, '\0', 64);
            memcpy(strCharset, "GB18030", strlen("GB18030"));
        }
    }

    return ret;
}

/**
* ������: get_html_title
* ȫ��: HttpGet::get_html_title
* ��������: ��html�����н�����title
* ���ʿ���: private
* @param: char * str��html����
* @param: unsigned int lLen��html���볤��
* @param: char* strCode��Դ��������
* @param: unsigned int lHash����ϣֵ�����ڱ���ת����ı�������
* @return: ��ȡ�ɹ�����true�����򷵻�false
*/
bool HttpGet::get_html_title(char* str, unsigned int lLen, char* strCode, unsigned int lHash)
{
    boost::cmatch what;
    const char* begin = str;
    const char* end = str + lLen;

    if (strlen(strCode) == 0)
    {
        strcpy(strCode, "gb2312");
    }

    if (boost::regex_search(begin, end, what, *expression_html_title))
    {
        int len = what[0].length() - 15;
        if (len <= 0)
        {
            return false;
        }

        char strTmp[TITLE_MAXSIZE] = { 0 };
        // ����title�ĳ��ȣ����������������ȡ��������С-1���ֽ�
        len = (len < sizeof(strTmp)) ? len : sizeof(strTmp) - 1;
        memcpy(strTmp, what[0].first + 7, len);

        // �ÿո����title�еĿհ׷�
        for (unsigned int i = 0; i < len; i++)
        {
            if (strTmp[i] == '\r' || strTmp[i] == '\n' || strTmp[i] == '\t')
            {
                strTmp[i] = ' ';
            }
        }

        if (strcasecmp(strCode, "utf-8") == 0 || strncasecmp(strCode, "iso-", 4) == 0)
        {
            strcpy(strTitle, strTmp);
        }
        else if (!strncasecmp(strCode, "gbk", 3) || !strncasecmp(strCode, "gb18030", 7) 
            || !strncasecmp(strCode, "gb2312", 6) || !strncasecmp(strCode, "utf-8", 5))
        {
            // ����ת��
            char* pStr = strTmp;
            char* pOutbuf = strTitle;
            char** pIn = &pStr;
            char** pOut = &pOutbuf;

            len = strlen(pStr);
            int dstLen = TITLE_MAXSIZE; // ���ڱ���ת�����title����
            iconv_t cd = iconv_open("utf-8", strCode);

            if (cd == (iconv_t)-1)
            {
                return false;
            }

            memset(strTitle, '\0', TITLE_MAXSIZE);

            if (iconv(cd, pIn, (size_t*)&len, pOut, (size_t*)&dstLen) == -1)
            //if (iconv(cd, (char**)&pStr, (size_t*)&len, (char**)&pOutbuf, (size_t*)&dstLen) == -1)
            {
                map<int, tmpPos>::iterator iter;
                for (iter = mapNd.begin(); iter != mapNd.end(); ++iter)
                {
                    if (lHash == iter->second.hash)
                    {
                        strcpy(iter->second.strCd, "utf-8");
                    }
                }

                strcpy(strTitle, strTmp);
            }

            iconv_close(cd);
        }

        return true;
    }

    return false;
}

/*
*-----------------------------------------------------------------------
* Func Name   : deal_get_css
* Description : push css hash and referrer to map
* Parameter   : hash and referrer
* Return      : void
*-----------------------------------------------------------------------
*/
bool HttpGet::deal_get_css(unsigned int lHash,char *url,struct PacketInfo *pPkt,int nKey)
{
	tmpPos tmpos;
	//memset(&tmpos,'\0',sizeof(struct temp_pos));
	tmpos.hash = lHash;
	memset(tmpos.referrer,'\0',MAX_PATH_LEN);
	memset(tmpos.strCss,'\0',512);
	memcpy(tmpos.strCss,url,strlen(url));
	tmpos.nHCflag = 1;
	
	boost::cmatch what;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;
	if (boost::regex_search(begin, end, what,*expression_css2))
	{
		//cout<<"matched Referer!"<<endl;
		int nlen = what[0].length();
		nlen -= 11;
		memcpy(tmpos.referrer,what[0].first+9,nlen);
		char *p1=strstr(tmpos.referrer,"://");
		if (p1 == NULL)
		{
			cout<<"Can't get the css first page!"<<endl;
			return false;
		}
		p1 += 3;
		char strHost[128];
		memset(strHost,0,128);
		char *p2 = strstr(p1,"/");
		if (p2 == NULL)
		{
			memcpy(strHost,p1,strlen(p1)-2);
		}
		else
		{
			nlen = p2 - p1;
			memcpy(strHost,p1,nlen);
		}
		//cout<<"Host: "<<strHost<<endl;
		char *p3 = strstr(url,"/");
		if (p3 == NULL)
		{
			cout<<"Can't get the first page of css url!"<<endl;
			return false;
		}
		int nLength = p3 - url;
		char strTmp[512],strFilePath[MAX_PATH_LEN];
		memset(strTmp,0,512);
		memset(strFilePath,0,MAX_PATH_LEN);
		memcpy(strTmp,url,nLength);
		//cout<<"strTmp: "<<strTmp<<endl;
		struct tm *pt;
		time_t curtime;
		curtime=time(NULL);   
		pt=localtime(&curtime);
		if (strncmp(strTmp,strHost,strlen(strHost)) == 0)
		{
			sprintf(strFilePath,"%s%d%d%d%s%d%s%s",HTML_SEPCTRL_PATH,pt->tm_year+1900,pt->tm_mon+1,pt->tm_mday,"/",pt->tm_hour,"/",url);
		}
		else
		{
			sprintf(strFilePath,"%s%d%d%d%s%d%s%s%s%s",HTML_SEPCTRL_PATH,pt->tm_year+1900,pt->tm_mon+1,pt->tm_mday,"/",pt->tm_hour,"/",strHost,"/",url);
		}
		//cout<<"strFilePath:"<<strFilePath<<endl;
		FILE *fp;
		fp = fopen(strFilePath,"r");
		if (fp != NULL)
		{
			//cout<<"strFilePath: "<<strFilePath<<" is exist!"<<endl;
			fclose(fp);
			return false;
		}

		//cout<<"get the referer!"<<endl;
		mapNd.insert(map<int,tmpPos>::value_type(nKey,tmpos));
		return true;
	}
	else
	{
		//cout<<"no matched Referer!"<<endl;
		return false;
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : mk_hash_index
* Description : ������Ԫ�飬����Hash��ֵ
* Parameter   : srcIp dstIp srcPort dstPort
* Return      : unsigned int
*-----------------------------------------------------------------------
*/
unsigned int HttpGet::mk_hash_index(struct tuple addr) //,unsigned int lSec)
{
    unsigned int res = 0;
    res = (addr.sport << 7) ^ (addr.sport << 8)
        ^ (addr.dport << 6) ^ (addr.dport << 9)
        ^ (addr.saddr >> 1) ^ (addr.daddr >> 1)
        ^ (addr.saddr >> 2) ^ (addr.daddr << 1);
    res = (res >> 1); // + lTmpLen;
    char str[32] = { 0 };
    sprintf(str, "%d", res);

    if (str[0] == '-')
    {
        str[0] = ' ';
    }

    res = atol(str);
    return res;
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_return_pkt
* Description : �ж����ݰ�pPkt�Ƿ�Ϊ�������ķ������ݰ�
* Parameter   : struct PacketInfo
* Return      : �����HTML���ذ�������true�����򷵻�false
*-----------------------------------------------------------------------
*/
bool HttpGet::is_return_pkt(struct PacketInfo* pPkt)
{
    bool ret = false;
    unsigned int lHash = 0;
    struct tuple tp;

    tp.saddr = pPkt->ip->daddr;
    tp.sport = ntohs(pPkt->tcp->dest);
    tp.daddr = pPkt->ip->saddr;
    tp.dport = ntohs(pPkt->tcp->source);

    // ������Ԫ���Hashֵ
    lHash = mk_hash_index(tp); //,pPkt->pkt->ts.tv_sec);

    std::map<int, tmpPos>::iterator iter;
    for (iter = mapNd.begin(); iter != mapNd.end(); ++iter)
    {
        if (lHash == iter->second.hash)
        {
            ret = true;
            break;
        }
    }

    return ret;
}


/**
* ������: analyse_get_pkt
* ȫ��: HttpGet::analyse_get_pkt
* ��������: ������
* ���ʿ���: public
* @param: struct PacketInfo * pPkt
* @return: �ɹ�����true��ʧ�ܷ���false
*/
bool HttpGet::analyse_get_pkt(struct PacketInfo* pPkt)
{
    bool ret = false;

    if (is_http(pPkt))
    {
        if (is_get_pkt(pPkt))
        {
            // ��ʼһ���Ự
            // ��ʼ��һЩ��Ա
            nContentLen = 0;
            memset(userAgent_, 0x00, sizeof(userAgent_));
            memset(strTitle, 0x00, sizeof(strTitle));
            memset(strCode, 0x00, sizeof(strCode));
            memset(strCharset, 0x00, sizeof(strCharset));
            memset(strTitle, 0x00, sizeof(strTitle));

            analyse_UserAgent(pPkt);
            get_http_url(pPkt);
            ret = true;
        }
        else if (is_return_pkt(pPkt))
        {
            is_http_ok(pPkt);
            ret = true;
        }
    }

    return ret;
}


/*
*-----------------------------------------------------------------------
* Func Name   : is_html_ok
* Description : ����Content-Typeͷ�����ж��Ƿ�Ϊhtml��css��xml����������
* Parameter   : struct PacketInfo
* Return      : ���򷵻�true�����򷵻�false
*-----------------------------------------------------------------------
*/
bool HttpGet::is_html_ok(struct PacketInfo *pPkt)
{
    bool ret = false;
	
	boost::cmatch what;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;
	if (  boost::regex_search(begin, end, what,*expression_html1)
	    ||boost::regex_search(begin, end, what,*expression_html2)
	    ||boost::regex_search(begin, end, what,*expression_html3))
    {
        ret = true;
    }

    return ret;
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_chunk
* Description : judge the html data isn't use chunk size to transport
* Parameter   : struct PacketInfo
* Return      : int
*-----------------------------------------------------------------------
*/
bool HttpGet::is_chunk(struct PacketInfo *pPkt)
{
	boost::cmatch what;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;
	if (boost::regex_search(begin, end, what,*expression_chunk))
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_gzip
* Description : judge the html data isn't use gzip to transport
* Parameter   : struct PacketInfo
* Return      : int
*-----------------------------------------------------------------------
*/
bool HttpGet::is_gzip(struct PacketInfo *pPkt)
{	
	boost::cmatch what;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;
	if (boost::regex_search(begin, end, what,*expression_gzip))
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : is_default
* Description : judge the get packet isn't has Accept-Encoding: gzip
* Parameter   : struct PacketInfo
* Return      : bool
*-----------------------------------------------------------------------
*/
bool HttpGet::is_deflate(struct PacketInfo *pPkt)
{
	boost::cmatch what;
	const char *begin = pPkt->body;
	const char *end = pPkt->body + pPkt->bodyLen;
	if (boost::regex_search(begin, end, what,*expression_deflate))
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : decomp_gzip
* Description : decompress the data
* Parameter   : src:uncompress data,len:length of uncompress data,dest: decompress data
* Return      : int
*-----------------------------------------------------------------------
*/
int HttpGet::decomp_gzip(char *src, unsigned int len, char **dest,int flag)
{
	int res;
	char tmp[201];
	//int have;
	int is_first = 1;
	int n;
	int has_error = 0;
	int ret;
	char *ptemp=NULL;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	//cout<<"2255 flag = "<<flag<<endl;
	if (flag == 1)
	{
		ret = inflateInit2(&d_stream, 47);
	}
	else if (flag == 3)
	{
		//inflate_read(src,len,dest);
		inflateInit2(&d_stream,-15);
		//return 0;
	}
	d_stream.next_in = (Bytef *)src;
	d_stream.avail_in = len;

	//cout<<"decomp_gzip beginning!!!"<<endl;
	do 
	{
		d_stream.next_out = (Bytef *)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END) 
		{
			LOG_WARN("httpget:decomp_gzip(): decompressing gzip error\n");
			return -1;
		} 
		else 
		{
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) 
			{
				*dest = (char *)malloc(n + 1);
				if (*dest == NULL)
				{
					//cout<<"1111111111"<<endl;
					has_error = 1;
					return -1;
				}
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
			else 
			{
				//*dest = (char *)realloc(*dest, d_stream.total_out + 1);
				ptemp=(char *)realloc(*dest, d_stream.total_out + 1);
				/*if (*dest == NULL)
				{
					//cout<<"1111111111"<<endl;
					has_error = 1;
				}
				strcat(*dest, tmp);*/
				if(ptemp == NULL)
				{
					has_error = 1;
					return -1;
					ptemp=*dest;
				} 
				*dest=ptemp;
				strcat(*dest,tmp);
			}
		}
	} 
	while (d_stream.avail_out == 0);
	inflateEnd(&d_stream);
	
	//cout<<"decomp_gzip end!!!!"<<endl;
	if (has_error) 
	{
		return -1;
	} 
	else 
	{
		return 1;
	}
}

/*
*-----------------------------------------------------------------------
* Func Name   : get_position
* Description : length between beginning of the packet and chunk size position
* Parameter   : str,strlen
* Return      : int
*-----------------------------------------------------------------------
*/
int HttpGet::get_position(char *str,int strLen)
{
	int nLength = 0;
	boost::cmatch matchedStr;
	const char *begin = str;
	//cout<<"body:"<<begin<<endl;
	const char *end = str + strLen;
	if (boost::regex_search(begin, end, matchedStr, *ChunkRule))
	{
		nLength = matchedStr[0].first - begin;
	}
	else
	{
		nLength = -1;
	}
	return nLength;
}

/*
*-----------------------------------------------------------------------
* Func Name   : get_chunksize_len
* Description : get the length of the chunk size
* Parameter   : str, strlen
* Return      : unsigned int
*-----------------------------------------------------------------------
*/
int HttpGet::get_chunksize_len(char *str,int strLen)
{
	int nLength = 0;
	boost::cmatch matchedStr;
	const char *begin = str;
	const char *end = str + strLen;
	if (boost::regex_search(begin, end, matchedStr, *ChunkRule))
	{
		nLength = matchedStr[0].length();
	}
	else
	{
		nLength = -1;
	}
	return nLength;
}
		
/*
*-----------------------------------------------------------------------
* Func Name   : deal_chunk_data
* Description : deal with the chunk data
* Parameter   : lHash
* Return      : void
*-----------------------------------------------------------------------
*/
void HttpGet::deal_chunk_data(unsigned int lHash)
{
	//char str[16];
	int nLen = 0;
	unsigned int lLength = 0;
	std::map<int,tmpPos>::iterator iter;
	for (iter = mapNd.begin();iter != mapNd.end();++iter)
	{
		if (lHash == iter->second.hash)
		{
			if (iter->second.nChunkedFlag == 1)
			{
				char *pTmp = new char[iter->second.contLen+1];
				iter->second.strBuildData = new char[iter->second.contLen+1];
				memset(iter->second.strBuildData,'\0',iter->second.contLen+1);
				memset(pTmp,'\0',iter->second.contLen+1);
				memcpy(pTmp,iter->second.strData.c_str(),iter->second.contLen);
				char *p = strstr(pTmp,"\r\n");
				if (p == NULL)
				{
					//cout<<"fail to get the first chunk size!"<<endl;
					delete[] pTmp;
					return;
				}
				p += 2;
				//char st[16];
				//memset(st,0,16);
				//memcpy(st,pTmp,p-pTmp);
				//cout<<"st = "<<st<<endl;
				//cout<<"p-pTmp = "<<p-pTmp<<endl;
			
				while (p - pTmp != iter->second.contLen)
				{
					lLength = p - pTmp;
					//cout<<"lLength = "<<lLength<<endl;
					nLen = get_position(p,iter->second.contLen - lLength);
					//cout<<"nLen = "<<nLen<<endl;
					if (nLen < 0)
					{
						break;
					}
					int nLength = get_chunksize_len(p,iter->second.contLen - lLength);
					//cout<<"nlength = "<<nLength<<endl;
					if (nLength < 0)
						break;

					if ((iter->second.lDataSize + nLen) < (iter->second.contLen + 1))
					{
						memcpy(iter->second.strBuildData+iter->second.lDataSize,p,nLen);
						iter->second.lDataSize += nLen;
						p += (nLen + nLength);
					}
					else
						break;
				}
				iter->second.strData.clear();
				iter->second.lContentLen = iter->second.lDataSize;
				delete[] pTmp;
				pTmp = NULL;
				//cout<<"iter->second.lContentLen = "<<iter->second.lContentLen<<endl;
				break;
			}
			else
			{
				iter->second.strBuildData = new char[iter->second.contLen+1];
				memset(iter->second.strBuildData,'\0',iter->second.contLen+1);
				memcpy(iter->second.strBuildData,iter->second.strData.c_str(),iter->second.contLen);
				iter->second.strData.clear();
				iter->second.lContentLen = iter->second.contLen;
				break;
			}
		}
	}
}

/**
* ������: analyse_UserAgent
* ȫ��: HttpGet::analyse_UserAgent
* ��������: ����HTTP��UserAgentͷ���������浽userAgent_
* ���ʿ���: private
* @param: PacketInfo * pPkt
* @return: void
*/
void HttpGet::analyse_UserAgent(PacketInfo* pPkt)
{
    //std::string regstr = "\r\nUser-Agent:\\s(.*?)\r\n";    
    boost::cmatch what;

    const char* begin = pPkt->body;
    const char* end = pPkt->body + pPkt->bodyLen;

    if (boost::regex_search(begin, end, what, *expression_useragent))
    {
        int len = what[1].length();
        len = len < sizeof(userAgent_) ? len : sizeof(userAgent_) - 1;
        memcpy(userAgent_, what[1].first, len);
        userAgent_[len] = '\0';
    }
}

/*
*-----------------------------------------------------------------------
* Func Name   : regex_init
* Description : init regex
* Parameter   : void
* Return      : void
*-----------------------------------------------------------------------
*/
void HttpGet::regex_init()
{
     FiltRule = new boost::regex(FILT);
     ChunkRule = new boost::regex(CHUNKRULE);
     expression_useragent = new boost::regex("\r\nUser-Agent:\\s(.*?)\r\n");
     expression_host = new boost::regex("Host:.*?\\r\\n");
     expression_url = new boost::regex("GET /.*? HTTP/1.");
     expression_html1 = new boost::regex("HTTP/1.(0|1) 200 OK.*?Content-(T|t)ype: text/(html|css|vnd.wap.wml)");
     expression_html2 = new boost::regex("HTTP/1.(0|1) 200 OK.*?Content-(T|t)ype: application/.*?xhtml\\+xml");
     expression_html3 = new boost::regex("HTTP/1.(0|1) 200 OK.*?content=\"text/(html|css|vnd.wap.wml);");
     expression_html_title = new boost::regex("(<TITLE>|<title>).*?(</TITLE>|</title>)");
     expression_css = new boost::regex("\\.CSS");
     expression_css2 = new boost::regex("Referer:.*?\r\n");
     expression_charset = new boost::regex("charset=.*?(\r)?\n");
     expression_charset2 = new boost::regex("[Cc]ontent=(\")?text/html.*?[Cc]harset= ?(.*?)>");
     expression_content_length = new boost::regex("Content-(L|l)ength:.*?\\r?\\n");
     expression_chunk = new boost::regex("Transfer-Encoding: chunked");
     expression_gzip = new boost::regex("Content-Encoding: gzip");
     expression_deflate = new boost::regex("Content-Encoding: deflate");
}

