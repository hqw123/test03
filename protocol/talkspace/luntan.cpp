
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <iconv.h>

#include "luntan.h"
#include "db_data.h"
#include "Analyzer_log.h"

Luntan::Luntan()
{
	luntan_type = 0;
    base_path.assign("/home/spyData/moduleData/luntan/");
    
	baidu_path.assign("/home/spyData/moduleData/luntan/baidu/");
	qiangguo_path.assign("/home/spyData/moduleData/luntan/qiangguo/");
	maopu_path.assign("/home/spyData/moduleData/luntan/maopu/");
	tianya_path.assign("/home/spyData/moduleData/luntan/tianya/");
	kaidi_path.assign("/home/spyData/moduleData/luntan/kaidi/");
	xjmu_path.assign("/home/spyData/moduleData/luntan/xinjiang_medical_university/");
	xjufe_path.assign("/home/spyData/moduleData/luntan/xinjiang_finance_university/");
    xicihutong_path.assign("/home/spyData/moduleData/luntan/xicihutong/");
	init();
}

Luntan::~Luntan()
{
/*
111111111111111111
*/
}

void Luntan::init()
{
	if (::access(base_path.c_str(), F_OK) != 0)
    {
        ::mkdir(base_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}

    if (::access(baidu_path.c_str(), F_OK) != 0)
    {
        ::mkdir(baidu_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(qiangguo_path.c_str(), F_OK) != 0)
    {
        ::mkdir(qiangguo_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(maopu_path.c_str(), F_OK) != 0)
    {
        ::mkdir(maopu_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(tianya_path.c_str(), F_OK) != 0)
    {
        ::mkdir(tianya_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(kaidi_path.c_str(), F_OK) != 0)
    {
        ::mkdir(kaidi_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(xjmu_path.c_str(), F_OK) != 0)
    {
        ::mkdir(xjmu_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if (::access(xjufe_path.c_str(), F_OK) != 0)
    {
        ::mkdir(xjufe_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

    if(::access(xicihutong_path.c_str(), F_OK) != 0)
    {
        ::mkdir(xicihutong_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    }

}

int Luntan::store_file(int type)
{
	int fd = 0;
	int content_len = 0;
	char file_path[256] = {0};
	char name[100] = {0};
	struct timeval tv;
	struct timezone tz;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	
	gettimeofday(&tv, &tz);
	snprintf(name, 100, "content-%lu-%lu", tv.tv_sec, tv.tv_usec);
	snprintf(file_path, 256, "%s%s", get_store_path(type).c_str(), name);
	
	fd = open(file_path, O_RDWR|O_CREAT, file_mode);
	if (fd == -1)
	{
		LOG_ERROR("%s write err!\n", name);
		return -1;
	}
	
    store_path.assign(file_path);
    
	content_len = strlen(content);
	if(content_len > 0)
	{
		write(fd, content, content_len);
	}
	
	close(fd);
	return 0;
}

void Luntan::storedb(int type)
{
	struct in_addr addr;
	FORUM_T tmp_data;
	memset(&tmp_data, 0, sizeof(FORUM_T));
	
	tmp_data.p_data.clueid = objectid;
	tmp_data.p_data.readed = 0;

	addr.s_addr = m_tcp->srcIp;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", m_tcp->srcMac[0]&0xff,
			m_tcp->srcMac[1]&0xff, m_tcp->srcMac[2]&0xff, m_tcp->srcMac[3]&0xff, m_tcp->srcMac[4]&0xff, m_tcp->srcMac[5]&0xff);
	sprintf(tmp_data.p_data.clientPort, "%d", m_tcp->srcPort);
	addr.s_addr = m_tcp->destIp;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", m_tcp->destPort);

    if (title)
    {
	    strncpy(tmp_data.title, title, 199);
    }
    else
    {
        strcpy(tmp_data.title, "");
    }

	if (username)
	{
		strncpy(tmp_data.username, username, 49);
	}
    else
	{
		strcpy(tmp_data.username, "");
	}
	
	strcpy(tmp_data.content_path, store_path.c_str());

	tmp_data.p_data.captureTime = m_tcp->timevalCapture;
	tmp_data.p_data.deleted = 0;
	tmp_data.p_data.proType = type;

	msg_queue_send_data(FORUM, (void *)&tmp_data, sizeof(tmp_data));
}

short Luntan::get_luntan_type()
{
	int type = 0;

	const char* host = m_http->hostUrl;
	
	if(!strcmp(host, "tieba.baidu.com") || !strcmp(host, "c.tieba.baidu.com"))
	{
		type = BAIDU_TIEBA;
	}
	else if(!strcmp(host, "bbs1.people.com.cn"))
    {
		type = QIANGGUO;
	}
	else if(strstr(host, "mop.com"))
    {
		type = MAOPU;
	}
	else if(!strcmp(host, "bbs.tianya.cn") || !strcmp(host, "wireless.tianya.cn"))
    {
		type = TIANYA;
	}
	else if(strstr(host, "kdnet.net"))
    {
		type = KAIDI_COMMUNITY;
	}
	else if(!strcmp(host, "xjmu.myubbs.com"))
    {
		type = XINJIANG_MEDICAL_UNIVERSITY;
	}
	else if(!strcmp(host, "xjufe.myubbs.com"))
    {
		type = XINJIANG_FINANCE_UNIVERSITY;
	}
    else if(!strcmp(host, "www.xici.net"))
    {
        type = XICIHUTONG;
    }

	luntan_type = type;

	return type;
}

std::string Luntan::get_store_path(int type)
{
    switch(type)
    {
        case BAIDU_TIEBA:
            return baidu_path;
            
        case QIANGGUO:
            return qiangguo_path;

        case MAOPU:
            return maopu_path;
            
        case TIANYA:
            return tianya_path;
            
        case KAIDI_COMMUNITY:
            return kaidi_path;
            
        case XINJIANG_MEDICAL_UNIVERSITY:
            return xjmu_path;
            
        case XINJIANG_FINANCE_UNIVERSITY:
            return xjufe_path;

        case XICIHUTONG:
            return xicihutong_path;
    }

    return base_path;
}

void Luntan::decode_gbk(char** decode_content, int len)
{
     iconv_t cp = iconv_open("utf-8", "gbk");
     if (cp == (iconv_t)-1)
     {
        return ;
     }
     
     size_t insize = len * 4;
     size_t outsize = insize * 4;
     
     char* content_bak = new char[outsize];
     if(!content_bak)
     {
        printf("title_bak new fail\n");
        return;
     }
     
     memset(content_bak, 0, outsize);
     char* tmp_in = *decode_content;
     char* tmp_out = content_bak;
     if (iconv(cp, &tmp_in, &insize, &tmp_out, &outsize) == -1)
     {
        return ;
     }
     
     delete[] *decode_content;
     *decode_content = content_bak;
     iconv_close(cp);
     
}

//去除<>xxxx</>这样无用的内容
void Luntan::clear_flag(char** addr, int len)
{
    int i = 0, j = 0;
    char* tmp_addr = new char[len];
    if(!tmp_addr)
    {
        printf("clear_flag malloc fail\n");
        return;
    }
    memset(tmp_addr, 0, len);
    while(i < len)
    {
        //%3C 代表< , %3E 代表>
        if(!strncmp((*addr) + i, "%3C", 3))
        {
            while(strncmp((*addr) + i, "%3E", 3))
            {
                i++;
            }
            i += 3;
        }
        
        tmp_addr[j++] = (*addr)[i++];
    }
    
    delete[] *addr;
    *addr = tmp_addr;
}

int Luntan::getluntan_content_title()
{
	char* data = m_http->http_content;
	int i = 0, j = 0;
	int vector[12] = {0};
	int iResult = -1;
	int  iLen = strlen(data);
    char title_s[200] = {0};
    char* content_s = NULL;
	int title_len = 0, content_len = 0;
	
	if(matchtitle)
	{
		iResult = pcre_exec(matchtitle, NULL, data, iLen, 0, 0, vector, 12);	
		if(iResult < 0)
		{
			 goto next;
		}
		else
		{
			i = vector[1];
			while(i<iLen && j<200 && data[i]!='&')
			{
				title_s[j] = data[i];
				i++;
				j++;
			}

            if(0 == j)
                goto next;
            
			title_len = j;
            title = new char[title_len*4];
            if(title == NULL)
            {
                LOG_ERROR("new title fail.\n");
                return -1;
            }

            memset(title, 0, title_len*4);
            url_decode(title_s, title_len, title, title_len*4);
            
            if(luntan_type == XINJIANG_MEDICAL_UNIVERSITY || luntan_type == XINJIANG_FINANCE_UNIVERSITY || luntan_type == KAIDI_COMMUNITY || luntan_type == XICIHUTONG)
            {
                decode_gbk(&title, title_len);
            }
		}
	}
	else
	{
		LOG_ERROR("matchtitle is NULL.\n");
		return -1;
	}
	
	memset(vector, 0, sizeof(vector));
next:
	if(matchcontent)
	{
		iResult = pcre_exec(matchcontent, NULL, data, iLen, 0, 0, vector, 12);
		if(iResult < 0)
		{
			return -1;
		}
		else
		{
			i = vector[1];
			while(i<iLen && data[i]!='&')
			{
				content_len++;
				i++;
			}

            if(0 == content_len)
                return -1;
            
			i = vector[1];
			content_s = new char[content_len+1];
			if(!content_s)
			{
				LOG_ERROR("new content fail.\n");
				return -1;
			}
			memset(content_s, 0, content_len+1);
			strncpy(content_s, data+i, content_len);
            clear_flag(&content_s, content_len);
            
            content = new char[content_len * 4];
            if(!content)
            {
                LOG_ERROR("content new fail\n");
                return -1;
            }
            memset(content, 0, content_len * 4);
            url_decode(content_s, content_len, content, content_len*4);
            delete[] content_s;
            
            if(luntan_type == XINJIANG_MEDICAL_UNIVERSITY || luntan_type == XINJIANG_FINANCE_UNIVERSITY || luntan_type == KAIDI_COMMUNITY|| luntan_type == XICIHUTONG)
            {
                decode_gbk(&content, content_len);
            }
		}
	}
	else
	{
		LOG_ERROR("matchcontent is NULL.\n");
		return -1;
	}
		
	return 0;
}

int Luntan::getluntan_reply_content()
{
	char* data = m_http->http_content;
	int i = 0;
	int vector[12] = {0};
	int iResult = -1;
	int  iLen = strlen(data);
	int content_len = 0;
    char* content_s = NULL;
    
	if(matchcontent)
	{
		iResult = pcre_exec(matchcontent,NULL,data,iLen,0,0,vector,12);
		if(iResult < 0)
		{
			return -1;
		}
		else
		{
			i = vector[1];
			while(i<iLen && data[i]!='&')
			{
				content_len++;
				i++;
			}
			
			i = vector[1];
			content_s = new char[content_len+1];
			if(!content_s)
			{
				LOG_ERROR("new content fail.\n");
				return -1;
			}
			
			memset(content_s, 0, content_len+1);
			strncpy(content_s, data+i, content_len);
            clear_flag(&content_s, content_len);
            content = new char[content_len * 4];
            if(!content)
            {
                LOG_ERROR("content new fail\n");
                return -1;
            }
            memset(content, 0, content_len * 4);
            url_decode(content_s, content_len, content, content_len*4);
            delete[] content_s;
            
            if(luntan_type == XINJIANG_MEDICAL_UNIVERSITY || luntan_type == XINJIANG_FINANCE_UNIVERSITY || luntan_type == KAIDI_COMMUNITY || luntan_type == XICIHUTONG)
            {
               decode_gbk(&content, content_len); 
            }
            
		}
	}
	else
	{
		LOG_ERROR("matchcontent is NULL.\n");
		return -1;
	}
	
	return 0;
}

int Luntan::getluntan_username()
{
	int i = 0,j = 0;
	char username_s[50] = {0};
	int username_len = 0;
	char* cookie_data = (char*)m_http->cookie; 
	char* addr = NULL;
	
	if(luntan_type == MAOPU)
	{
		addr = strstr(cookie_data, "_mu=");
		if(!addr)
		{
			return -1;
		}
	
		while(!(addr[i]=='%' && addr[i+1]=='7' && addr[i+2]=='C'))
		{
			i++;
		}
		i = i + 3;
	
		while(!(addr[i]=='%' && addr[i+1]=='7' && addr[i+2]=='C') && j < 50)
		{
			username_s[j++] = addr[i++];
		}
	}
	else if(luntan_type == TIANYA)
	{
        addr = strstr(cookie_data, "user=w=");
        if (!addr)
        {
            return -1;
        }

        addr += 7;
        while(addr[i] != '&' && j < 50)
        {
            username_s[j++] = addr[i++];
        }
	}
	else if(luntan_type == KAIDI_COMMUNITY)
	{
		addr = strstr(cookie_data, "username=");
        if (!addr)
        {
            return -1;
        }

		addr += 9;
		while(addr[i]!='&' && j < 50)
		{
			username_s[i] = addr[i];
			i++;
		}
	}
    else if(luntan_type == BAIDU_TIEBA) 
    {
        addr = strstr(m_http->http_content, "client_id=");
        if(!addr)
        {
            return -1;
        }

        addr += strlen("client_id=");
        while(addr[i] != '&' && j < 50)
		{
			username_s[i] = addr[i];
			i++;
		}
    }
	else
	{
		return -1;
	}
	
	username_len = strlen(username_s);
	username = new char[username_len * 4];
	if(!username)
	{
		LOG_ERROR("new username fail.\n");
		return -1;
	}
	
	memset(username, 0, username_len * 4);
	url_decode(username_s, username_len, username, username_len*4);
	return 0;
}

int Luntan::analyse_luntan(common_tcp* tcp, common_http* http, int id)
{
	m_tcp = tcp;
	m_http = http;
	objectid = id;

	short number = get_luntan_type();

	if(!number)
		return -1;

	if(number == BAIDU_TIEBA)
    {
		analyse_baidutieba();
	}
	else if(number == QIANGGUO)
    {
		analyse_qiangguoluntan();
	}
	else if(number == MAOPU)
    {
		analyse_maopu();
	}
	else if(number == TIANYA)
    {
		analyse_tianya();
	}
	else if(number == KAIDI_COMMUNITY)
    {
		analyse_kaidicommunity();
	}
	else if(number == XINJIANG_MEDICAL_UNIVERSITY)
    {
		analyse_Xinjiang_medical_university_luntan();
	}
	else if(number == XINJIANG_FINANCE_UNIVERSITY)
    {
		analyse_Xinjiang_finance_university_luntan();
	}
    else if(number == XICIHUTONG)
    {
        analyse_xicihutong();
    }
	
	return number;
}

int Luntan::analyse_baidutieba()
{
	const char* uri = m_http->reqUri;
	if(!strncmp(uri, "/f/commit/thread/add", 20) || !strncmp(uri, "/c/c/thread/add", 15))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
		
	}
	else if(!strncmp(uri, "/f/commit/post/add", 18) || !strncmp(uri, "/c/c/post/add", 13))
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

    getluntan_username();
    
	store_file(BAIDU_TIEBA);
	storedb(1201);
	date_release();
	return 0;
}

int Luntan::analyse_qiangguoluntan()
{
	const char* uri = m_http->reqUri;
	if (!strncmp(uri,"/postAction.do HTTP",19))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if (!strncmp(uri,"/postAction.do?callback=jQuery",30))
	{
		if (getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else 
	{
		return -1;
	}

	store_file(QIANGGUO);
	storedb(1207);
    date_release();
    
	return 0;
}

int Luntan::analyse_maopu()
{
	const char* uri = m_http->reqUri;
    
	if(!strncmp(uri, "/ajax/subject/add HTTP", 22) || !strncmp(uri, "/dzh/subject/", 13) ||
        !strncmp(uri, "/subject/save/ajax HTTP", 23) )
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if(!strncmp(uri, "/ajax/reply/quick HTTP",22) || strstr(uri, "/saveReply.json?") || \
    !strncmp(uri, "/ajax/reply/innerreply HTTP", 27) || strstr(uri, "saveSubReply.json?") || \
    !strncmp(uri, "/reply/add/ajax HTTP", 20) || !strncmp(uri, "/dzh/reply/", 10)) 
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else 
	{
		return -1;
	}

	getluntan_username();

    store_file(MAOPU);
	storedb(1202);
    date_release();
    
	return 0;
}

int Luntan::analyse_tianya()
{
	const char* uri = m_http->reqUri;
    
	if(!strncmp(uri, "/api?method=bbs.ice.compose HTTP", 32) || !strncmp(uri, "/v/forumStand/compose HTTP", 26))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if(!strncmp(uri, "/api?method=bbs.ice.reply HTTP", 30) || !strncmp(uri, "/v/forumStand/reply HTTP", 24) ||
            !strncmp(uri, "/api HTTP", 9) || !strncmp(uri, "/v/forumStand/comment HTTP", 26))
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
	
	getluntan_username();

    store_file(TIANYA);
	storedb(1203);
    date_release();
    
	return 0;
}

int Luntan::analyse_kaidicommunity()
{
	const char* uri = m_http->reqUri;
	if(!strncmp(uri, "/SavePost_ubb.asp?Action=snew", 29) || !strncmp(uri, "/api/topic/topic-posts.json HTTP", 32))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if(!strncmp(uri, "/do_lu_shuiyin.asp?action=sre&method=fastreply", 46) || !strncmp(uri, "/api/topic/topic-reply.json HTTP", 32))
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	getluntan_username();

    store_file(KAIDI_COMMUNITY);
	storedb(1204);
    date_release();
    
	return 0;
}

int Luntan::analyse_Xinjiang_medical_university_luntan()
{
	const char* uri = m_http->reqUri;
	if(!strncmp(uri, "/forum.php?mod=post&action=newthread", 36))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if(!strncmp(uri, "/forum.php?mod=post&action=reply", 32))
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
	
	store_file(XINJIANG_MEDICAL_UNIVERSITY);
	storedb(1205);
    date_release();
    
	return 0;
}

int Luntan::analyse_Xinjiang_finance_university_luntan()
{
	const char* uri = m_http->reqUri;
    
	if(!strncmp(uri, "/forum.php?mod=post&action=newthread", 36))
	{
		if(getluntan_content_title() < 0)
		{
			return -1;
		}
	}
	else if(!strncmp(uri, "/forum.php?mod=post&action=reply", 32))
	{
		if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	store_file(XINJIANG_FINANCE_UNIVERSITY);
	storedb(1206);
    date_release();
    
	return 0;
}

int Luntan::analyse_xicihutong()
{
    const char* uri = m_http->reqUri;

    if(strstr(uri, "put.asp HTTP") && strstr(m_http->http_content, "doc_title="))
    {
        if(getluntan_content_title() < 0)
		{
			return -1;
		}
    }
    else if(strstr(uri, "put.asp HTTP") && !strstr(m_http->http_content, "doc_title="))
    {
        if(getluntan_reply_content() < 0)
		{
			return -1;
		}
	}
    else
    {
        return -1;
    }
	
    store_file(XICIHUTONG);
    storedb(1208);
    date_release();
	
    return 0;
}

