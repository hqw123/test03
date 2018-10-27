
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "kaixin.h"
#include "db_data.h"
#include "Analyzer_log.h"

Kaixin::Kaixin()
{
	memset(userid, 0, 20);
	memset(passive_userid, 0, 20);
	memset(post_id, 0, 20);
    
    base_path.assign("/home/spyData/moduleData/kaixin/");
    
	if (::access(base_path.c_str(), F_OK) != 0)
    {
        ::mkdir(base_path.c_str(), S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}
    
	match_passive_userid = pcre_compile(PASSIVE_USERID, PCRE_CASELESS, &chpError, &iErro, NULL);
}

Kaixin::~Kaixin()
{
	pcre_free(match_passive_userid);
}

void Kaixin::storedb()
{
	struct in_addr addr;
	SOCIAL_NETWORK_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = objectid;
	tmp_data.p_data.readed = 0;

	addr.s_addr = m_tcp->srcIp;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", m_tcp->srcMac[0]&0xff, m_tcp->srcMac[1]&0xff, 
            m_tcp->srcMac[2]&0xff, m_tcp->srcMac[3]&0xff, m_tcp->srcMac[4]&0xff, m_tcp->srcMac[5]&0xff);
	sprintf(tmp_data.p_data.clientPort, "%d", m_tcp->srcPort);
	addr.s_addr = m_tcp->destIp;
	strcpy(tmp_data.p_data.serverIp,inet_ntoa(addr));
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
	
	strncpy(tmp_data.userid, userid, 19);
    strncpy(tmp_data.articleid, post_id, 19);
	strncpy(tmp_data.content_path, store_path.c_str(), 255);

    tmp_data.p_data.captureTime = m_tcp->timevalCapture;
    tmp_data.p_data.proType = 1401;
    tmp_data.p_data.deleted = 0;
    
	msg_queue_send_data(SOCIAL_NETWORK, (void *)&tmp_data, sizeof(tmp_data));
}

void Kaixin::storemsgdb()
{
	struct in_addr addr;
	IMINFO_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = objectid;
	tmp_data.p_data.readed = 0;
	addr.s_addr = m_tcp->srcIp;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", m_tcp->srcMac[0]&0xff,
			m_tcp->srcMac[1]&0xff, m_tcp->srcMac[2]&0xff, m_tcp->srcMac[3]&0xff,m_tcp->srcMac[4]&0xff, m_tcp->srcMac[5]&0xff);
	
	sprintf(tmp_data.p_data.clientPort, "%d", m_tcp->srcPort);
	addr.s_addr = m_tcp->destIp;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", m_tcp->destPort);
	tmp_data.p_data.captureTime = m_tcp->timevalCapture;
	tmp_data.optype = 3;
    
	if (content)
	{
	    strncpy(tmp_data.content, content, 499);   
	}
	else
	{
		strcpy(tmp_data.content, "");
	}

	strncpy(tmp_data.sendNum, userid, 20);
	strncpy(tmp_data.recvNum, passive_userid, 20);
	
	tmp_data.p_data.proType = 524;
	tmp_data.p_data.deleted = 0;
	
	msg_queue_send_data(IMINFO, (void *)&tmp_data, sizeof(tmp_data));
}

void Kaixin::store_user_pass()
{
    /*write webaccount data to shared memory, by zhangzm*/
    struct in_addr addr;
    WEBACCOUNT_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));
    
	tmp_data.p_data.clueid = objectid;
	tmp_data.p_data.readed = 0;
	addr.s_addr = m_tcp->srcIp;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", m_tcp->srcMac[0]&0xff,
			m_tcp->srcMac[1]&0xff, m_tcp->srcMac[2]&0xff, m_tcp->srcMac[3]&0xff,m_tcp->srcMac[4]&0xff, m_tcp->srcMac[5]&0xff);
	
	sprintf(tmp_data.p_data.clientPort, "%d", m_tcp->srcPort);
	addr.s_addr = m_tcp->destIp;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", m_tcp->destPort);
    
    tmp_data.p_data.captureTime = m_tcp->timevalCapture;
    strcpy(tmp_data.url, "www.kaixin001.com");

    if (username)
        strncpy(tmp_data.username, username, 63);
    else
        strcpy(tmp_data.username, "");

    if (password)
        strncpy(tmp_data.password, password, 63);
    else
        strcpy(tmp_data.password, "");
    
    tmp_data.p_data.proType = 201;
    tmp_data.p_data.deleted = 0;
    
    msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

int Kaixin::store_file(char* type)
{
	int fd = 0;
	int content_len = 0;
	char file_path[256] = {0};
	char name[100] = {0};
	struct timeval tv;
	struct timezone tz;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	
	gettimeofday(&tv, &tz);
	
	snprintf(name, 100, "%s-%lu-%lu", type, tv.tv_sec, tv.tv_usec);
	snprintf(file_path, 256, "%s%s", base_path.c_str(), name);
	
	fd = open(file_path, O_RDWR|O_CREAT, file_mode);
	if (fd == -1)
	{
		LOG_ERROR("open file fail!\n");
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

int Kaixin::analyse_kaixin(common_tcp* tcp, common_http* http, int id)
{
	m_tcp = tcp;
	m_http = http;
	objectid = id;
	
	const char* uri = m_http->reqUri;
	if (!strncmp(uri, "/interface/statLog2.php HTTP", 28))
    {
		get_login();
	}
	else if (!strncmp(uri, "/records/ajax/submit.php HTTP", 29))
    {
		get_record();
	}
	else if (!strncmp(uri, "/diary/write_submit.php HTTP", 28))
    {
		get_diary();
	}
	else if (!strncmp(uri, "/comment/post.php HTTP", 22))
    {
		get_comment();
	}
	else if (!strncmp(uri, "/chat/send.php HTTP", 19))
    {
		get_chat();
	}
	else if (!strncmp(uri, "/msg/post.php HTTP", 18))
    {
		get_instation_postmessage();
	}
	else if (!strncmp(uri, "/msg/reply.php HTTP", 19))
    {
		get_instation_replymessage();
	}
	else if(!strncmp(uri, "/oauth/access_token HTTP", 24))
    {
        client_get_login();
    }
	else if(!strncmp(uri, "/mobile/agent.json HTTP", 23) && strstr(http->http_content, " name=\"privacy\""))
    {
        client_get_record();
    }
	else
    {
		return -1;
	}
	
	return 0;
}

/*********************************************************************************************
Describe: deal PC client data
*********************************************************************************************/
int Kaixin::get_content()
{
	char* data = m_http->http_content;
	int i = 0;
	int vector[12] = {0};
	int iResult = -1;
	int iLen = strlen(data);
	int content_len = 0;
    char* content_s = NULL;
	
	if (matchcontent)
	{
		iResult = pcre_exec(matchcontent, NULL, data, iLen, 0, 0, vector, 12);
		if(iResult < 0)
		{
			LOG_INFO("exec content fail.\n");
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
			content_s = new char[content_len + 1];
			if (!content_s)
			{
				LOG_ERROR("new content_s fail.\n");
				return -1;
			}
			
			memset(content_s, 0, content_len + 1);
			strncpy(content_s, data+i, content_len);
            content = new char[content_len*4];
	        if(content == NULL)
            {
                LOG_ERROR("new content fail.\n");
		        return -1;
	        }
			
	        memset(content, 0, content_len*4);
	        url_decode(content_s, content_len, content, content_len*4);
            delete[] content_s;
      	}
	}
	else
	{
		LOG_ERROR("matchcontent is NULL.\n");
		return -1;
	}
	
	return 0;
}

int Kaixin::get_title()
{
	char* data = m_http->http_content;
	int i = 0, j = 0;
	int vector[12] = {0};
	int iResult = -1;
	int  iLen = strlen(data);
	char title_s[200] = {0};
	int title_len = 0;
	
	if (matchtitle)
	{
		iResult = pcre_exec(matchtitle, NULL, data, iLen, 0, 0, vector, 12);
		if (iResult < 0)
		{
			LOG_INFO("exec title fail.\n");
			return -1;
		}
		else
		{
			i = vector[1];
			while (i<iLen && j<200 && data[i]!='&')
			{
				title_s[j] = data[i];
				i++;
				j++;
			}
			
			title_len = j;
		}
	}
	else
	{
		LOG_ERROR("matchtitle is NULL.\n");
		return -1;
	}

	title = new char[title_len*4];
	if(title == NULL)
	{
		LOG_ERROR("new title fail.\n");
		return -1;
	}
	
	memset(title, 0, title_len*4);
	url_decode(title_s, title_len, title, title_len*4);
    
	return 0;
}

int Kaixin::get_username()
{
	int i = 0;
	char username_s[50] = {0};
	int username_len = 0;
	char* cookie_data = (char*)m_http->cookie;
	char* addr = NULL;
    
	addr = strstr(cookie_data, "preemail=");
	if(!addr)
	{
		//LOG_INFO("can not find kaixin username.\n");
		return -1;
	}
	
	addr += 9;
	while(addr[i]!=';' && i < 50)
	{
		username_s[i] = addr[i];
		i++;
	}
	username_s[i] = '\0';
	username_len = strlen(username_s);
	username = new char[username_len*4];
	if(!username)
	{
		LOG_ERROR("username new fail.\n");
		return -1;
	}
	
	memset(username, 0, username_len*4);
	url_decode(username_s, username_len, username, username_len*4);
   
	return 0;
}

int Kaixin::get_userid()
{
	int i = 0;
	char* cookie_data = (char*)m_http->cookie; 
	char* addr = NULL;

    memset(userid, 0, 20);
    
	addr = strstr(cookie_data, "_uid=");
	if(!addr)
	{
		//LOG_INFO("can not find kaixin userid.\n");
		return -1;
	}

	addr += 5;
	while (addr[i] != ';' && i < 20)
	{
		userid[i] = addr[i];
		i++;
	}
	
	return 0;
}

int Kaixin::get_postid()
{
	int i = 0;
	char* data = m_http->http_content;

    memset(post_id, 0, 20);
    
	char* addr = strstr(data, "id=");
	addr += 3;
	while(addr[i]!='&' && i<20)
	{
		post_id[i] = addr[i];
		i++;
	}
    
	return 0;
}

int Kaixin::get_passive_userid()
{
	char* data = m_http->http_content;
	int i = 0, j = 0;
	int vector[12] = {0};
	int iResult = -1;
	int  iLen = strlen(data);

    memset(passive_userid, 0, 20);
	
	if(match_passive_userid)
	{
		iResult = pcre_exec(match_passive_userid, NULL, data, iLen, 0, 0, vector, 12);	
		if(iResult < 0)
		{
			//LOG_INFO("exec passive_postid fail\n");
			return -1;
		}
		else
		{
			i = vector[1];
			while(i<iLen &&j<20 && data[i]!='&')
			{
				passive_userid[j] = data[i];
				i++;
				j++;
			}
			
		}
	}
	else
	{
		LOG_ERROR("match_passive_userid is NULL.\n");
		return -1;
	}
}

int Kaixin::get_login()
{
	if(strstr(m_http->http_content, "login"))
	{
		if (get_username() < 0)
            return -1;
        
		get_userid();
        date_release();
	}
	
	return 0;
}

int Kaixin::get_record()
{
	char* addr = strstr(m_http->http_content, "rcode=");
	if(addr && addr[6] != '&')
	{
        if (get_content() < 0)
            return -1;
    
		get_username();
		get_userid();
        
		store_file("record");
		storedb();
        date_release();
	}
	
	return 0;
}

int Kaixin::get_diary()
{
    if (get_content() < 0)
        return -1;

	get_username();
	get_userid();
	get_title();
    
	store_file("diary");
	storedb();
    date_release();
    
	return 0;
}

int Kaixin::get_comment()
{
    if (get_content() < 0)
        return -1;

	get_username();
	get_userid();
	get_title();
	get_postid();
    
	store_file("comment");
	storedb();
    date_release();
    
	return 0;
}

int Kaixin::get_chat()
{
    if (get_content() < 0)
        return -1;

	get_username();
	get_userid();
	get_passive_userid();
    
	storemsgdb();
    date_release();
    
	return 0;
}

int Kaixin::get_instation_postmessage()
{
    if (get_content() < 0)
        return -1;

	get_username();
	get_userid();
	get_passive_userid();
    
	storemsgdb();
    date_release();
    
	return 0;
}

int Kaixin::get_instation_replymessage()
{
    if (get_content() < 0)
        return -1;

	get_username();
	get_userid();
    
	storemsgdb();
    date_release();
    
	return 0;
}

/*********************************************************************************************
Describe: deal phone client data
*********************************************************************************************/
int Kaixin::client_get_username()
{
    char* data = m_http->http_content;
    int i = 0;
    char username_s[50] = {0};
    char* addr = strstr(data, "auth_username");
    if(!addr) 
    {
        //LOG_INFO("can not find cli_kaixin username.\n");
        return -1;
    }
    
    addr = addr + strlen("auth_username") + 4;
    while(addr[i] != '\r' && i < 50)
    {
        username_s[i] = addr[i];
        i++;
    }
    
    username = new char[i*2];
    if(!username)
	{
        LOG_ERROR("new username fail.\n");
		return -1;
	}
	memset(username, 0, i*2);
	url_decode(username_s, i, username, i*2);
    
    return 0;
}

int Kaixin::client_get_password()
{
    char* data = m_http->http_content;
    int i = 0;

    char* addr = strstr(data, "auth_password");
    if(!addr)
    {
          //LOG_INFO("can not find cli_kaixin password.\n");
          return -1;
    }

    addr = addr + strlen("auth_password") + 4;
    while(addr[i++] != '\r');

    password = new char[i];
    memset(password, 0, i);
    strncpy(password, addr, i);

    return 0;
}

int Kaixin::client_get_content()
{
    char* data = m_http->http_content;
    int i = 0;

    char* addr = strstr(data, "content");
    if(!addr)
    {
        //LOG_INFO("can not find client_kaixin content.\n");
        return -1;
    }

    addr = addr + strlen("content") + 5;
    while(addr[i++] != '\r');

    content = new char[i];
    memset(content, 0, i);
    strncpy(content, addr, i);

    return 0;
}

int Kaixin::client_get_userid()
{
    int i = 0;
    char* data = m_http->http_content;

    memset(userid, 0, 20);

    char* addr = strstr(data, "uid");
    if(!addr)
    {
        //LOG_INFO("can not find client_kaixin userid.\n");
        return -1;
    }

    addr = addr + strlen("uid") + 5;
    while(addr[i] != '\r' && i < 20)
    {
        userid[i] = addr[i];
        i++;
    }

    return 0;
}

int Kaixin::client_get_login()
{
    if (client_get_username() < 0)
        return -1;
    
    if (client_get_password() < 0)
        return -1;
    
    store_user_pass();
    date_release();
    
    return 0;
}

int Kaixin::client_get_record()
{
    if (client_get_content() < 0)
        return -1;
    
    client_get_userid();
    store_file("record");
    storedb();
    date_release();
    
    return 0;
}


