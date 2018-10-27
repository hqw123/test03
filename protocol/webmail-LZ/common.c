
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/socket.h>
#include <openssl/evp.h>

#include "common.h"
#include "global.h"
#include "ofo_cope.h"
#include "clue_c.h"
#include "db_data.h"

#define MAXDATASIZE 256

char mail_data_path[MAX_PATH_LEN + 1];
char mail_temp_path[MAX_PATH_LEN + 1];
char attach_down_path[MAX_PATH_LEN + 1];
char mail_password_path[MAX_PATH_LEN + 1];

extern int str_to_num(char * size);
extern int ControlC302;
extern char C302ServerIp[MAX_LENGTH];
extern int C302Serverport;

MailTable mail_tab;
AttachTable attach_tab;

Tmpfrom fromarray[5];

typedef struct _tagGmailNode
{
	char gmailUserName[MAX_UN_LEN + 1];
	char gmailPassWord[MAX_UN_LEN + 1];
}GMAILNODE;

void makeStr(char * str)
{
	char * i = str, * j = str;
	while(*i && *j)
	{
		if(*i != '\'')
		{
			*j = *i;
			j++;
		}
		
		i++;
	}
	
	*j = '\0';
}

void CpyStr(char dest[], char * sorc)
{
	int i = 0;
	while(*sorc)
	{
		dest[i++] = *sorc;
		sorc++;
	}
	dest[i] = '\0';
}

void DbgShow(char buf[],char file[])
{
	if(strlen(buf)==0)
		return;
	if(buf==NULL)
		return;

	char path[]="//workflord//sjs//node//webmail//res//";
	strcat(path,file);
	FILE * fp;
	fp=fopen(path,"wt");
	if(fp==NULL)
	{
		LOG_ERROR("Cann't Open the file:%s\n",file);
		return;
	}
	char * buff=(char *)malloc(strlen(buf)+1);
	strcpy(buff,buf);
	buff[strlen(buf)]='\0';
	fputs(buff,fp);
	fclose(fp);
	free(buff);
	buff = NULL;
}

int delete_mail_info(Mail_info *mail_info)
{
	//printf("delete mail_info ... \n");
	
	if(!mail_info)
		return -1;
	
	Attachment *tmp1 = mail_info->attach;
	Attachment *tmp2 = NULL;

	mail_info->prev->next = mail_info->next;
    if(mail_info->next != NULL)
		mail_info->next->prev = mail_info->prev;
	
	if(mail_info->mail_data)
	{
		free(mail_info->mail_data);
		mail_info->mail_data = NULL;
	}
	if(mail_info->recive_data)
	{
		free(mail_info->recive_data);
		mail_info->recive_data = NULL;
	}
	if(mail_info->content)
	{
		free(mail_info->content);
		mail_info->content = NULL;
	}
	if(mail_info->mail_id)
	{
		free(mail_info->mail_id);
		mail_info->mail_id = NULL;
	}
	if(mail_info->body)
	{
		free(mail_info->body);
		mail_info->body=NULL;
	}
	if(mail_info->header)
	{
		free(mail_info->header);
		mail_info->header=NULL;
	}

	while (tmp1) {
		tmp2 = tmp1;
		tmp1 = tmp1->next;
		tmp2->next = NULL;
		free(tmp2);
	}
	free(mail_info);
	mail_info = NULL;
	mail_tab.count--;

	//printf("delete mail_info complete ... \n");
}

int add_count()
{
	 //fprintf(stderr, "\n enter     add_count     enter  \n");
	 Mail_info * pPearent = mail_tab.head;
	 Mail_info * mail_info = mail_tab.head->next;

	 while (mail_info) 
	 {
		 mail_info->count++;
		 if(mail_info->count == 10)
		 {
			 delete_mail_info(mail_info);
			 mail_info = pPearent->next;
		 }
		 else
		 {
			 pPearent = mail_info;
			 mail_info = mail_info->next;
		 }
	 }
}

int add_count_yu()
{
      Mail_info *mail_info = mail_tab.head->next;
      Mail_info *mail_next = NULL;
      while(mail_info)
      {
           mail_info->count++;
           mail_next = mail_info->next;
           if(mail_info->count == 10)
           {
                 delete_mail_info(mail_info);
           }
           mail_info = mail_next;
      }
}

int del_mail_node(Mail_info *temp)
{
	//printf("del_mail_node ...\n");
	if(!temp)
		return 0;
	
	int i;
	Attachment *attachment = NULL;

	if (temp->next != NULL)
	{
		temp->prev->next = temp->next;
		temp->next->prev = temp->prev;
	}
	else
	{
		temp->prev->next = NULL;
	}

	if(temp->mail_data)
	{
		free(temp->mail_data);
		temp->mail_data = NULL;
	}
	if(temp->recive_data)
	{
		free(temp->recive_data);
		temp->recive_data = NULL;
	}
	if(temp->content)
	{
		free(temp->content);
		temp->content = NULL;
	}
	if(temp->mail_id)
	{
		free(temp->mail_id);
		temp->mail_id = NULL;
	}
	if(temp->body) 
	{
		free(temp->body);
		temp->body=NULL;
	}
	if(temp->header)
	{
		free(temp->header);
		temp->header=NULL;
	}
	i = temp->num_of_attach;
	while (i > 0) {
		attachment = temp->attach;
		temp->attach = attachment->next;
		attachment->next = NULL;
		if(attachment)
			free(attachment);
		i--;
	}

	free(temp);
	temp = NULL;
	mail_tab.count--;
	add_count();
	//printf("del_mail_node complete ...\n");
}

int del_attach_node(Attach_info *temp)
{
	//printf("del_attach_node ...\n");
	if (temp->next == NULL) 
	{
		attach_tab.tail=temp->prev;
		temp->prev->next = NULL;
	} 
	else 
	{
		temp->prev->next = temp->next;
		temp->next->prev = temp->prev;
	}
	attach_tab.count--;
	//printf("del_attach_node complete ...\n");
}
int judge_chunk_1(char *data)
{
       int is_chunk = 0;
    if (memfind(data, "\r\nTransfer-Encoding: chunked\r\n",591)!= NULL)
        is_chunk = 1;
    else
        is_chunk = 0;
     return is_chunk;
                 
}
int judge_chunk(char *data)
{
    int is_chunk = 0;
    if (strstr(data, "\r\nTransfer-Encoding: chunked\r\n")!= NULL)
        is_chunk = 1;
    else
        is_chunk = 0;
     return is_chunk;
      
}

int get_http_length_2(char *data, int *is_chunk)
{
	int length = 0;
	//int is_chunk = 0;
	char *p1=data;
	char *p2=NULL;
	if (p1 == NULL) return 0;
	p2=strstr(p1,"\r\n\r\n");
	if (p2==NULL) return 0;
	unsigned int n=p2-p1;

	if (memfind(data, "\r\nTransfer-Encoding: chunked\r\n",n) != NULL) {
		*is_chunk = 1;
	} else {
		*is_chunk = 0;
	}

	if (*is_chunk) {
		char *p = strstr(data, "\r\n\r\n");
		p += 4;
		while (*p != '\r') {
			if ('0' <= *p && '9' >= *p)
				length = length * 16 + (*p - '0');
			else if ('a' <= *p && 'f' >= *p)
				length = length * 16 + (*p - 'a' + 10);
			else if ('A' <= *p && 'F' >= *p)
				length = length * 16 + (*p - 'A' + 10);
			else
				break;
			p++;
		}
	} else {
		char *p = strstr(data, "\r\nContent-Length:");

		if (p == NULL)
			return 0;
		p += 17;
		while( *p != '\r') {
			if(*p != ' ')
				length = length * 10 + (*p - '0');
			p++;
		}
	}

	if (length < 0)
		length = -1;
	return length;
}

int get_http_length_1(char *data)
{
	int length = 0;
	int is_chunk = 0;

	if (memfind(data, "\r\nTransfer-Encoding: chunked\r\n",591) != NULL) {
		is_chunk = 1;
	} else {
		is_chunk = 0;
	}

	if (is_chunk) {
		char *p = strstr(data, "\r\n\r\n");
		p += 4;
		while (*p != '\r') {
			if ('0' <= *p && '9' >= *p)
				length = length * 16 + (*p - '0');
			else if ('a' <= *p && 'f' >= *p)
				length = length * 16 + (*p - 'a' + 10);
			else if ('A' <= *p && 'F' >= *p)
				length = length * 16 + (*p - 'A' + 10);
			else
				break;
			p++;
		}
	} else {
		char *p = strstr(data, "\r\nContent-Length: ");

		if (p == NULL)
			return 0;
		p += 18;
		while( *p != '\r') {
			length = length * 10 + (*p - '0');
			p++;
		}
	}

	if (length < 0)
		length = -1;
	return length;
}

int get_http_length(char *data)
{
	int length = 0;
	int is_chunk = 0;

	if (strstr(data, "\r\nTransfer-Encoding: chunked\r\n") != NULL) {
		is_chunk = 1;
	} else {
		is_chunk = 0;
	}

	if (is_chunk) {
		char *p = strstr(data, "\r\n\r\n");
		p += 4;
		while (*p != '\r') {
			if ('0' <= *p && '9' >= *p)
				length = length * 16 + (*p - '0');
			else if ('a' <= *p && 'f' >= *p)
				length = length * 16 + (*p - 'a' + 10);
			else if ('A' <= *p && 'F' >= *p)
				length = length * 16 + (*p - 'A' + 10);
			else
				break;
			p++;
		}
	} else {
		char *p = strstr(data, "\r\nContent-Length:");

		if (p == NULL)
			return 0;
		p += 17;
		while( *p != '\r') {
			if(*p != ' ')
				length = length * 10 + (*p - '0');
			p++;
		}
	}

	if (length < 0)
		length = -1;
		
	return length;
}

int clear_from(char *old_from)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;

	if (old_from == NULL)
		return -1;

	pstart = strstr(old_from, "<");
	if (pstart != NULL) {
		pstart++;
		pend = strstr(pstart, ">");
	} else {
		pstart = strstr(old_from, "&lt;");
		if (pstart != NULL) {
			pstart += 4;
			pend = strstr(pstart, "&gt;");
		}
	}
	
	if (pend == NULL)
		return 0;
	len = pend - pstart;
	if (len == 0)
		return 0;
	memmove(old_from, pstart, len);
	old_from[len] = 0;

	return 0;
}

int write_to_okdata(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	unsigned int seq;
	int off_seq;
	int len;
	char *tmp = NULL, *tmp1 = NULL;

	if (mail_info == NULL || data == NULL || ptcp == NULL || data_len >= 65535)
		return -1;

	seq = ntohl(ptcp->seq);
	if (mail_info->recive_length == 0)
	{
		mail_info->recive_length = 5000;
		mail_info->recive_data = (char *)malloc(5001);
		if (mail_info->recive_data == NULL) 
		{
			LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
			return -1;
		}
		memset(mail_info->recive_data, 0, 5001);
		mail_info->http_seq = seq;
	}
	
	if (mail_info->recive_length == 5000) 
	{
		off_seq = seq - mail_info->http_seq;
		if (off_seq < 0) 
		{
			data -= off_seq;
			data_len += off_seq;
			if (data_len < 1)
			{
				return 0;
			}
			off_seq = 0;
		}
		if (off_seq + data_len > mail_info->recive_length)
		{
			LOG_WARN("webmail:write_to_okdata: message too long!!!\n");
			return -1;
		}
		memcpy(mail_info->recive_data + off_seq, data, data_len);

		tmp = strstr(mail_info->recive_data, "\r\n\r\n");
		if (tmp != NULL)
		{
			tmp += 4;
			mail_info->http_seq = tmp - mail_info->recive_data + mail_info->http_seq;
			tmp1 = strstr(mail_info->recive_data, "Transfer-Encoding: chunked\r\n");
			if (tmp1 != NULL && tmp1 < tmp)
			{
				mail_info->recive_length = DEFAULT_OK_LEN;
				mail_info->is_ok_chunked = 1;
			} 
			else
			{
				mail_info->is_ok_chunked = 0;
				len = get_http_length(mail_info->recive_data);
				if (len == -1)
				{
					LOG_WARN("webmail:write_to_okdata: get_http_length() error!\n");
					return -1;
				}
				if (len == 0)
				{
					len = DEFAULT_OK_LEN;
				}
				mail_info->recive_length = len;
			}
			
			tmp1 = (char *)malloc(mail_info->recive_length + MTU + 1);
			if (tmp1 == NULL)
			{
				LOG_WARN("webmail:write_to_okdata: malloc()2 failed!\n");
				return -1;
			}
			
			memset(tmp1, 0, mail_info->recive_length + MTU + 1);
			len = 5000 - (tmp - mail_info->recive_data);
			if (len > mail_info->recive_length)
			{
				len = mail_info->recive_length;
			}
			memcpy(tmp1, tmp, len);
			free(mail_info->recive_data);
			mail_info->recive_data = tmp1;
			tmp1 = NULL;
		}
		
		return 0;
	}
	off_seq = seq - mail_info->http_seq;
	if (off_seq < 0) 
	{
		data -= off_seq;
		data_len += off_seq;
		if (data_len < 1)
		{
			return 0;
		}
		off_seq = 0;
	}
	if (off_seq + data_len > mail_info->recive_length)
	{
		//fprintf(stderr, "webmail:write_to_okdata: message too long!\n");
		return -1;
	}
	memcpy(mail_info->recive_data + off_seq, data, data_len);

	return 0;
}

int write_to_okdata_2(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	unsigned int seq;
	int off_seq;
	int len;
	char *tmp = NULL, *tmp1 = NULL;

	if (mail_info == NULL || data == NULL || ptcp == NULL || data_len >= 65535)
		return -1;

	seq = ntohl(ptcp->seq);
	if (mail_info->recive_length == 0)
	{
		mail_info->recive_length = 5000;
		mail_info->recive_data = (char *)malloc(5001);
		if (mail_info->recive_data == NULL) 
		{
			LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
			return -1;
		}
		memset(mail_info->recive_data, 0, 5001);
		mail_info->http_seq = seq;
	}
	if (mail_info->recive_length == 5000) 
	{
		off_seq = seq - mail_info->http_seq;
		if (off_seq < 0) 
		{
			data -= off_seq;
			data_len += off_seq;
			if (data_len < 1)
			{
				return 0;
			}
			off_seq = 0;
		}//printf("off_seq = %d,data_len = %d,mail_info->recive_length = %d",off_seq,data_len,mail_info->recive_length);
		if (off_seq + data_len > mail_info->recive_length)
		{
			LOG_WARN("webmail:write_to_okdata: message too long!!!\n");
			return -1;
		}
		memcpy(mail_info->recive_data + off_seq, data, data_len);

		tmp = strstr(mail_info->recive_data, "\r\n\r\n");
		if (tmp != NULL)
		{
			tmp += 4;
			mail_info->http_seq = tmp - mail_info->recive_data + mail_info->http_seq;
			tmp1 = strstr(mail_info->recive_data, "Transfer-Encoding: chunked\r\n");
			if (tmp1 != NULL && tmp1 < tmp)
			{
				mail_info->recive_length = DEFAULT_OK_LEN;
				mail_info->is_ok_chunked = 1;
			} 
			else
			{
				mail_info->is_ok_chunked = 0;
				len = get_http_length(mail_info->recive_data);
				if (len == -1)
				{
					LOG_WARN("webmail:write_to_okdata: get_http_length() error!\n");
					return -1;
				}
				if (len == 0)
				{
					len = DEFAULT_OK_LEN;
				}
				mail_info->recive_length += len;
			}
			tmp1 = (char *)malloc(mail_info->recive_length + MTU + 1);
			if (tmp1 == NULL)
			{
				LOG_WARN("webmail:write_to_okdata: malloc()2 failed!\n");
				return -1;
			}
			memset(tmp1, 0, mail_info->recive_length + MTU + 1);
			len = 5000 - (tmp - mail_info->recive_data);
			if (len > mail_info->recive_length)
			{
				len = mail_info->recive_length;
			}
			memcpy(tmp1, tmp, len);
			free(mail_info->recive_data);
			mail_info->recive_data = tmp1;
			tmp1 = NULL;
		}
		return 0;
	}
	off_seq = seq - mail_info->http_seq;
	if (off_seq < 0) 
	{
		data -= off_seq;
		data_len += off_seq;
		if (data_len < 1)
		{
			return 0;
		}
		off_seq = 0;
	}
	if (off_seq + data_len > mail_info->recive_length)
	{
		//fprintf(stderr, "webmail:write_to_okdata: message too long!\n");
		return -1;
	}
	memcpy(mail_info->recive_data + off_seq, data, data_len);

	return 0;
}

int write_to_okdata_chunked_gzip(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		mail_info->recive_length = 0;
		mail_info->recive_data = (char *)malloc(1024 * 1024);
		if (mail_info->recive_data == NULL)
		{
			//fprintf(stderr, "webmail:write_to_okdata: malloc()1 failed!\n");
			return -1;
		}
		memset(mail_info->recive_data, 0, 1024 * 1024);
		memcpy(mail_info->recive_data + mail_info->recive_length, data, data_len);
		mail_info->recive_length += data_len;
	}
	else
	{
        if ((mail_info->recive_length + data_len) > 1024 * 1024 || NULL == mail_info->recive_data)
            return -1;
    
		memcpy(mail_info->recive_data + mail_info->recive_length, data, data_len);
		mail_info->recive_length += data_len;
	}

	return 0;
}

int Chunked(Mail_info * mail_info)
{
	char * i = NULL, * j = NULL, size_str[16], * head = NULL;
	int len, chunked_size, dest_size = 0;
	char * dest = (char *)malloc(1024 * 1024);
	if (dest == NULL)
	{
		LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
		return 0;
	}
	memset(dest, 0, 1024 * 1024);
	i = strstr(mail_info->recive_data, "Transfer-Encoding: chunked\r\n");//printf("i = %s\n",i);

	if(i == NULL)
		return 0;
	i += 26;
	i = strstr(i,"\r\n\r\n");
	i += 2;
	while(strncmp(i, "\r\n0\r\n\r\n", 7))
	{//printf("\n                          3\n");
		i = strstr(i, "\r\n");
		if(i == NULL)
			return 0;
		i += 2;
		j = strstr(i, "\r\n");
		if(j == NULL)
			return 0;
		len = j - i;
		memset(size_str, 0, 16);
		memcpy(size_str, i, len);
		size_str[len] = '\0';
		chunked_size = str_to_num(size_str);
		head = j + 2;
		if(dest_size+chunked_size > 1024 * 1024)
			dest = (char*)realloc(dest,dest_size+chunked_size+1);
		memcpy(dest + dest_size, head, chunked_size);
		dest_size += chunked_size;
		i = head + chunked_size;
	}
	mail_info->recive_data = NULL;
	free(mail_info->recive_data);
	mail_info->recive_data = dest;
	//mail_info->recive_length = dest_size;
	dest = NULL;
	return dest_size;
}

int write_nochunked_okdata(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	//printf("write_nochunked_okdata ...\n");
	unsigned int seq;
	int off_seq;
	int len;
	char *tmp = NULL, *tmp1 = NULL;

	if (mail_info == NULL || data == NULL || ptcp == NULL || data_len >= 65535)
		return -1;

	seq = ntohl(ptcp->seq);
	if (mail_info->recive_length == 0) {
		mail_info->recive_length = 5000;
		mail_info->recive_data = (char *)malloc(5001);
		if (mail_info->recive_data == NULL) {
			LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
			return -1;
		}
		memset(mail_info->recive_data, 0, 5001);
		mail_info->http_seq = seq;
	}
	if (mail_info->recive_length == 5000) {
		off_seq = seq - mail_info->http_seq;
		if (off_seq < 0) {
			data -= off_seq;
			data_len += off_seq;
			off_seq = 0;
		}
		if (off_seq + data_len > mail_info->recive_length) {
			LOG_WARN("webmail:write_to_okdata: message too long!\n");
			return -1;
		}
		memcpy(mail_info->recive_data + off_seq, data, data_len);

		tmp = strstr(mail_info->recive_data, "\r\n\r\n");
		if (tmp != NULL) {
			tmp += 4;
			mail_info->http_seq = tmp - mail_info->recive_data + mail_info->http_seq;
			len = get_http_length(mail_info->recive_data);
			if (len == -1) {
				LOG_WARN("webmail:write_to_okdata: get_http_length() error!\n");
				return -1;
			}
			if (len == 0)
				len = DEFAULT_OK_LEN;
			mail_info->recive_length = len;
			tmp1 = (char *)malloc(mail_info->recive_length + MTU + 1);
			if (tmp1 == NULL) {
				LOG_WARN("webmail:write_to_okdata: malloc()2 failed!\n");
				return -1;
			}
			memset(tmp1, 0, mail_info->recive_length + MTU + 1);
			len = 5000 - (tmp - mail_info->recive_data);
			if (len > mail_info->recive_length)
				len = mail_info->recive_length;
			memcpy(tmp1, tmp, len);
			free(mail_info->recive_data);
			mail_info->recive_data = tmp1;
			tmp1 = NULL;
		}
		return 0;
	}
	off_seq = seq - mail_info->http_seq;
	if (off_seq < 0) {
		data -= off_seq;
		data_len += off_seq;
		off_seq = 0;
	}
	if (off_seq + data_len > mail_info->recive_length) {
		LOG_WARN("webmail:write_to_okdata: message too long!\n");
		return -1;
	}
	memcpy(mail_info->recive_data + off_seq, data, data_len);
	//printf("write_nochunked_okdata complete ...\n");
	return 0;
}

int write_chunked_okdata(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	//printf("write_chunked_okdata ...\n");
	unsigned int seq;
	int off_seq;
	int len;
	char *tmp = NULL, *tmp1 = NULL;

	if (mail_info == NULL || data == NULL || ptcp == NULL || data_len >= 65535)
		return -1;

	seq = ntohl(ptcp->seq);
	if (mail_info->recive_length == 0) {
		tmp = strstr(data, "\r\n\r\n");
		if (tmp != NULL) {
			tmp += 4;
			mail_info->http_seq = tmp - data + seq;
			mail_info->recive_length = DEFAULT_OK_LEN;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length + 101);
			if (mail_info->recive_data == NULL) {
				LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
				return -1;
			}
			memset(mail_info->recive_data, 0, mail_info->recive_length + 101);
		}
		//return 0;
	}
	off_seq = seq - mail_info->http_seq;
	if (off_seq < 0) {
		data -= off_seq;
		data_len += off_seq;
		off_seq = 0;
	}
	if (off_seq + data_len > mail_info->recive_length) {
		LOG_WARN("webmail:write_to_okdata: message too long!\n");
		return -1;
	}
	memcpy(mail_info->recive_data + off_seq, data, data_len);
	//printf("write_chunked_okdata complete ...\n");
	return 0;
}

int write_to_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp)
{
	//printf("write_to_mail ... \n");
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int len;
	char *tmp = NULL;

	if (mail_info->mail_length == 0) 
	{
		mail_info->mail_length = 5000;
		mail_info->mail_data = (char *)malloc(5001);
		if (mail_info->mail_data == NULL) 
		{
			return -1;
		}
		memset(mail_info->mail_data, 0, 5001);
		mail_info->start_seq = seq;
	}
	
	if(mail_info->mail_length == 5000) 
	{
		off_seq = seq - mail_info->start_seq;
		if (off_seq + data_len > mail_info->mail_length) 
		{
			LOG_WARN("message too long!\n");
			return -1;
		}
		
		memcpy(mail_info->mail_data + off_seq, data, data_len);
		len = get_http_length(mail_info->mail_data);
		if (-1 == len)
			return -1;
			
		if (len > 0) 
		{
			mail_info->mail_length += len;
			tmp = (char *)malloc((size_t)mail_info->mail_length + 1);
			if (tmp == NULL) {
				return -1;
			}
			memset(tmp, 0, mail_info->mail_length + 1);
			memcpy(tmp, mail_info->mail_data, 5000);
			free(mail_info->mail_data);
			mail_info->mail_data = tmp;
		}
		
		return 0;
	}
	
	off_seq = seq - mail_info->start_seq;
	if (off_seq + data_len > mail_info->mail_length) 
	{
		LOG_WARN("message too long!\n");
		return -1;
	}
	memcpy(mail_info->mail_data + off_seq, data, data_len);
	//printf("write_to_mail complete ...\n");
	return 0;
}

int write_to_attach_3(Attach_info *attach_info)
{
	int fd;

	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT);
	if (fd == -1)
		return -1;

	write(fd, attach_info->body, attach_info->bodyLen);
	close(fd);
	return 0;
}

int write_to_attach(Attach_info *attach_info, char *data, unsigned int data_len, unsigned int seq)
{
	//printf("write_to_attach ...\n");
	int off_seq;
	int fd;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq < 0) 
	{
		data_len += off_seq;
		if (data_len < 1)
		{
			return 0;
		}
		data -= off_seq;
		off_seq = 0;
	}
	fd = open(attach_info->path_of_here, O_RDWR);
	if (fd == -1)
	{
		return -1;
	}
	lseek(fd, off_seq, SEEK_SET);
	write(fd, data, data_len);
	close(fd);

	//printf("write_to_attach complete ...\n");
	return 0;
}

int write_to_attach_2(Attach_info *attach_info, char *data, unsigned int data_len, unsigned int seq)
{
	//printf("write_to_attach ...\n");
	int off_seq;
	int fd;
	int result;
	if(seq<attach_info->start_seq) return 0;
	off_seq=seq-attach_info->start_seq;
	fd = open(attach_info->path_of_here, O_RDWR);
	if (fd == -1)
	{
		return -1;
	}
	lseek(fd, off_seq+attach_info->recive_length, SEEK_SET);
	write(fd, data, data_len);
	close(fd);

	//printf("write_to_attach complete ...\n");
	return 0;
}

//
int write_to_okmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp) 
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int len;
	char *tmp = NULL;

	if (mail_info->recive_data == NULL) 
    {
		mail_info->recive_length = get_http_length(data) ;//真正长度
		mail_info->recive_data = (char *)malloc(mail_info->recive_length +2000);
		if (mail_info->recive_data == NULL) 
        {
			return -1;
		}
		memcpy(mail_info->recive_data , data, data_len);
		mail_info->http_seq = seq;
	}
	else 
    {
		off_seq = seq - mail_info->http_seq;
		if (off_seq + data_len > mail_info->recive_length + 2000) 
        {
			LOG_WARN("message too long!\n");
			return -1;
		}
		memcpy(mail_info->recive_data + off_seq, data, data_len);
		
	}
	
	//printf("write_to_mail complete ...\n");
	return 0;
}

int write_to_okattach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp) 
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int len;
	char *tmp = NULL;
	//printf("seq:%lu\n",seq);
	//printf("data_len:%d\n",data_len);
	if (attach_info->recive_data == NULL) {
		attach_info->recive_length = get_http_length(data) ;//真正长度
		//printf("attach_info->recive_length :%d\n",attach_info->recive_length);
		attach_info->recive_data = (char *)malloc(attach_info->recive_length +2000);
		if (attach_info->recive_data == NULL) {
			return -1;
		}
		memcpy(attach_info->recive_data , data, data_len);
		attach_info->http_seq = seq;
		//printf("attach_info->http_seq :%lu \n",attach_info->http_seq );
	}
	else {
		off_seq = seq - attach_info->http_seq;
		//printf("off_seq + data_len: %d\n",off_seq + data_len);
		if (off_seq + data_len > attach_info->recive_length + 2000) {
			LOG_WARN("message too long!\n");
			return -1;
		}
		memcpy(attach_info->recive_data + off_seq, data, data_len);
		
	}
	
	return 0;
}

//
Mail_info *find_mail_head(char *connect_id, Mail_info *mail_head) 
{
	Mail_info *mail_info =mail_head->next;
	while (mail_info !=NULL) {
		if(!strcmp(mail_info->connect_id,connect_id))
			break;
		mail_info = mail_info->next;
	}
	return mail_info;
}

Mail_info *find_mail_head2(char *connect_id, Mail_info *mail_head,unsigned short type) 
{
	Mail_info *mail_info = mail_head->prev;
	while (mail_info !=NULL) {
		if(!strcmp(mail_info->connect_id,connect_id) && type != mail_info->mail_type)
			break;
		mail_info = mail_info->next;
	}
	return mail_info;
}

Attach_info *find_attach(char *ID)
{
	Attach_info *attach_info = attach_tab.head->next;
	while (attach_info != NULL) {
		if (!strcmp(attach_info->ID_str, ID)) {
			del_attach_node(attach_info);
			break;
		}
		attach_info = attach_info->next;
	}
	return attach_info;
}

Attach_info *find_attach_1(Mail_info *mail_info)
{
    Attach_info *attach_info = attach_tab.head->next;
    while(attach_info != NULL)
    {
        if(attach_info->source_ip == mail_info->source_ip && attach_info->dest_ip == mail_info->dest_ip)
        {
            del_attach_node(attach_info);
            break;
        }
        
        attach_info = attach_info->next;
    }
    
    return attach_info;
}

int proce_attach_head(Attach_info *attach_info, char *data, unsigned int data_len, char **file_content)
{
	char *p = NULL;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	int result;
	p = strstr(data, "\r\nContent-Type: ");
	if (p == NULL)
		return -1;
	p = strstr(p, "\r\n\r\n");
	if (p == NULL)
		return -1;
	p += 4;

	*file_content = p;
	attach_info->start_seq = p - data; 
	result = regcompile_2(data, file_name_pattern, &attach_info->path_of_sender);
	if (result == -1)
		return -1;
	if (!strlen(attach_info->path_of_sender))
		return -2;
	//printf("######path_of_sender: %s#########\n", attach_info->path_of_sender);
	return data_len - (p - data); 
}

unsigned str_to_uint(char *len_str)
{
	char *p = NULL;
	unsigned length = 0;

	p = len_str;
	while (*p != '\0') {
		if ('0' <= *p && '9' >= *p)
			length = length * 16 + (*p - '0');
		else if ('a' <= *p && 'f' >= *p)
			length = length * 16 + (*p - 'a' + 10);
		else if ('A' <= *p && 'F' >= *p)
			length = length * 16 + (*p - 'A' + 10);
		else
			break;	
		p++;
	}

	return length;
}

int decomp_chunked_gzip(char *src, size_t max_len, char **dest)
{
	//printf("decomp_chunked_gzip ...\n");
	char *pch1 = NULL;
	char *pch2 = NULL;
	char *pdep = NULL;
	char len_str[9] = {0};
	size_t len;
	size_t seg_len;
	size_t total_len;
	int result;

	//assert(src != NULL);
	if (src == NULL)
		return -1;

	pch1 = src;
	pdep = src;
	total_len = 0;
	*dest = NULL;

	while (pch1 < src + max_len - 10) {
		pch2 = memfind(pch1, "\r\n", 10);
		len = pch2 - pch1;
		if (len > 10)
			return -1;
		memcpy(len_str, pch1, len);
		len_str[len] = 0;
		seg_len = str_to_uint(len_str);
		total_len += seg_len;
		pch1 = pch2 + 2;
		memcpy(pdep, pch1, seg_len);
		if (memcmp(pch2 - 2, "\0\0", 2) == 0)
			break;
		pch1 = pch1 + seg_len + 2;
	}

	char *tmp_dest = NULL;
	
	result = decomp_gzip(src, total_len, &tmp_dest);
	if (result == -1)
		return -1;

	*dest = tmp_dest;
	//printf("decomp_chunked_gzip complete ...\n");
	return 0;
}

int decomp_gzip(char *src, unsigned int len, char **dest)
{
	int res = -1;
	char tmp[201] = {0};
	int have = 0;
	int is_first = 1;
	int n = 0;
	int has_error = 0;
	int ret = -1;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Byte*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Byte*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK)
        {
			LOG_WARN("webmail:decomp_gzip(): decompressing gzip error\n");
			has_error = 1;
			break;
		} 
        else 
        {
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) 
            {
				*dest = (char *)malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
                
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
            else 
            {
				*dest = (char *)realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
                
				strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error) 
    {
		if (!is_first)
			free(*dest);
		*dest = NULL;
		//printf("decomp_gzip complete Error ...\n");
		return -1;
	}
    else
    {
		//printf("decomp_gzip complete Ok ...\n");
		return 0;
	}
}

int decomp_gzip_1(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_1 ...\n");
  	int res = 0;
	char tmp[201] = {0};
	int have = 0;
	int is_first = 1;
	int n = 0;
	int has_error = 0;
	int ret = 0;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Byte*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Byte*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK) 
        {
			LOG_WARN("webmail:decomp_gzip_1(): decompressing gzip error\n");
			has_error = 1;
			break;
		} 
        else 
        {
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) 
            {
				*dest = (char *)malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
                
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
            else 
            {
				*dest = (char *)realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
                
				strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

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

int decomp_gzip_2(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_2 ...\n");
	int res = 0;
	char tmp[201] = {0};
	int have = 0;
	int is_first = 1;
	int n = 0;
	int has_error = 0;
	int ret = 0;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Byte*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Byte*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END) 
        {      
			LOG_WARN("webmail:decomp_gzip_2(): decompressing gzip error\n");
			has_error = 1;
			break;      	       
		} 
        else 
        {
			n = 200 - d_stream.avail_out;
			tmp[n] = 0;
			if (is_first) 
            {
				*dest = (char *)malloc(n + 1);
				if (*dest == NULL)
					has_error = 1;
                
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
            else 
            {
				*dest = (char *)realloc(*dest, d_stream.total_out + 1);
				if (*dest == NULL)
					has_error = 1;
				strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

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

int decomp_gzip_3(char *src, unsigned int len, char **dest)
{
	//printf("decomp_gzip_3 ...\n");
	int res = 0;
	char tmp[201] = {0};
	int have = 0;
	int is_first = 1;
	int n = 0;
	int has_error = 0;
	int ret = 0;
    char *ptemp = NULL;

	z_stream d_stream;
	d_stream.zalloc = NULL;
	d_stream.zfree = NULL;
	d_stream.opaque = NULL;
	ret = inflateInit2(&d_stream, 47);
	d_stream.next_in = (Byte*)src;
	d_stream.avail_in = len;

	do {
		d_stream.next_out = (Byte*)tmp;
		d_stream.avail_out = 200;
		res = inflate(&d_stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END) 
        {
			LOG_WARN("webmail:decomp_gzip_3(): decompressing gzip error\n");
			has_error = 1;
			break;
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
                    has_error = 1;
                    return 0;
                }
				memcpy(*dest, tmp, n + 1);
				is_first = 0;
			} 
            else 
			{
				//*dest = realloc(*dest, d_stream.total_out + 1);
                ptemp = (char *)realloc(*dest, d_stream.total_out + 1);
                if (ptemp == NULL)
                {
                    has_error = 1;
                    ptemp = *dest;
                    return 0;
                }
                
                *dest = ptemp;
                strcat(*dest, tmp);
				//if (*dest == NULL)
				//	has_error = 1;
				//strcat(*dest, tmp);
			}
		}
	} while (d_stream.avail_out == 0);

	inflateEnd(&d_stream);

	if (has_error) 
    {
		//printf("decomp_gzip_3 complete Error ...\n");
	    return -1;
	} 
    else 
    {
		//printf("decomp_gzip_3 complete Ok ...\n");
		return 0;
	}
}

int get_time(char *data, char *dest)
{
	char *p1 = NULL, *p2 = NULL;
	char tm_str[MAX_TIME_LEN + 1];
	time_t timeval;
	struct tm time_struct, *tm_ptr;
	struct tm *time_ptr;
//	char timezone[10] = "GMT";

	//printf("######in get_time######\n%s\n",data);
	p1 =strstr(data,"\r\nDate: ");
	if(p1==NULL) return -1;
	p1 += 8;
	p2 =strstr(p1,"\r\n");
	if(p2==NULL) return -1;
	strncpy(tm_str, p1, p2 - p1);
	tm_str[p2 - p1] = 0;

	strptime(tm_str, "%a, %d %b %Y %H:%M:%S %Z", &time_struct);
//	time_struct.tm_zone = timezone;
//	time_struct.tm_hour += 8;
//	time_struct.tm_gmtoff = 0;
	timeval = mktime(&time_struct) + 8 * 3600;
	tm_ptr = localtime(&timeval);
	snprintf(dest, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);

	//printf("######out of get_time######\n");
}

time_t convert_time_format(char *data)
{
	struct tm tm_ptr;
	time_t timeval;
	int result_val = -1;

	if (!data)
		return -1;

    if (10 == strlen(data))  // the length of 1497421615 is 10
    {
        timeval = strtol(data, 0, 10);
        return timeval;
    }

	result_val = sscanf(data, "%04d-%02d-%02d %02d:%02d:%02d", &tm_ptr.tm_year, &tm_ptr.tm_mon, &tm_ptr.tm_mday, &tm_ptr.tm_hour, &tm_ptr.tm_min, &tm_ptr.tm_sec);
	if (result_val != -1)
	{
		tm_ptr.tm_year = tm_ptr.tm_year - 1900;
		tm_ptr.tm_mon = tm_ptr.tm_mon - 1;

		timeval = mktime(&tm_ptr);
	}
	else
	{
		timeval = time(NULL);
	}

	return timeval;
}

int code_convert(char *from_charset, char *to_charset, char *inbuf, int inlen , char *outbuf, int outlen)
{
   iconv_t cd;
   int rc;
   char *pin = inbuf;
   char *pout = outbuf;
/*
   const char *name;
   UCharsetDetector *csd;
   const UCharsetMatch *ucm;
   UErrorCode status = U_ZERO_ERROR;


   csd = ucsdet_open(&status);
   ucsdet_setText(csd, inbuf, inlen, &status);
   ucm = ucsdet_detect(csd, &status);
	name = ucsdet_getName(ucm, &status);
   printf("char name: %s\n", name);
*/

   cd = iconv_open(to_charset, from_charset);
   if (cd == (iconv_t)-1)
	   return -1;
   
   memset(outbuf, 0, outlen);
   if (iconv(cd, &pin, (size_t*)&inlen, &pout, (size_t*)&outlen) == -1) 
   {
	   iconv_close(cd);
	   //fprintf(stderr, "src: %s\ndest: %s\n", inbuf, outbuf);
	   return -1;
   }
   iconv_close(cd);

 //  ucnv_convert("utf-8", "gb18030", outbuf, outlen, inbuf, inlen, NULL);
   return 0;
}

int htmldecode_full(char *src, char *dest)
{
	int strlength=strlen(src);
	if(strlength<3)
	{
		strcpy(dest,src);
		return -1;
	}
	int i=0;
	int flag=0;
	int j=0;
	char tmp1=0;
	char tmp2=0;
	char tmpA=0;
	char tmpB=0;
	char A,B;
	
	for(i=0; i<strlength; i++)
	{
		if(src[i] =='%')
		{
			flag = 1;
			continue;
		}
		switch(flag)
		{
			case 0:
			{
				dest[j]=src[i];
				if(dest[j] == '+') dest[j] = ' ';
				j++;
				break;
			}
			case 1:
				tmpA = src[i];
				flag = 2;
				break;
			case 2:
				tmpB = src[i];
				tmp1 = toupper(tmpA);
				tmp2 = toupper(tmpB);
				if(((tmp1 >= 48&&tmp1 <= 57) || (tmp1 >= 65&&tmp1 <= 90)) && (
				(tmp2 >= 48&&tmp2 <= 57) || (tmp2 >= 65 && tmp2 <= 90)))
				{
					if(tmp1 >= 48&&tmp1 <= 57) A = tmp1 - 48;
					else A = 10 + tmp1 - 65;
					if(tmp2 >= 48 && tmp2 <= 57) B = tmp2 - 48;
					else B = 10 + tmp2 - 65;
					dest[j] = A * 16 + B;
				}
				else
				{
					dest[j] = '%';
					dest[j+1] = tmp1;
					dest[j+2] = tmp2;
					j += 2;
				}
				flag = 0;
				j++;
				break;
			default:
				break;
		}
	}
	dest[j] = 0;
	return 0;
}

int regcompile_1(char *src,char *pattern,char *matched,int length)
{
  size_t len;
  regex_t re;
  regmatch_t subs[SUBSLEN];
  char errbuf[EBUFLEN];
  int err, i;
  
  //printf("***************\n compost id : %s \n***************\n",src);
 
  err=regcomp(&re,pattern,REG_EXTENDED);
  if(err)
  {
   len=regerror(err,&re,errbuf,sizeof(errbuf));
   fprintf(stderr, "error:regcomp:%s\n",errbuf);
   return -1;
  }
  err=regexec(&re,src,(size_t)SUBSLEN,subs,0);
  if(err==REG_NOMATCH)
  {
    fprintf(stderr, "sorry,no match...\n");
    regfree(&re);
    return -1;
  }
  else if(err)
  {
    len= regerror(err,&re,errbuf,sizeof(errbuf));
    fprintf(stderr, "error:regexec:%s\n",errbuf);
    regfree(&re);
    return -1;
  }
 
  len=subs[1].rm_eo-subs[1].rm_so;
  if(len<length){
  memcpy(matched,src+subs[1].rm_so,len);
  matched[len]='\0';
  }else{
  memcpy(matched,src+subs[1].rm_so,length);
  matched[length]='\0';
  }
  regfree(&re);
  return 0;
}

int regcompile_2(char *src,char *pattern,char **matched)
{
  size_t len;
  regex_t re;
  regmatch_t subs[SUBSLEN];
  char errbuf[EBUFLEN];
  int err = -1, i;

  if (src == NULL)
	  return -2;
  err=regcomp(&re,pattern,REG_EXTENDED);
  if(err)
  {
   len=regerror(err,&re,errbuf,sizeof(errbuf));
   fprintf(stderr, "error:regcomp:%s\n",errbuf);
   return -1;
  }
  err=regexec(&re,src,(size_t)SUBSLEN,subs,0);
  if(err==REG_NOMATCH)
  {
    fprintf(stderr, "sorry,no match...\n");
    regfree(&re);
    return -1;
  }
  else if(err)
  {
    len= regerror(err,&re,errbuf,sizeof(errbuf));
   fprintf(stderr, "error:regexec:%s\n",errbuf);
	regfree(&re);
    return -1;
  }
  
  len=subs[1].rm_eo-subs[1].rm_so;


  *matched = (char *)malloc((size_t)(len + 1));
	if (*matched == NULL) {
		regfree(&re);
		return -1;
	}
 
   memcpy(*matched, src + subs[1].rm_so, len);
  (*matched)[len]='\0';
	regfree(&re);
	return 0;
}

reg_rtn_struct cns_reg(const char *src, const char *pattern)
{
	reg_rtn_struct reg_rtn_struct_var;

#define OVECCOUNT 10
	pcre *re;
	const char *error;
	int erroffset;
	int ovector[OVECCOUNT];
	int rc, i;

	reg_rtn_struct_var.rtn = -1;
	reg_rtn_struct_var.pstart = -1;
	reg_rtn_struct_var.pend = -1;

	re = pcre_compile(pattern, PCRE_DOTALL, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "webmail:cns_reg(): pcre_compile()failed at offset %d: %s\n", erroffset, error);
		return reg_rtn_struct_var;
	}
	rc = pcre_exec(re, NULL, src, strlen(src), 0, 0, ovector, OVECCOUNT);
	if (rc < 0) {
		/*
		if (rc == PCRE_ERROR_NOMATCH)
			fprintf(stderr, "Sorry, no match...\n");
		else
			fprintf(stderr, "Matching error %d\n", rc);
		*/
		pcre_free(re);
		re = NULL;
		return reg_rtn_struct_var;
	}
	
	reg_rtn_struct_var.rtn = 0;
	reg_rtn_struct_var.pstart = ovector[0];
	reg_rtn_struct_var.pend = ovector[1];

	pcre_free(re);
	re = NULL;
	return reg_rtn_struct_var;
}


int cns_str_ereplace(char **src, const char *pattern, const char *newsubstr)
{
	if (strcmp(pattern, newsubstr) == 0) {
		return 0;
	}

	reg_rtn_struct reg_rtn_struct_var;
	int rtn = 0;
	int pstart = 0;
	int pend = 0;
	char *dest = *src;
	char *tmp;
	char *new_tmp_str = dest;
	int new_tmp_str_len = 0;

	while (!rtn) {
		reg_rtn_struct_var = cns_reg(new_tmp_str, pattern);
		rtn = reg_rtn_struct_var.rtn;
		pstart = reg_rtn_struct_var.pstart;
		pend = reg_rtn_struct_var.pend;

		if (!rtn) {
			tmp = (char *)calloc(sizeof(char), strlen(dest) + strlen(newsubstr) - (pend-pstart) +1);
			if (tmp == NULL)
				break;
			strncpy(tmp, dest, new_tmp_str_len + pstart);
			tmp[new_tmp_str_len + pstart] = '\0';
			strcat(tmp, newsubstr);
			strcat(tmp, new_tmp_str + pend);
			free(dest);
			dest = tmp;
			tmp = NULL;
			new_tmp_str_len = new_tmp_str_len + pstart + strlen(newsubstr);
			new_tmp_str = dest + new_tmp_str_len;
		}
	}
	*src = dest;
	return 0;
}

char *clear_html_tag(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
    char* data = NULL;
	if (str == NULL)
		return NULL;
	
	int result;
	result = cns_str_ereplace(&str, "<[sS][tT][Yy][Ll][Ee].*?</[Ss][Tt][Yy][Ll][Ee]>", "");
//	if (result != -1)
//		result = cns_str_ereplace(&str, "<span style=.*?</span>", "");
	if (result != -1)
		result = cns_str_ereplace(&str, "<[^>]+>", "");
	if (result != -1)
		result = cns_str_ereplace(&str, "<[Bb][Rr]>", "\n");

	return str;
}

char *clear_html_symbol(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;

	int result;
// ��?��符�?转�形�?��?��?	result = cns_str_ereplace(&str, "&lt;", "<");
	if (result != -1)
		result = cns_str_ereplace(&str, "&gt;", ">");
	if (result != -1)
		result = cns_str_ereplace(&str, "&apos;", "'");
	if (result != -1)
		result = cns_str_ereplace(&str, "&quot;", "\"");
	if (result != -1)
		result = cns_str_ereplace(&str, "&nbsp;", " ");
	if (result != -1)
		result = cns_str_ereplace(&str, "&(?!#x{0,1}[[:xdigit:]]{2,6};)", "&amp;");
    if (result != -1)
		result = cns_str_ereplace(&str, "&amp;", "&");
    
	return str;
/*             ��?��符�?? 代�?	char *tmp_str1 = NULL, *tmp_str2 = NULL;
	int result;

	tmp_str1 = conv_to_xml_symbol(source);
	if (tmp_str1 == NULL)
		return NULL;
	tmp_str2 = conv_xml_symbol(tmp_str1);
	free(tmp_str1);

	return tmp_str2;
*/
}

char *conv_xml_symbol(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;

	int result;
	result = cns_str_ereplace(&str, "&lt;", "<");
	if (result != -1)
		result = cns_str_ereplace(&str, "&gt;", ">");
	if (result != -1)
		result = cns_str_ereplace(&str, "&apos;", "'");
	if (result != -1)
		result = cns_str_ereplace(&str, "&quot;", "\"");
	if (result != -1)
		result = cns_str_ereplace(&str, "&(?!#x{0,1}[[:xdigit:]]{2,6};)", "&amp;");
	return str;
}

char *conv_to_xml_symbol(char *source)
{
	if (source == NULL)
		return NULL;

	char *str = strdup(source);
	if (str == NULL)
		return NULL;

	int result;
	result = cns_str_ereplace(&str, "&lt;", "<");
	if (result != -1)
		result = cns_str_ereplace(&str, "&gt;", ">");
	if (result != -1)
		result = cns_str_ereplace(&str, "&amp;", "&");
	if (result != -1)
		result = cns_str_ereplace(&str, "&apos;", "'");
	if (result != -1)
		result = cns_str_ereplace(&str, "&quot;", "\"");
//	if (result != -1)
//		result = cns_str_ereplace(&str, "&.{2,7};", "*");

	return str;
}

void trim_attach(char *filename, off_t n)
{
	int fd;
	off_t old_length;

	fd = open(filename, O_RDWR);
	if (fd == -1)
		return ;
	old_length = lseek(fd, 0, SEEK_END);
	//LOG_INFO("old_length : %d\n",old_length);
	ftruncate(fd, old_length - n );

	close(fd);
}

void trim_attach2(char *filename, size_t len)
{
	int fd;
	struct stat st;
	off_t off;
	int result;
	int size;
	char *boun_pos = NULL;
	int pagesize;
	char *mapped = NULL;

	pagesize = sysconf(_SC_PAGESIZE);
	fd = open(filename, O_RDWR);
	if (fd < 0)
		return ;
	result = fstat(fd, &st);
	if (result < 0)
		return ;

	off = (st.st_size / pagesize) * pagesize;
	size = st.st_size - off;
	if (size < len) {
		size += ((len - size) / pagesize + 1) * pagesize;
		off = st.st_size - size;
		if (off < 0)
			off = 0;
	}
	len = st.st_size - off;

	mapped = (char *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, off);
	perror("mmap");
	if (mapped == MAP_FAILED) {
		close(fd);
		return ;
	}
	boun_pos = memfind(mapped, "\r\n----------", len);
	if (boun_pos == NULL) {
		close(fd);
		return ;
	}
	off += boun_pos - mapped;
	munmap(mapped, len);
	ftruncate(fd, off);
	close(fd);
}

int get_file_name(char *path, char *filename)
{
	size_t len;
	int j;

	if (path == NULL) {
		strcpy(filename, "unknow");
		return -1;
	}

	len = strlen(path);
	j = len - 1;
	if (path[0] == '/') {
		while (j > -1 && path[j] != '/') {
			j--;
		}
	} else {
		while (j > -1 && path[j] != '\\') {
			j--;
		}
	}
	if (len - 1 - j > MAX_FN_LEN - 1)
		strcpy(filename, "unknow");
	else
		strcpy(filename, path + j + 1);
}

int create_dir(char *path, char *mail_str, char *mail_name)
{
	time_t timeval;
	struct tm *tm_ptr = NULL;
    char tmp_name[MAX_UN_LEN+1];
	char dir_str[MAX_UN_LEN + TIME_LEN + 2];
	mode_t dir_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	int result;
    int len;
    
    len = strlen(mail_name);
    if (len > MAX_UN_LEN)
    {
        strncpy(tmp_name, mail_name, MAX_UN_LEN);
        tmp_name[MAX_UN_LEN]='\0';
    } 
    else 
    {
        strcpy(tmp_name, mail_name);
    }

	mkdir(mail_data_path, dir_mode);
	timeval = time(NULL);
	tm_ptr = localtime(&timeval);

	sprintf(path, "%s/%d-%02d-%02d/", mail_data_path, tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday );
	mkdir(path, dir_mode);

	strcat(path, mail_str);
	mkdir(path, dir_mode);

	sprintf(dir_str, "/%s_%02d_%02d_%02d_%02d", tmp_name, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec, rand()%100);
	strcat(path, dir_str);
	int ilen = strlen(path);
	char * i, * j;
	i = strstr(path, "&#64;");
	if(i)
	{
		*i = '@';
		j = i + 5;
		strcpy(i + 1, j);
		*(path + ilen - 1 - 4 ) = '\0';
	}

	mkdir(path, dir_mode);
}

int ulong_to_ipstr(unsigned int sip, char dip[16])
{
        memset(dip, 0, 16);
        sprintf(dip, "%d.%d.%d.%d", sip&0x000000FF, (sip>>8)&0x0000FF,(sip>>16)&0x00FF,sip>>24);
        return 0;
}

void write_oracle_db_webmail(int object_id, Mail_info *mail_info,char *datafile,char *attachment, char * attachs_name, int opt)
{
	time_t timeVal;
	unsigned short sport = ntohs(mail_info->source_port);
	unsigned short dport = ntohs(mail_info->dest_port);
	char mac_string[18]={0};
	unsigned char *p = mail_info->client_mac;
	sprintf(mac_string, "%02x-%02x-%02x-%02x-%02x-%02x", p[0], p[1], p[2], p[3], p[4], p[5]);

	clear_unwanted_chars(mail_info->to, 2600);
	clear_unwanted_chars(mail_info->cc, 2600);
	clear_unwanted_chars(mail_info->bcc, 2600);

	char attach[MAX_PATH_LEN + 1] = {0};
	int affixflag;
	if(strlen(attachment) == 0)
	{
		if(lzDataPath == NULL)
		{
			strcpy(attach, "/home/spyData/moduleData/webmail/downattach");
		}
		else
		{
			strcpy(attach, lzDataPath);
			strcat(attach, "/spyData/moduleData/webmail/downattach");
		}
		affixflag = 0;
	}
	else
	{
		strcpy(attach, attachment);
		affixflag = 1;
	}
	
	char mid[MAX_ID_LEN + 1] = {0};
	if(mail_info->mail_id != NULL)
		strcpy(mid, mail_info->mail_id);

	makeStr(mail_info->username);
	makeStr(mail_info->from);
	makeStr(mail_info->to);
	makeStr(mail_info->cc);
	makeStr(mail_info->bcc);
	makeStr(mail_info->subject);
	char source_ip[16] = {0};
	char dest_ip[16] = {0};
	ulong_to_ipstr(mail_info->source_ip, source_ip);
	ulong_to_ipstr(mail_info->dest_ip, dest_ip);
	timeVal = convert_time_format(mail_info->sent_time);

	/*write webmail data to shared memory, by zhangzm*/
	WEBMAIL_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = object_id;
	tmp_data.p_data.readed = 0;
	strcpy(tmp_data.p_data.clientIp, source_ip);
	strncpy(tmp_data.p_data.clientMac, mac_string, 17);
	sprintf(tmp_data.p_data.clientPort, "%d", sport);
	strcpy(tmp_data.p_data.serverIp, dest_ip);
	sprintf(tmp_data.p_data.serverPort, "%d", dport);
	
	tmp_data.p_data.captureTime = mail_info->cap_time;
	tmp_data.optype = opt;
	strncpy(tmp_data.username, mail_info->username, 64);
	strncpy(tmp_data.password, mail_info->passwd, 64);
	tmp_data.sendTime = (unsigned int)timeVal;
	strncpy(tmp_data.sendAddr, mail_info->from, 259);
	strncpy(tmp_data.recvAddr, mail_info->to, 259);
	strncpy(tmp_data.ccAddr, mail_info->cc, 259);
	strncpy(tmp_data.bccAddr, mail_info->bcc, 259);
	strncpy(tmp_data.subject, mail_info->subject, 259);
	strncpy(tmp_data.datafile, datafile, 259);
	strncpy(tmp_data.attachment, attach, 259);
	tmp_data.affixflag = affixflag;
	strncpy(tmp_data.mid, mid, 1023);
	
	tmp_data.p_data.proType = mail_info->mail_num;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBMAIL, (void *)&tmp_data, sizeof(tmp_data));
}

void write_oracle_db_webmail_m(int object_id, Mail_info *mail_info, char *datafile, char *attachment, char *attachs_name, int opt)
{
	time_t  timeVal;
	unsigned  short sport=ntohs(mail_info->source_port);
	unsigned  short dport=ntohs(mail_info->dest_port);
	char mac_string[18]={0};
	unsigned char *p = mail_info->client_mac;
	sprintf(mac_string, "%02x-%02x-%02x-%02x-%02x-%02x", p[0], p[1], p[2], p[3], p[4], p[5]);

	clear_unwanted_chars(mail_info->to, 2600);
	clear_unwanted_chars(mail_info->cc, 2600);
	clear_unwanted_chars(mail_info->bcc, 2600);

	char attach[MAX_PATH_LEN + 1] = {0};
	
	int affixflag;
	if(strlen(attachment) == 0)
	{
		if(lzDataPath == NULL)
		{
			strcpy(attach, "/home/spyData/moduleData/webmail/downattach");
		}
		else
		{
			strcpy(attach, lzDataPath);
			strcat(attach, "/spyData/moduleData/webmail/downattach");
		}
		affixflag = 0;
	}
	else
	{
		strcpy(attach, attachment);
		affixflag = 1;
	}
	
	char mid[MAX_ID_LEN + 1] = {0};
	if(mail_info->mail_id != NULL)
		strcpy(mid, mail_info->mail_id);

	makeStr(mail_info->username);
	makeStr(mail_info->from);
	makeStr(mail_info->to);
	makeStr(mail_info->cc);
	makeStr(mail_info->bcc);
	char source_ip[16] = {0};
	char dest_ip[16] = {0};
	ulong_to_ipstr(mail_info->source_ip, source_ip);
	ulong_to_ipstr(mail_info->dest_ip, dest_ip);
	timeVal = convert_time_format(mail_info->sent_time);

	/*write webmail data to shared memory, by zhangzm*/
	WEBMAIL_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = object_id;
	tmp_data.p_data.readed = 0;
	strcpy(tmp_data.p_data.clientIp, source_ip);
	strncpy(tmp_data.p_data.clientMac, mac_string, 17);
	sprintf(tmp_data.p_data.clientPort, "%d", sport);
	strcpy(tmp_data.p_data.serverIp, dest_ip);
	sprintf(tmp_data.p_data.serverPort, "%d", dport);
	
	tmp_data.p_data.captureTime = mail_info->cap_time;
	tmp_data.optype = opt;
	strncpy(tmp_data.username, mail_info->username, 64);
	strncpy(tmp_data.password, mail_info->passwd, 64);
	tmp_data.sendTime = (unsigned int)timeVal;
	strncpy(tmp_data.sendAddr, mail_info->from, 259);
	strncpy(tmp_data.recvAddr, mail_info->to, 259);
	strncpy(tmp_data.ccAddr, mail_info->cc, 259);
	strncpy(tmp_data.bccAddr, mail_info->bcc, 259);
	strncpy(tmp_data.subject, mail_info->subject, 259);
	strncpy(tmp_data.datafile, datafile, 259);
	strncpy(tmp_data.attachment, attach, 259);
	tmp_data.affixflag = affixflag;
	strncpy(tmp_data.mid, mid, 1023);
	
	tmp_data.p_data.proType = mail_info->mail_num;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBMAIL, (void *)&tmp_data, sizeof(tmp_data));
}

void write_oracle_db_cookieinfo(Mail_info *mail_info)
{
	time_t  timeVal;
	time(&timeVal);

	const char * server_C304;
	const char * database_C304;
	const char * user_C304;
	const char * password_C304;
	int          Cookie;
	const char* configfile = "/LzSystem/CookieDevice.xml";
	if(access(configfile, F_OK) != 0)
	{
		LOG_ERROR("CookieDevice.xml not exist!\n");
		return;
	} 
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if (!doc) 
	{
		LOG_ERROR("Read configure file failed!\n");
		return;
	}
	curNode = xmlDocGetRootElement(doc);
	if (!curNode) 
	{
		LOG_ERROR("Empty configure file!\n");
		xmlFreeDoc(doc);
		return;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST "CookieDevice")) 
	{
		LOG_ERROR("Root node error!\n");
		xmlFreeDoc(doc);
		return;
	}
	xmlChar* xdbServer = NULL;
	xmlChar* xdatabase = NULL;
	xmlChar* xdbUser = NULL;
	xmlChar* xdbPassword = NULL;
	xmlChar* xcookie = NULL;
	itemNode = curNode->xmlChildrenNode;
	while (itemNode) 
	{
		if (itemNode->type != XML_ELEMENT_NODE) 
		{
			itemNode = itemNode->next;
			continue;
		}
		if (!xmlStrcmp(itemNode->name, BAD_CAST "dbServer")) 
		{
			xdbServer = xmlNodeGetContent(itemNode);
			server_C304 = (const char *)xdbServer;				
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "database")) 
		{
			xdatabase = xmlNodeGetContent(itemNode);
			database_C304 = (const char *)xdatabase;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbUser"))
		{
			xdbUser = xmlNodeGetContent(itemNode);
			user_C304 =  (const char *)xdbUser;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbPassword")) 
		{
			xdbPassword = xmlNodeGetContent(itemNode);			
			password_C304 = (const char *)xdbPassword;
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "cookie")) 
		{
			xcookie = xmlNodeGetContent(itemNode);
			const char * tmpCookie= (const char *)xcookie;
			Cookie = atoi(tmpCookie);
		}
		itemNode = itemNode->next;
	}	
	xmlFreeDoc(doc);
	if(Cookie == 1){
		//printf("cookie into DB ...\n");
		clear_unwanted_chars(mail_info->to, 2600);
		clear_from(mail_info->to);
		makeStr(mail_info->to);
		//char * str = "等待收取";
		//char * state = GBK2UTF8_mail(str, strlen(str));
		char * state = "等待收取";
		char * sql = (char *)malloc(1024 * 64);
		memset(sql, 0, 1024 * 64);
		
#if 0  //zhangzm	MYSQL cookie
		sprintf(sql,
				"insert into data_collection(emailAccount,cookie,sendtime,remark,isAvil,state) values ('%s','%s',FROM_UNIXTIME(%lu),FROM_UNIXTIME(%lu),%d,'%s')",
				mail_info->to,
				mail_info->cookie_data,
				timeVal,
				timeVal,
				1,
				state
			);
		
		//printf("%s\n", sql);
		//printf("cookie_server : %s\n", server_C304);
		MYSQL * conn = mysql_init(NULL);
		if (!mysql_real_connect(conn, server_C304,user_C304, password_C304, database_C304, 0, NULL, 0))
		{ 
			fprintf(stderr, "mysql error %d:%s\n", mysql_errno(conn),mysql_error(conn));
			return;
		}
		mysql_query(conn,"SET NAMES utf8");
		int res = mysql_query(conn, sql);
		if(res)
		{
			fprintf(stderr,"Insert error %d: %s\n",mysql_errno(conn),mysql_error(conn));
			return;
		}
	
		mysql_close(conn);
#endif
		free(sql);
		sql = NULL;
	}
}

void UpdateAttach(char * filename, char * mid)
{
#if 0  //zhangzm
	//printf("UpdateAttach ...\n");
	char mid_tmp[MAX_ID_LEN + 3] = "0";
	sprintf(mid_tmp, "%%%s%%", mid);

	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return;

	char * sql = (char *)malloc(1024 * 64);
	memset(sql, 0, 1024 * 64);
	
	sprintf(sql,
			"update data_collection set mail_attachment=concat(mail_attachment,'|','%s'), affix_flag = 1 where mail_id like '%s'",
			filename,
			mid_tmp
		   );

	sqlConn_->SetSql(sql);
	sqlConn_->DoSql();

	free(sql);
	sql = NULL;
#endif
}

void UpdateAttachNew(char * filename, char * name, char * mid)
{
#if 0  //zhangzm
	if(strlen(mid)<=0) return;
	//printf("UpdateAttachNew ...\n");
	
	char mid_tmp[MAX_ID_LEN + 3] = "0";
	sprintf(mid_tmp, "%%%s%%", mid);

	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return;
	
	char * sql = (char *)malloc(1024 * 64);
	memset(sql, 0, 1024 * 64);
	
	sprintf(sql,
			"update data_collection set mail_attachment = concat(mail_attachment, '|', '%s'), attachment_name = case ifnull(attachment_name,'') when '' then '%s' else concat(attachment_name,'|','%s') END, affix_flag = 1 where mail_id like '%s'",
			filename,
			name,
			name,
			mid_tmp
		   );

	sqlConn_->SetSql(sql);
	sqlConn_->DoSql();
	
	free(sql);
	sql = NULL;
#endif
}

void UpdateAttachNew_m(char * filename, char * name, char * mid)
{
#if 0  //zhangzm
	//printf("UpdateAttachNew_m ...\n");
	char mid_tmp[MAX_ID_LEN + 3] = "0";
	sprintf(mid_tmp, "%%%s%%", mid);

	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return;
	
	char * sql = (char *)malloc(1024 * 64);
	memset(sql, 0, 1024 * 64);
	
	sprintf(sql,
			"update data_collection set attachment = concat(attachment, '|', '%s'), attachmentname = case ifnull(attachmentname,'') when '' then '%s' else concat(attachmentname,'|','%s') END, affixflag = 1 where mid like '%s'",
			filename,
			name,
			name,
			mid_tmp
		   );

	sqlConn_->SetSql(sql);
	sqlConn_->DoSql();

	free(sql);
	sql = NULL;
#endif
}

void write_oracle_db_password(int object_id, Mail_info *mail_info)
{
	//printf("password into DB ...\n");
	unsigned short sport = ntohs(mail_info->source_port);
	unsigned short dport = ntohs(mail_info->dest_port);
	unsigned char *p = mail_info->client_mac;
	
	int type = 202;
	if(mail_info->mail_num == 301 || mail_info->mail_num == 303 || mail_info->mail_num == 304 || mail_info->mail_num == 308 || mail_info->mail_num == 305 || mail_info->mail_num == 310 || mail_info->mail_num == 313 || mail_info->mail_num == 306)
		type = 203;//type = 701;
	
	makeStr(mail_info->username);
	/*write webaccount data to shared memory, by zhangzm*/
	WEBACCOUNT_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = (unsigned int)object_id;
	tmp_data.p_data.readed = 0;
	ulong_to_ipstr(mail_info->source_ip, tmp_data.p_data.clientIp);
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
	sprintf(tmp_data.p_data.clientPort, "%d", sport);
	ulong_to_ipstr(mail_info->dest_ip, tmp_data.p_data.serverIp);
	sprintf(tmp_data.p_data.serverPort, "%d", dport);
	
	tmp_data.p_data.captureTime = mail_info->cap_time;
	strncpy(tmp_data.url, mail_info->url, 255);
	strncpy(tmp_data.username, mail_info->username, 64);
	strncpy(tmp_data.password, mail_info->passwd, 64);
	
	tmp_data.p_data.proType = type;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

void write_oracle_db_password_m(int object_id, Mail_info *mail_info)
{
	//printf("password_m into DB ...\n");
    unsigned short sport=ntohs(mail_info->source_port);
    unsigned short dport=ntohs(mail_info->dest_port);
    unsigned char *p=mail_info->client_mac;
	
	int type = 201;
	/*if(mail_info->mail_num == 301 || mail_info->mail_num == 303 || mail_info->mail_num == 304 || mail_info->mail_num == 308 || mail_info->mail_num == 305 || mail_info->mail_num == 310 || mail_info->mail_num == 313)
		type = 701;*/
	
	makeStr(mail_info->username);
	/*write webaccount data to shared memory, by zhangzm*/
	WEBACCOUNT_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));

	tmp_data.p_data.clueid = (unsigned int)object_id;
	tmp_data.p_data.readed = 0;
	ulong_to_ipstr(mail_info->source_ip, tmp_data.p_data.clientIp);
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
	sprintf(tmp_data.p_data.clientPort, "%d", sport);
	ulong_to_ipstr(mail_info->dest_ip, tmp_data.p_data.serverIp);
	sprintf(tmp_data.p_data.serverPort, "%d", dport);

	tmp_data.p_data.captureTime = mail_info->cap_time;
	strncpy(tmp_data.url, mail_info->url, 255);
	strncpy(tmp_data.username, mail_info->username, 64);
	strncpy(tmp_data.password, mail_info->passwd, 64);

	tmp_data.p_data.proType = type;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

int get_mac_str(unsigned char *p, char *mac_string)
{
	sprintf(mac_string, "%02x-%02x-%02x-%02x-%02x-%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
}

int clear_unwanted_chars(char *str, size_t max_len)
{
	size_t len = strlen(str);
	int i, m = 0, n = 0;
	unsigned char ch;

	if (len > max_len)
		len = max_len;

	str[len] = 0;
	if (len == 0 || (str[len - 1] & 0x80) == 0x00) {
		return 0;
	}

	for (i = len - 1; i >= 0; i--) {
		ch = str[i];
		if (ch >= 0xc0) {
			for (m = 0; m <= 8; m++) {
				if (ch >= 0x80)
					ch <<= 1;
				else 
					break;
			}
			if (m - 1 > n) {
				str[i] = 0;
			}
			return 0;
		} else if (ch > 0x80) {
			n++;
		} else {
			return -1;
		}
	}
	return -1;
}

int get_recv_clue_content(Mail_info *mail_info, char *clue_content, size_t size)
{
	int i;
	char *p = mail_info->to;
	int have_read_cc = 0;

	for (i = 0; i < size; i++, p++) {
		if (*p == 0)
			if (!have_read_cc)
				p = mail_info->cc;
			else
				break;
		clue_content[i] = *p;
	}
	
	clue_content[i] = 0;
}

void * GetGmail(void * threadVoid)
{
	GMAILNODE * gmail = (GMAILNODE *)threadVoid;
	
	//LOG_INFO("gmail username : %s\n", gmail->gmailUserName);
	//LOG_INFO("gmail password : %s\n", gmail->gmailPassWord);
	
	int sockfd;
	struct hostent *host;
	struct sockaddr_in serv_addr;
	int iLength;
	char buf[MAXDATASIZE];
	
// 	printf("C302ServerIp : %s\n", C302ServerIp);
// 	printf("C302Serverport : %d\n", C302Serverport);
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		LOG_ERROR("socket error\n");
		return NULL;
	}
	//printf("socket succes !\n");
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(C302Serverport);
	//serv_addr.sin_addr = *((struct in_addr *)host->h_addr);
	serv_addr.sin_addr.s_addr = inet_addr(C302ServerIp);
	bzero(&(serv_addr.sin_zero),8);
	if (connect(sockfd, (struct sockaddr *)&serv_addr,sizeof(struct sockaddr))==-1)
	{
		perror("connect error");
		return NULL;
	}
	//printf("connecting succes !\n");
	memset(buf, 0, MAXDATASIZE);
	iLength = recv(sockfd, buf, MAXDATASIZE, 0);
	
	send(sockfd, gmail->gmailUserName, strlen(gmail->gmailUserName), 0);
	
	memset(buf, 0, MAXDATASIZE);
	iLength = recv(sockfd, buf, MAXDATASIZE, 0);
	
	send(sockfd, gmail->gmailPassWord, strlen(gmail->gmailPassWord), 0);
	
	memset(buf, 0, MAXDATASIZE);
	iLength = recv(sockfd, buf, MAXDATASIZE, 0);
	
	close(sockfd);
}

int write_xml(Mail_info *mail_info)
{
	char source_port[10] = {0}, dest_port[10] = {0};
	unsigned short int source = ntohs(mail_info->source_port);
	unsigned short int dest = ntohs(mail_info->dest_port);
	char mac_string[MAX_MAC_STR_LEN + 1] = {0};
	char writepath[MAX_PATH_LEN + 1] = {0};
	char capture_time[MAX_TIME_LEN + 1] = {0};
	char datafile_path[MAX_PATH_LEN + 1] = {0};
	char *tmp_str = NULL;
	int  type = 0;
	char ctype[2] = {0};
	int object_id = 0;
	sprintf(source_port, "%d", source);
	sprintf(dest_port, "%d", dest);
	snprintf(capture_time, MAX_TIME_LEN, "%lu", time(NULL));

	get_mac_str(mail_info->client_mac, mac_string);
	if (mail_info->save_path[0] != 0) 
	{
		snprintf(datafile_path, MAX_PATH_LEN, "%s/mail.xml", mail_info->save_path);
	} 
	else 
	{
		strcpy(mail_info->save_path, mail_data_path);
		datafile_path[0] = 0;
	}

	clear_unwanted_chars(mail_info->subject, 260);
	
	char attachs_path[MAX_ATTA_PATH_LEN + 1] = {0};
	char attachs_name[MAX_ATTA_PATH_LEN + 1] = {0};
	char temp_attachs_path[MAX_ATTA_PATH_LEN + 1] = {0};
	char temp_attachs_name[MAX_ATTA_PATH_LEN + 1] = {0};
	Attachment *attachment = mail_info->attach;
	if (attachment != NULL)
		strncpy(attachs_path, mail_info->save_path, MAX_ATTA_PATH_LEN);
    
	while (attachment != NULL) 
	{	
		tmp_str = conv_xml_symbol(attachment->loc_name);//lihan
		if (tmp_str != NULL)
		{
			snprintf(temp_attachs_path, MAX_ATTA_PATH_LEN, "%s/%s", attachs_path, tmp_str);//lihan 2017.3.23
			strcpy(attachs_path, temp_attachs_path);
			//attachment = attachment->next;
			free(tmp_str);
			tmp_str = NULL;
		}
		
		tmp_str = conv_xml_symbol(attachment->loc_name);
		if (tmp_str == NULL)
			continue;
        
		if (strlen(attachs_name) == 0)
			snprintf(temp_attachs_name, MAX_ATTA_PATH_LEN, "%s", tmp_str);
		else
			snprintf(temp_attachs_name, MAX_ATTA_PATH_LEN, "%s/%s", attachs_name, tmp_str);//lihan

		strcpy(attachs_name, temp_attachs_name);
		attachment = attachment->next;
		free(tmp_str);
		tmp_str = NULL;
	}

	unsigned short mtype = mail_info->mail_type & 0x00F0;
	char clue_content[MAX_CLUE_CONTENT_LEN + 1] = {0};
	int res;
	
	char Mac_Str[20] = {0};
	unsigned char *strMac = mail_info->client_mac;
	sprintf(Mac_Str, "%02x-%02x-%02x-%02x-%02x-%02x", strMac[0], strMac[1], strMac[2], strMac[3], strMac[4], strMac[5]);

	struct in_addr addr;
	addr.s_addr = mail_info->source_ip;
	object_id = get_clue_id(Mac_Str, inet_ntoa(addr));
	
	//LOG_INFO("Mac_Str : %s\n", Mac_Str);

	if (mtype == 0x0020 || mtype == 0x0030)
	{
#ifdef VPDNLZ
		object_id = GetObjectId2(mail_info->source_ip,mail_info->pppoe);
#else
		//object_id = GetObjectId(Mac_Str);
#endif
		type = 3;
		ctype[0] = '3';
	}
	else if(mtype == 0x0040)
	{
#ifdef VPDNLZ
		object_id = GetObjectId2(mail_info->source_ip,mail_info->pppoe);
#endif
		type = 4;
		ctype[0] = '4';
	}
	else if(mtype == 0x0080)
	{
#ifdef VPDNLZ
		object_id = GetObjectId2(mail_info->source_ip,mail_info->pppoe);
#endif
		type = 5;
		ctype[0] = '5';
	}
	else
    {
		if (mail_info->from[0] != 0)
		{
#ifdef VPDNLZ
			object_id = GetObjectId2(mail_info->source_ip,mail_info->pppoe);
#else
			//object_id = GetObjectId(Mac_Str);
#endif
			type = 2;
			ctype[0] = '2';
		} 
		else 
		{
#ifdef VPDNLZ
			object_id = GetObjectId2(mail_info->source_ip,mail_info->pppoe);
#else
			//object_id = GetObjectId(Mac_Str);
#endif
			type = 1;
			ctype[0] = '1';
			
			//LOG_INFO("****** username ******\n%s\n", mail_info->username);
			write_oracle_db_password(object_id, mail_info);
			
			//if(strstr(mail_info->username, "@gmail.com") && ControlC302 == 1)
			if(ControlC302 == 1 && (strstr(mail_info->username, "@gmail") || 
						 strstr(mail_info->username, "@qq") || 
						 strstr(mail_info->username, "@163") || 
						 strstr(mail_info->username, "@126") || 
						 strstr(mail_info->username, "@yeah")))
			{
				GMAILNODE * gmail = (GMAILNODE *)malloc(sizeof(GMAILNODE));
				memset(gmail->gmailUserName, 0, MAX_UN_LEN + 1);
				memset(gmail->gmailPassWord, 0, MAX_UN_LEN + 1);
				memcpy(gmail->gmailUserName, mail_info->username, strlen(mail_info->username));
				gmail->gmailUserName[strlen(mail_info->username)] = '\0';
				memcpy(gmail->gmailPassWord, mail_info->passwd, strlen(mail_info->passwd));
				gmail->gmailPassWord[strlen(mail_info->passwd)] = '\0';
				
				pthread_t Thread_i_tid;
				pthread_create(&Thread_i_tid, NULL, GetGmail, (void *)gmail);
			}
			
			return 0;
		}
	}
	
	//LOG_INFO("objectID : %d\n", object_id);
	write_oracle_db_webmail(object_id, mail_info, datafile_path, attachs_path, attachs_name, type);
}

int write_xml_m(Mail_info *mail_info)
{
	char source_port[10] = {0}, dest_port[10] = {0};
	unsigned short int source = ntohs(mail_info->source_port);
	unsigned short int dest = ntohs(mail_info->dest_port);
	char mac_string[MAX_MAC_STR_LEN + 1] = {0};
	char writepath[MAX_PATH_LEN + 1] = {0};
	char capture_time[MAX_TIME_LEN + 1] = {0};
	char datafile_path[MAX_PATH_LEN + 1] = {0};
	char *tmp_str = NULL;
	int  type = 0;
	char ctype[2] = {0};
	int object_id = 0;
	sprintf(source_port, "%d", source);
	sprintf(dest_port, "%d", dest);
	snprintf(capture_time, MAX_TIME_LEN, "%lu", time(NULL));

	get_mac_str(mail_info->client_mac, mac_string);
	if (mail_info->save_path[0] != 0) 
	{
		snprintf(datafile_path, MAX_PATH_LEN, "%s/mail.xml", mail_info->save_path);
	} 
	else 
	{
		strcpy(mail_info->save_path, mail_data_path);
		datafile_path[0] = 0;
	}

	clear_unwanted_chars(mail_info->subject, 260);
	
	char attachs_path[MAX_ATTA_PATH_LEN + 1] = {0};
	char attachs_name[MAX_ATTA_PATH_LEN + 1] = {0};
	char temp_attachs_path[MAX_ATTA_PATH_LEN + 1] = {0};
	char temp_attachs_name[MAX_ATTA_PATH_LEN + 1] = {0};
	Attachment *attachment = mail_info->attach;
	if (attachment != NULL)
		strncpy(attachs_path, mail_info->save_path, MAX_ATTA_PATH_LEN);
	while (attachment != NULL) 
	{
		tmp_str = conv_xml_symbol(attachment->loc_name);//lihan 4.12
		if (tmp_str != NULL)
		{
			snprintf(temp_attachs_path, MAX_ATTA_PATH_LEN, "%s/%s", attachs_path, tmp_str);//lihan
			//printf("temp_attachs_path : %s\n", temp_attachs_path);
			strcpy(attachs_path, temp_attachs_path);
			//printf("attachs_path : %s\n", attachs_path);
			//attachment = attachment->next;
			free(tmp_str);
			tmp_str = NULL;
		}
		
		tmp_str = conv_xml_symbol(attachment->loc_name);
		if (tmp_str == NULL)
			continue;
		if (strlen(attachs_name) == 0)
			snprintf(temp_attachs_name, MAX_ATTA_PATH_LEN, "%s", tmp_str);
		else
			snprintf(temp_attachs_name, MAX_ATTA_PATH_LEN, "%s/%s", attachs_name, tmp_str);//lihan
		//printf("temp_attachs_name : %s\n", temp_attachs_name);
		strcpy(attachs_name, temp_attachs_name);
		//printf("attachs_name : %s\n", attachs_name);
		attachment = attachment->next;
		free(tmp_str);
		tmp_str = NULL;
	}

	unsigned short mtype = mail_info->mail_type & 0x00F0;
	char clue_content[MAX_CLUE_CONTENT_LEN + 1];
	int res;
	
	char Mac_Str[20] = {0};
	unsigned char *strMac = mail_info->client_mac;
	sprintf(Mac_Str, "%02x-%02x-%02x-%02x-%02x-%02x", strMac[0], strMac[1], strMac[2], strMac[3], strMac[4], strMac[5]);

	struct in_addr addr;
	addr.s_addr = mail_info->source_ip;
	object_id = get_clue_id(Mac_Str, inet_ntoa(addr));
	
	//LOG_INFO("Mac_Str_m : %s\n", Mac_Str);

	if (mtype == 0x0020 || mtype == 0x0030)
	{
		//object_id = GetObjectId(Mac_Str);
		type = 3;
		ctype[0] = '3';
	}
	else
	{
		if (mail_info->from[0] != 0)
		{
			//object_id = GetObjectId(Mac_Str);
			type=2;
			ctype[0]='2';
		} 
		else 
		{
			//object_id = GetObjectId(Mac_Str);
			type=1;
			ctype[0]='1';
			
			//LOG_INFO("****** username_m ******\n%s\n", mail_info->username);
			write_oracle_db_password_m(object_id, mail_info);
			
			//if(strstr(mail_info->username, "@gmail.com") && ControlC302 == 1)
			/*if(ControlC302 == 1 && (strstr(mail_info->username, "@gmail") || 
						 strstr(mail_info->username, "@qq") || 
						 strstr(mail_info->username, "@163") || 
						 strstr(mail_info->username, "@126") || 
						 strstr(mail_info->username, "@yeah")))
			{
				GMAILNODE * gmail = (GMAILNODE *)malloc(sizeof(GMAILNODE));
				memset(gmail->gmailUserName, 0, MAX_UN_LEN + 1);
				memset(gmail->gmailPassWord, 0, MAX_UN_LEN + 1);
				memcpy(gmail->gmailUserName, mail_info->username, strlen(mail_info->username));
				gmail->gmailUserName[strlen(mail_info->username)] = '\0';
				memcpy(gmail->gmailPassWord, mail_info->passwd, strlen(mail_info->passwd));
				gmail->gmailPassWord[strlen(mail_info->passwd)] = '\0';
				
				pthread_t Thread_i_tid;
				pthread_create(&Thread_i_tid, NULL, GetGmail, (void *)gmail);
			}*/
			
			return 0;
		}
	}
	
	//LOG_INFO("objectID_m : %d\n", object_id);
	
	write_oracle_db_webmail_m(object_id, mail_info, datafile_path, attachs_path, attachs_name, type);
}

void write_to_file(Mail_info *mail_info)
{
	char *tmp_str = NULL;
	char writepath[MAX_PATH_LEN + 1] = {0};
	size_t len;

	unsigned short lowtype = mail_info->mail_type & 0x00ff;
	if (lowtype != 32)
	{
		tmp_str = conv_xml_symbol(mail_info->to);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->to, tmp_str, MAX_TO_LEN);
		mail_info->to[MAX_TO_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->cc);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->cc, tmp_str, MAX_CC_LEN);
		mail_info->cc[MAX_CC_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->bcc);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->bcc, tmp_str, MAX_BCC_LEN);
		mail_info->bcc[MAX_BCC_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->subject);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->subject, tmp_str, MAX_SUBJ_LEN);
		mail_info->subject[MAX_SUBJ_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;
    }
	
	if (mail_info->content != NULL)
	{
		tmp_str = clear_html_symbol(mail_info->content);	
		free(mail_info->content);
		//mail_info->content = NULL;
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	else
	{
		return;
	}

	clear_unwanted_chars(mail_info->subject, MAX_SUBJ_LEN);

	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL, attach_node = NULL;
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "mail");
	xmlDocSetRootElement(doc, root_node);

	xmlNewChild(root_node, NULL, BAD_CAST "from", BAD_CAST mail_info->from);
	xmlNewChild(root_node, NULL, BAD_CAST "to", BAD_CAST mail_info->to);
	xmlNewChild(root_node, NULL, BAD_CAST "cc", BAD_CAST mail_info->cc);
	xmlNewChild(root_node, NULL, BAD_CAST "bcc", BAD_CAST mail_info->bcc);
	xmlNewChild(root_node, NULL, BAD_CAST "time", BAD_CAST mail_info->sent_time);
	xmlNewChild(root_node, NULL, BAD_CAST "subject", BAD_CAST mail_info->subject);
	if (mail_info->content != NULL)
		xmlNewChild(root_node, NULL, BAD_CAST "content", BAD_CAST mail_info->content);
	else
		xmlNewChild(root_node, NULL, BAD_CAST "content", BAD_CAST "unkown");

	attach_node = xmlNewNode(NULL, BAD_CAST "attachment");
	xmlAddChild(root_node, attach_node);
	Attachment *attachment = mail_info->attach;
	while (attachment != NULL) 
	{
		tmp_str = conv_xml_symbol(attachment->loc_filename);
		if (tmp_str == NULL)
			continue;
		xmlNewChild(attach_node, NULL, BAD_CAST "filepath", BAD_CAST tmp_str);
		free(tmp_str);
		tmp_str = NULL;
		attachment = attachment->next;
	}

	sprintf(writepath, "%s/mail.xml", mail_info->save_path);
	xmlSaveFormatFileEnc(writepath, doc, "UTF-8", 1);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	write_xml(mail_info);	
	clear_tmp_file();
}

void write_to_file_m(Mail_info *mail_info)
{//printf("\nwrite_to_file\n");
	char *tmp_str = NULL;
	char writepath[MAX_PATH_LEN + 1] = {0};
	size_t len;

	unsigned short lowtype = mail_info->mail_type & 0x00ff;
	if(lowtype != 32)
	{
		tmp_str = conv_xml_symbol(mail_info->to);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->to, tmp_str, MAX_TO_LEN);
		mail_info->to[MAX_TO_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->cc);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->cc, tmp_str, MAX_CC_LEN);
		mail_info->cc[MAX_CC_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->bcc);
		if (tmp_str == NULL)
			return;
		strncpy(mail_info->bcc, tmp_str, MAX_BCC_LEN);
		mail_info->bcc[MAX_BCC_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;

		tmp_str = conv_xml_symbol(mail_info->subject);
		if (tmp_str == NULL)
			return;
        
		strncpy(mail_info->subject, tmp_str, MAX_SUBJ_LEN);
		htmldecode_full(mail_info->subject, mail_info->subject);
		mail_info->subject[MAX_SUBJ_LEN] = 0;
		free(tmp_str);
		tmp_str = NULL;
    }

    if (mail_info->content != NULL)
    {
    	tmp_str = clear_html_symbol(mail_info->content);
    	free(mail_info->content);
    	mail_info->content = tmp_str;
    	tmp_str = NULL;
    	htmldecode_full(mail_info->content, mail_info->content);
    }
	else
	{
		return;
	}

	clear_unwanted_chars(mail_info->subject, MAX_SUBJ_LEN);

	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL, attach_node = NULL;
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "mail");
	xmlDocSetRootElement(doc, root_node);

	xmlNewChild(root_node, NULL, BAD_CAST "from", BAD_CAST mail_info->from);
	xmlNewChild(root_node, NULL, BAD_CAST "to", BAD_CAST mail_info->to);
	xmlNewChild(root_node, NULL, BAD_CAST "cc", BAD_CAST mail_info->cc);
	xmlNewChild(root_node, NULL, BAD_CAST "bcc", BAD_CAST mail_info->bcc);
	xmlNewChild(root_node, NULL, BAD_CAST "time", BAD_CAST mail_info->sent_time);
	xmlNewChild(root_node, NULL, BAD_CAST "subject", BAD_CAST mail_info->subject);
	if (mail_info->content != NULL)
		xmlNewChild(root_node, NULL, BAD_CAST "content", BAD_CAST mail_info->content);
	else
		xmlNewChild(root_node, NULL, BAD_CAST "content", BAD_CAST "unkown");

	attach_node = xmlNewNode(NULL, BAD_CAST "attachment");
	xmlAddChild(root_node, attach_node);
	Attachment *attachment = mail_info->attach;
	while (attachment != NULL) 
	{
		tmp_str = conv_xml_symbol(attachment->loc_filename);
		if (tmp_str == NULL)
			continue;
		xmlNewChild(attach_node, NULL, BAD_CAST "filepath", BAD_CAST tmp_str);
		free(tmp_str);
		tmp_str = NULL;
		attachment = attachment->next;
	}

	sprintf(writepath, "%s/mail.xml", mail_info->save_path);
	xmlSaveFormatFileEnc(writepath, doc, "UTF-8", 1);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	write_xml_m(mail_info);
	clear_tmp_file();
}

int clear_tmp_file()
{
	static time_t last_clear_time = 0;
	DIR *dir;
	struct dirent *files;
	struct stat st;
	time_t time_now = time(NULL);
	char filepath[MAX_PATH_LEN + 1];
	int result;

	if (time_now - last_clear_time < 72000)
		return 0;

	dir = opendir(mail_temp_path);
	if (dir == NULL)
		LOG_WARN("webmail:clear_tmp_file(): opendir() return error\n");

	while ((files = readdir(dir)) != NULL) {
		if (!strcmp(files->d_name, ".") || !strcmp(files->d_name ,".."))
			continue;
		snprintf(filepath, MAX_PATH_LEN, "%s/%s", mail_temp_path, files->d_name);
		result = stat(filepath, &st);
		if (result == -1)
			continue;
		if (time_now - st.st_atime > 72000)
			unlink(filepath);
	}
	closedir(dir);
	last_clear_time = time_now;
}


char *memfind(char *str, char *substr, size_t n)
{
	size_t i, len;
	char *p = str;
	char *p1 = NULL;
	char *p2 = NULL;

	if (str == NULL || substr == NULL)
		return NULL;
        if (n<strlen(substr)) return NULL;
	len = n - strlen(substr) + 1;
	for (i = 0; i < len; i++) 
    {
		if (*p != *substr) 
        {
			p++;
			continue;
		}

		p1 = substr;
		p2 = p;
		while (*p1 != 0) 
        {
			if (*(++p2) != *(++p1))
				break;
		}
		if (*p1 == 0) 
        {
			return p;
		}
		p++;
	}
	return NULL;
}

int delete_attach(Attach_info *attach_info)
{
	if (attach_info->ok_data != NULL)
	{
		free(attach_info->ok_data);
		attach_info->ok_data = NULL;
	}
	if (attach_info->path_of_sender != NULL)
	{
		free(attach_info->path_of_sender);
		attach_info->path_of_sender = NULL;
	}
	free(attach_info);
	attach_info = NULL;
}

void get_from(char *from,unsigned int sourceip)
{
	int i = 6;
    time_t timeval;
	while(i){
		if(fromarray[i - 1].ip == sourceip){
			strcpy(from, fromarray[i - 1].from);
			break;
		}
		i--;
	}
	if (!i) {
        time(&timeval);
		sprintf(from, "unkown_%lu",timeval);
	}
}

int insert_array(char *username, unsigned int source_ip)
{
     static int in = 0;
     if(in>=0 && in<=4){
		 strcpy(fromarray[in].from, username);
		 fromarray[in].ip=source_ip;
     }
	 in=(++in)%5;
}

void equal_convert(char * src,int len,char * dest)
{
	int i=0;
	for(i=0;i<len;i++)
	{
		if(*src=='=')
		{
			int x=0;
			int x1=*(src+1);
			int x2=*(src+2);
			if(x1>='0'&&x1<='9') x=(x1-'0')*16;
			else if(x1>='a'&&x1<='z') x=(x1-'a'+10)*16;
			else if(x1>='A'&&x1<='Z') x=(x1-'A'+10)*16;
			else return;
			if(x2>='0'&&x2<='9') x=(x2-'0')+x;
			else if(x2>='a'&&x2<='z') x=(x2-'a'+10)+x;
			else if(x2>='A'&&x2<='Z') x=(x2-'A'+10)+x;
			else return;
			*dest=x;
			dest++;
			src+=3;
			i+=2;
			continue;
		}
		*dest=*src;
		dest++;
		src++;
	}
	*dest=0;
}

/*int write_attach_down_2(Mail_info *mail_info)
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->recive_data;
	char *p2;
	char filename[MAX_FN_LEN] = "0";
	int len;
	unsigned int length;
	int is_chunk;
	char tmpname[MAX_FN_LEN] = "0";
	char *pzip_judge = NULL;
	char *p4=NULL;
	length=get_http_length_1(mail_info->recive_data);
	is_chunk=judge_chunk(mail_info->recive_data);
	p4 = strstr(p1,"\r\n\r\n");
	if (p4==NULL) return;
	unsigned int n=p4-p1;
	pzip_judge = memfind(p1,"Content-Encoding: gzip\r\n", n);
	int add_number=1;
	p2 = strstr(p1,"attachment; filename=\"");
	{
		if(p2==NULL)
			p2 = strstr(p1,"attachment;filename=\"");
		if(p2==NULL)
			return;
		else add_number=0;
	}
	p1 = p2;
	if (add_number==1)
	{
		p1 += 22;
	}
	else p1 += 21;
   
	p2 = strstr(p1,"\"\r\n");
	{
		if(p2==NULL)
			p2=strstr(p1,"\";\r\n");
		if (p2==NULL)
			return;
     
	}
	len = p2-p1;
	if(len>MAX_FN_LEN) len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,filename);
   
	p1 = strstr(p2, "\r\n\r\n");
	if(p1==NULL) return ;
	p1 +=4;
   
	char str_dir[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str_dir, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec,filename);
      
	int fd;
   
	fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
	if(!is_chunk)
	{
		write(fd, p1, length);
		close(fd);
	}
	else
	{
		p1=strstr(p1,"\r\n");
		if(p1==NULL) return -1;
		p1 += 2;
		if (pzip_judge)
		{//decomp zip
			decomp_gzip_2(p1,length,&mail_info->mail_data);
			if(mail_info->mail_data==NULL) return;
			p1=mail_info->mail_data;
			length=strlen(p1);
		}
     
		write(fd,p1,length);
		close(fd);
     
	}
   
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec, filename);
   
	UpdateAttach(str_file, mail_info->mail_id);
}*/

int write_attach_down_1(Mail_info *mail_info,unsigned int length, int is_chunk)
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->recive_data;
	char *p2;
	char filename[MAX_FN_LEN]="0";
	int len; 
	char tmpname[MAX_FN_LEN]="0"; 
	char *pzip_judge = NULL;
	char *p4 = NULL;
	if (p1==NULL) return -1;
	p4 = strstr(p1,"\r\n\r\n");
	if (p4==NULL) return -1;
	unsigned int n=p4-p1;
	pzip_judge = memfind(p1,"Content-Encoding: gzip\r\n", n);
	int add_number=1;
	p2 = strstr(p1,"attachment; filename=\"");
	if(p2==NULL)
	{
		p2 = strstr(p1,"attachment;filename=\"");
		if(p2==NULL)
		{
			p2 = strstr(p1,"; filename=\"");
			if(p2 == NULL)
				return -1;
			else add_number=2;
		}
		else add_number=0;
	}
	p1 = p2;
	if (add_number==1) p1 += 22;
	else if(add_number==2) p1 += 12;
	else p1 += 21;
	
	p2 = strstr(p1,"\"");
	{
// 		if(p2==NULL)
// 			p2=strstr(p1,"\";\r\n");
		if (p2==NULL)
			return -1;
	}
	len = p2-p1;
	if(len>MAX_FN_LEN) len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,filename);
	
	p1 = strstr(p2, "\r\n\r\n");
	if(p1==NULL) return -1;
	p1 +=4;
	
	char str_dir[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str_dir, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	
	int fd;
	
	fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
	if(!is_chunk)
	{
		if (pzip_judge)
		{//decomp zip
			decomp_gzip_2(p1,length,&mail_info->mail_data);
			if(mail_info->mail_data==NULL) return -1;
			p1=mail_info->mail_data;
			length=strlen(p1);
		}
		write(fd, p1, length);
		close(fd);
	}
	else
	{
		p1=strstr(p1,"\r\n");
		if(p1==NULL) return -1;
		p1 += 2;
		if (pzip_judge)
		{//decomp zip
			decomp_gzip_2(p1,length,&mail_info->mail_data);
			if(mail_info->mail_data==NULL) return -1;
			p1=mail_info->mail_data;
			length=strlen(p1);
		}
	
		write(fd,p1,length);
		close(fd);
	
	}
	
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu",tv.tv_sec, tv.tv_usec);
	
	//UpdateAttach(str_file, mail_info->mail_id);
	UpdateAttachNew(str_file, filename, mail_info->mail_id);
	//del_mail_node(mail_info);
	return 0;
}

int write_attach_down_2(Mail_info *mail_info,unsigned int length, int is_chunk)
{

   //printf(" \nnihao!\n");
   //printf("is_chunk = %d\n", is_chunk);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->recive_data;
	char *p2;
	char filename[MAX_FN_LEN]="0";
	int len;
	char tmpname[MAX_FN_LEN]="0"; 
	char *pzip_judge = NULL;
	char *p4 = NULL;
	if (p1==NULL) return -1;
	p4 = strstr(p1,"\r\n\r\n");
	if (p4==NULL) ;//return;
	unsigned int n=p4-p1;
	pzip_judge = strstr(p1,"Content-Encoding: gzip\r\n");
   //int add_number=1;
	p2 = strstr(p1,"attachment;filename=\"");
	if(p2 == NULL){
		p2 = strstr(p1,"attachment; filename=\"");
		if(p2!=NULL) p2+=1;
	}
	if(p2 == NULL){
		p2 = strstr(p1,"attachment; filename*=\"");         //sina downatt
		if(p2!=NULL) p2+=2;
	}
	if(p2!=NULL)
	{
		p2 += 21;
		if(!strncmp(p2,"UTF-8''",7))                     //sina downatt
			p2 += 7;
		p4 = strstr(p2,"\"\r\n");
		if(p4==NULL)
			p4 = strstr(p2,"\";\r\n");
		if(p4==NULL)
			p4 = strstr(p2,"\";");                   //gmail downatt
		len = p4-p2;
		if(len>MAX_FN_LEN)
			len=MAX_FN_LEN;
		if((strstr(p2,"=?UTF-8?B?")||strstr(p2,"=?UTF8?B?")||strstr(p2,"=?utf8?b?")) && !strncmp(p4-2,"?=",2))       //sina&yeah&sogou&gmail
		{
			int n = 11;
			char* i = strstr(p2,"=?UTF8?B?");
			if(i == NULL)
				i = strstr(p2,"=?utf8?b?");
			if(i == NULL){
				i = strstr(p2,"=?UTF-8?B?");
				i+=1;
				n = 12;
			}
			i+=9;
			char base64[MAX_FN_LEN]="0";
			strncpy(base64,i,len-n);
			base64[len-n]=0;
			memcpy(tmpname, Base2UTF8_mail(base64, len-n), len);
		}
		else if((strstr(p2,"=?utf8?q?")||strstr(p2,"=?UTF8?Q?")) && !strncmp(p4-2,"?=",2))       //sogou
		{
			regmatch_t pm[4];
			int ret = reg(p2,"=\\?(\\S+)\\?(q|Q)\\?(.+)\\?=.*?",pm,4);
			if(!ret)
			{
				char charset[15]={0};
				memcpy(charset,p2+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
				char * tmpsub2 = (char *)malloc(len+1);
				if(!tmpsub2) return -1;
				char ch=*(p2+pm[2].rm_so);
				if(ch=='q'||ch=='Q')
					equal_convert(p2+pm[3].rm_so,pm[3].rm_eo-pm[3].rm_so,tmpsub2);
				//printf(tmpsub2);
				code_convert(charset,"utf8",tmpsub2,strlen(tmpsub2),tmpname,100);
				free(tmpsub2);
				tmpsub2 = NULL;
			}
		}
		else
		{
			strncpy(tmpname,p2,len);
			tmpname[len] = 0;
		}
		strncpy(filename,tmpname,len);
		//printf("\ntmpname = %s",tmpname);
		htmldecode_full(tmpname,filename);
		//printf("filename = %s\n", filename);
		if(strstr(mail_info->recive_data,"charset=gbk")!=NULL)
		code_convert("gb2312","utf-8",tmpname,len,filename,MAX_FN_LEN);
		//printf("filename = %s\n", filename);
	}

	p1 = strstr(p1, "\r\n\r\n");
	if(p1==NULL)
		return -1;
	p1 +=4;

	char str_dir[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str_dir, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);

	int fd;

	//printf("\nlength = %d\n",length);
	if(!is_chunk)
	{
		fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
		write(fd, p1, mail_info->recive_length - 1000);
		close(fd);
		//printf("\nmail_info->recive_length = %d \np1 = %s\n",mail_info->recive_length - 1000,p1);
	}
	else
	{
		length = Chunked(mail_info);
		//length = mail_info->recive_length;
	//printf("length = %d\n",length);
		if (pzip_judge)
		{
       //printf("\nhow are you!");
			char *data = (char *)malloc(mail_info->recive_length*3);
			memset(data,0,mail_info->recive_length*3);
			decomp_gzip_2(mail_info->recive_data,mail_info->recive_length,&data);
			if(data == NULL) 
				return -1;
			free(mail_info->recive_data);
			mail_info->recive_data = data;
			length=strlen(mail_info->recive_data);
		}
		fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
     //printf("\nyesorno");
		write(fd,mail_info->recive_data,length);
		close(fd);
	}
   //printf("\nstr_dir = %s",str_dir);
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu",tv.tv_sec, tv.tv_usec);
   //printf("\nmail_info->mail_id = %s\n",mail_info->mail_id);
   //printf("\nstrlen(str_file) = %d",strlen(str_file)); 
   //printf("\nmail_info->source_port = %d",mail_info->source_port);
	mail_info->recive_data  == NULL;
	//UpdateAttach(str_file, mail_info->mail_id);
	if(mail_info->mail_type>>8 >= 0x81)
		UpdateAttachNew_m(str_file, filename, mail_info->mail_id);
	else
		UpdateAttachNew(str_file, filename, mail_info->mail_id);
   //del_mail_node(mail_info);
}

int write_attach_down_3(Mail_info *mail_info,unsigned int length, int is_chunk)
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->mail_data;
	char *p2;
	char filename[MAX_FN_LEN]="0";
	int len;
	char tmpname[MAX_FN_LEN]="0";
	char *pzip_judge = NULL;
	char *p3 = mail_info->recive_data;
	char *p4 = NULL;
	if (p3==NULL) return -1;
	pzip_judge = memfind(p1,"Content-Encoding: gzip\r\n", mail_info->mail_length);
	int add_number=1;
	p2 = strstr(p1,"attachment; filename=\"");
	if(p2==NULL)
	{
		p2 = strstr(p1,"attachment;filename=\"");
		if(p2==NULL)
			return -1;
		else
			add_number=0;
	}
	p1 = p2;
	if (add_number==1)
		p1 += 22;
	else
		p1 += 21;
	
	p2 = strstr(p1,"\"\r\n");
	{
		if(p2==NULL)
			p2=strstr(p1,"\";\r\n");
		if (p2==NULL)
			return -1;
	}
	len = p2-p1;
	if(len>MAX_FN_LEN) len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,filename);
	
	p4 = strstr(p3, "\r\n\r\n");
	if(p4==NULL) return -1;
	p4 +=4;
	
	char str_dir[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str_dir, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec,filename);
	
	int fd;
	
	fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
	if(!is_chunk)
	{
		if(pzip_judge)
		{
			decomp_gzip_2(p4,length,&mail_info->recive_data);
			if(mail_info->recive_data==NULL) return -1;
			p4=mail_info->recive_data;
			length=strlen(p4);
		}
		write(fd, p4, length);
		close(fd);
	}
	else
	{
		p4=strstr(p4,"\r\n");
		if(p4==NULL) return -1;
		p4 += 2;
		if (pzip_judge)
		{
			decomp_gzip_2(p4,length,&mail_info->recive_data);
			if(mail_info->recive_data==NULL) return -1;
			p4=mail_info->recive_data;
			length=strlen(p4);
		}
		write(fd,p4,length);
		close(fd);
	}
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec, filename);
	
	UpdateAttachNew(str_file,filename, mail_info->mail_id);
	return 0;
}

int write_attach_down(Mail_info *mail_info,unsigned int length, int is_chunk)
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->recive_data;
	char *p2;
	char filename[MAX_FN_LEN]="0";
	int len; 
	char tmpname[MAX_FN_LEN]="0"; 
	if(p1==NULL) return -1;
	p2 = strstr(p1,"attachment; filename=\"");
	if(p2==NULL)
	{
		p2= strstr(p1,"; filename=\"");
		if(p2 == NULL)
			return -1;
		p1 = p2;
		p1 += 12;
	}
	else
	{
		p1 = p2;
		p1 += 22;
	}
	p2 = strstr(p1,"\"\r\n");
	if(p2==NULL) return -1;
	len = p2-p1;
	if(len>MAX_FN_LEN) len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,filename);
	
	p1 = strstr(p2, "\r\n\r\n");
	if(p1==NULL) return -1;
	p1 +=4;
	
	char str[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec);
	
	int fd;
	
	fd = open(str, O_RDWR | O_CREAT, file_mode);
	if(!is_chunk)
	{
		write(fd, p1, length);
		close(fd);
	}
	else
	{
		p1=strstr(p1,"\r\n");
		if(p1==NULL) return -1;
		p1 += 2;
		write(fd,p1,length);
		close(fd);
	}
	
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec);
	
	//UpdateAttach(str_file, mail_info->mail_id);
	UpdateAttachNew(str_file, filename, mail_info->mail_id);
	//del_mail_node(mail_info);
	return 0;
}

void convert_contents(char * cont)
{
	char *p = cont,*q = cont;
	while(*p)
	{
		if(*p == '%')
		{
			if(*(p+1) == '2'&&*(p+2) == '2')
				*q = '\"';
			else 
				if(*(p+1) == '2'&&*(p+2) == '6')
					*q = '&';
			else 
				if(*(p+1) == '4'&&*(p+2) == '0')
					*q = '@';
			else 
				if(*(p+1) == '3'&&*(p+2) == 'C')
					*q = '<';
			else 
				if(*(p+1) == '3'&&*(p+2) == 'E')
					*q = '>';
			else 
				if(*(p+1) == '5'&&*(p+2) == 'C')
					*q = '\\';
			else 
				if(*(p+1) == '2'&&*(p+2) == 'C')
					*q = ',';
            		else 
				if(*(p+1) == '3'&&*(p+2) == 'B')
					*q = ';';
			else 
				if(*(p+1) == '5'&&*(p+2) == 'E')
					*q = '^';
			p+=3;
		}
		else
		{
			if(*p == '+')
				*q = ' ';
			else
				*q = *p;
			p++;
		}
		q++;
	}
	*q = '\0';
}

void down_contents(char * cont)
{
	char *p = cont,*q = cont;
	while(*p)
	{
		if(*p == '\\')
		{
			if(*(p+1) == '\"')
				*q = '\"';
			else 
				if(*(p+1) == 'r')
					*q = '\r';
			else 
				if(*(p+1) == 'n')
					*q = '\n';
			else 
				if(*(p+1) == 't')
					*q = '\t';
			p+=2;
		}
		else
		{
			*q = *p;
			p++;
		}
		q++;
	}
	*q = '\0';
}

void convert_time_to_string(int time,char *Srctime)
{
    time_t tmp_time = (time_t)time;
	struct tm *ptime=gmtime((const time_t*)&tmp_time);
	sprintf(Srctime,"%04d-%02d-%02d %02d:%02d:%02d",ptime->tm_year+1900,ptime->tm_mon+1,ptime->tm_mday,ptime->tm_hour+8,ptime->tm_min,ptime->tm_sec);
}

void get_send_time(char *Srctime, char *Sendtime)
{
	char *pstart = strstr(Srctime," ");
	pstart-=4;
	strncpy(Sendtime,pstart,4);
	strncat(Sendtime,"-",1);
	char *mon;
	pstart=strstr(Srctime,"-");
	pstart+=1;
	char *pend=strstr(pstart,"-");
	int len=pend-pstart;
	mon = (char *)malloc(len+1);
	memset(mon,0,len+1);
	memcpy(mon,pstart,len);
	//LOG_INFO("mon = %s\n",mon);
	if(strcmp(mon,"Jan") == 0)
		strncat(Sendtime,"01",2);
	else if(strcmp(mon,"Feb") == 0)
		strncat(Sendtime,"02",2);
	else if(strcmp(mon,"Mar") == 0)
		strncat(Sendtime,"03",2);
	else if(strcmp(mon,"Apr") == 0)
		strncat(Sendtime,"04",2);
	else if(strcmp(mon,"May") == 0)
		strncat(Sendtime,"05",2);
	else if(strcmp(mon,"Jun") == 0)
		strncat(Sendtime,"06",2);
	else if(strcmp(mon,"Jul") == 0)
		strncat(Sendtime,"07",2);
	else if(strcmp(mon,"Aug") == 0)
		strncat(Sendtime,"08",2);
	else if(strcmp(mon,"Sept") == 0)
		strncat(Sendtime,"09",2);
	else if(strcmp(mon,"Oct") == 0)
		strncat(Sendtime,"10",2);
	else if(strcmp(mon,"Nov") == 0)
		strncat(Sendtime,"11",2);
	else if(strcmp(mon,"Dec") == 0)
		strncat(Sendtime,"12",2);

	strncat(Sendtime,"-",1);
	strncat(Sendtime,Srctime,2);
	strncat(Sendtime," ",1);
	char *hour;
	pstart = strstr(Srctime," ");
	pstart+=1;
	pend = strstr(pstart,":");
	len =pend-pstart;
	hour =(char*)malloc(len);
	memset(hour,0,len);
	memcpy(hour,pstart,len);
	if(atoi(hour)<12)
	{
		sprintf(hour, "%d" , (atoi(hour)+12));
	}
	else
	{
		if(atoi(hour)>21)
			sprintf(hour, "%d" , (atoi(hour)-12));
		else
			sprintf(hour, "0%d", (atoi(hour)-12));
	}
	strncat(Sendtime,hour,2);
	pstart = strstr(Srctime,":");
	strncat(Sendtime,pstart,6);
}

char* Base2UTF8_mail(const char* base64, size_t len)
{
    //assert(base64 != NULL);
	if (base64 == NULL)
		return NULL;
	
    char *utf = NULL;
    utf = (char *)malloc(len);
    int utfLen = EVP_DecodeBlock((u_char*)utf, (const u_char*)base64, len);
    utf[utfLen]=0;
    if (utfLen <= 0 ) 
	{
		free(utf);
		utf = NULL;
        return NULL;
    }
    return utf;
}

void get_cookie(char *data, char *cookie)
{
	char *p1,*p2;
	p1 =strstr(data,"\r\nCookie: ");
	if(p1 == NULL)
		return;
	p1 += 10;
	p2 =strstr(p1,"\r\n");
	if(p2 == NULL)
		return;
	int len = p2-p1;
	memcpy(cookie,p1,len);
	cookie[len] = 0;
}

char* GBK2UTF8_mail(char* gbk, size_t len)
{
    //assert(gbk != NULL);
	if (gbk == NULL)
		return NULL;
	
    iconv_t cd;
    if ((cd  = iconv_open("UTF-8", "GB18030")) < 0) {
        LOG_ERROR("Get iconv handle failed!\n");
        return NULL;
    }
    size_t gbkLen;
    if (len == 0) {
        gbkLen = strlen(gbk);
    } else {
        gbkLen = len;
    }
    char** gbkPtr = &gbk;
    size_t utf8Len = gbkLen * 2;
    char* utf8 = (char *)malloc(utf8Len);
    memset(utf8, 0, utf8Len);
    char* utf8Ptr  = utf8;
    size_t res = iconv(cd, gbkPtr, &gbkLen, &utf8Ptr, &utf8Len);
    if (res < 0) {
        LOG_WARN("Convert failed!\n");
        free(utf8);
        utf8 = NULL;
    }
    iconv_close(cd);

    return utf8;
}

int charcmp_nosense(char c1, char c2)
{
	if(c1>='A' && c1<='Z') c1=c1+32;
	if(c2>='A' && c2<='Z') c2=c2+32;
	if(c1==c2) return 1;
	else return 0;
}
//不区分大小写查找字符串
char * strstr_2(char * s, char * sub)
{
	int len = strlen(sub);
	if(len==0) return s;
	int i;
	int f;
	while(*s)
	{
		if(charcmp_nosense(*s,*sub))
		{
			f=0;
			for(i=1;i<len;i++)
			{
				if(*(s+i)==0 || !charcmp_nosense(*(s+i),*(sub+i)))
				{
					f=1;break;
				}
			}
			if(!f) return s;
		}
		s++;
	}
	return NULL;
}

/***************************************************************************************************
Function name:  http_recive_attach
Describe :      combine HTTP and TCP response packets in the same stream
entry->status:
0x00 : init status
0x01 : find the complete http header
0x02 : TCP length format is "Transfer-Encoding: chunked", not "Content-Length"
0x04 : combine chunked data all the time in the same packet
0xfffffffb : combine chunked data uncompleted, need to combine date continued in the next packet
****************************************************************************************************/
int http_recive_attach(Attach_info *entry, char *data, int dataLen)
{
	if (!(entry->status&0x01))
	{
		char *p = strstr(data, "\r\n\r\n");
		if (p)
		{
			p += 4;
			if(entry->headerLen == 0)
			{
				entry->headerLen = p - data;
				entry->header = (char *)malloc(p - data + 1);
				if (!entry->header) 
                    return -1;
                
				memcpy(entry->header, data, p - data);
				entry->header[entry->headerLen] = 0;
			}
			else
			{
				entry->header = (char *)realloc(entry->header, entry->headerLen + (p-data) + 1);
				if (!entry->header) 
                    return -1;
                
				memcpy(entry->header + entry->headerLen, data, p - data);
				entry->headerLen += p-data;
				entry->header[entry->headerLen] = 0;
			}
            
			entry->status |= 1;
			char *p2 = strstr_2(entry->header, "\r\nTransfer-Encoding: chunked");
			if (p2)
			{
				entry->status |= 0x02;
				entry->body = (char *)malloc(1);
				entry->body[0] = 0;
				entry->status |= 0x04;
				char *p2 = strstr(p, "\r\n");
				while (p2)
				{
					if (p2+2 > data+dataLen) 
                        return 0;
                    
					unsigned int len = 0;
					char *p3 = NULL;
					for(p3=p; p3<p2; p3++)
					{
						if(*p3>='0' && *p3<='9')
                            len = len*16 + (*p3-'0');
						else if(*p3>='a' && *p3<='f')
                            len = len*16 + (*p3-'a'+10);
						else if(*p3>='A' && *p3<='F')
                            len = len*16 + (*p3-'A'+10);
						else 
                            break;
					}
                    
					if (len == 0)
					{
						entry->body[entry->bodyLen] = 0;
						return 1;
					}
                    
					p2 += 2;
					if(p2+len <= data+dataLen)
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if (!entry->body)
                            return -1;
                        
						memcpy(entry->body + entry->bodyLen, p2, len);
						entry->bodyLen += len;
						entry->bodyTotal += len;
						entry->status |= 0x04;
						p = p2 + len + 2;
						p2 = strstr(p, "\r\n");
						continue;
					}
					else
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if(!entry->body) 
                            return -1;
                        
						unsigned int slen = data + dataLen - p2;
						memcpy(entry->body + entry->bodyLen, p2, slen);
						entry->bodyTotal += len;
						entry->bodyLen += slen;
						entry->status &= 0xfffffffb;
						break;
					}
				}
			}
			else if(p2 = strstr_2(entry->header, "\r\nContent-Length: "))
			{
				p2 += 18;
				char *p3 = strstr(p2, "\r\n");
				char *p4 = NULL;
				unsigned int len = 0;
                
				while (*p2==' ')
                    p2++;
                
				for(p4=p2; p4<p3; p4++)
				{
					if(*p4>='0' && *p4<='9')
                        len = len*10 + (*p4-'0');
					else
                        break;
				}
                
				entry->bodyTotal = len;
                entry->bodyLen = dataLen - (p-data);
				entry->body = (char *)malloc(entry->bodyLen + 1);
				if (!entry->body) 
                    return -1;

                if (entry->bodyLen > 0)
				    memcpy(entry->body, p, entry->bodyLen);
                
				if (entry->bodyLen >= entry->bodyTotal)
				{
					entry->body[entry->bodyLen] = 0;
					return 1;
				}
			}
			else
			{
				return 1;
			}
		}
		else
		{
			if (entry->headerLen == 0)
			{
				entry->headerLen = dataLen;
				entry->header = (char* )malloc(dataLen);
				if(!entry->header) 
                    return -1;
                
				memcpy(entry->header, data, dataLen);
			}
			else
			{
				entry->header = (char *)realloc(entry->header, entry->headerLen + dataLen);
				memcpy(entry->header + entry->headerLen, data, dataLen);
				entry->headerLen += dataLen;
			}
		}
	}
	else
	{
		if (entry->status&0x02)
		{
			char *p = data;
			if (!(entry->status&0x04))
			{

				if (entry->bodyLen + dataLen < entry->bodyTotal)
				{
					memcpy(entry->body + entry->bodyLen, data, dataLen);
					entry->bodyLen += dataLen;
				}
				else
				{
					int offset = entry->bodyTotal - entry->bodyLen;
					memcpy(entry->body + entry->bodyLen, data, offset);
					entry->bodyLen = entry->bodyTotal;
					p = data + offset + 2;
					entry->status |= 0x04;
				}
			}
            
			if (entry->status&0x04)
			{
				char *p2 = NULL;
				while(*p=='\r'||*p=='\n') 
                    p++;
                
				p2 = strstr(p,"\r\n");
				while (p2)
				{
					if(p2+2 > data+dataLen) 
                        return 0;
                    
					unsigned int len = 0;
					char *p3 = NULL;
					for(p3=p; p3<p2; p3++)
					{
						if (*p3>='0' && *p3<='9') 
                            len = len*16 + (*p3-'0');
						else if (*p3>='a' && *p3<='f') 
                            len = len*16 + (*p3-'a'+10);
						else if (*p3>='A' && *p3<='F') 
                            len = len*16 + (*p3-'A'+10);
						else 
                            break;
					}
                    
					if (len == 0)
					{
						entry->body[entry->bodyLen] = 0;
						return 1;
					}
                    
					p2 += 2;
					if (p2+len <= data+dataLen)
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if (!entry->body) 
                            return -1;
                        
						memcpy(entry->body + entry->bodyLen, p2, len);
						entry->bodyLen += len;
						entry->bodyTotal += len;
						entry->status |= 0x04;
						p = p2 + len + 2;
						p2 = strstr(p,"\r\n");
						continue;
					}
					else
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if (!entry->body) 
                            return -1;
                        
						unsigned int slen = data + dataLen - p2;
						memcpy(entry->body + entry->bodyLen, p2, slen);
						entry->bodyTotal += len;
						entry->bodyLen += slen;
						entry->status &= 0xfffffffb;
						break;
					}
				}
			}
		}
		else
		{
            entry->body = (char *)realloc(entry->body, entry->bodyLen + dataLen + 1);
            if (!entry->body)
            {
                return -1;
            }
            
			memcpy(entry->body + entry->bodyLen, data, dataLen);
			entry->bodyLen += dataLen;
			if (entry->bodyLen >= entry->bodyTotal)
			{
				entry->body[entry->bodyLen] = 0;
				return 1;
			}
		}
	}
	return 0;
}

/***************************************************************************************************
Function name:  http_recive_mail
Describe :      combine HTTP and TCP response packets in the same stream
entry->status:
0x00 : init status
0x01 : find the complete http header
0x02 : TCP length format is "Transfer-Encoding: chunked", not "Content-Length"
0x04 : combine chunked data all the time in the same packet
0xfffffffb : combine chunked data uncompleted, need to combine date continued in the next packet
****************************************************************************************************/
int http_recive_mail(Mail_info *entry, char *data, int dataLen)
{
	if (!(entry->status&0x01))
	{
		char *p = strstr(data, "\r\n\r\n");
		if (p)
		{
			p += 4;
			if (entry->headerLen == 0)
			{
				entry->headerLen = p - data;
				entry->header = (char* )malloc(p - data + 1);
				if(!entry->header) 
                    return -1;
                
				memcpy(entry->header, data, p - data);
				entry->header[entry->headerLen] = 0;
			}
			else
			{
				entry->header = (char *)realloc(entry->header, entry->headerLen + (p - data) + 1);
				if(!entry->header) 
                    return -1;
                
				memcpy(entry->header + entry->headerLen, data, p - data);
				entry->headerLen += p-data;
				entry->header[entry->headerLen] = 0;
			}
            
			entry->status |= 0x01;
			char *p2 = strstr_2(entry->header, "\r\nTransfer-Encoding: chunked");
			if (p2)
			{
				entry->status |= 0x02;
				entry->body = (char *)malloc(1);
				entry->body[0] = 0;
				entry->status |= 0x04;
				char *p2 = strstr(p, "\r\n");
				while (p2)
				{
					if(p2 + 2 > data + dataLen) 
                        return 0;
                    
					unsigned int len = 0;
					char *p3 = NULL;
					for (p3=p; p3<p2; p3++)
					{
						if(*p3>='0' && *p3<='9') 
                            len = len*16 + (*p3-'0');
						else if(*p3>='a' && *p3<='f')
                            len = len*16 + (*p3-'a'+10);
						else if(*p3>='A' && *p3<='F')
                            len = len*16 + (*p3-'A'+10);
						else 
                            break;
					}
                    
					if (len == 0)
					{
						entry->body[entry->bodyLen] = 0;
						return 1;
					}
                    
					p2 += 2;
					if (p2+len <= data+dataLen)
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if (!entry->body) 
                            return -1;
                        
						memcpy(entry->body + entry->bodyLen, p2, len);
						entry->bodyLen += len;
						entry->bodyTotal += len;
						entry->status |= 0x04;
						p = p2 + len + 2;            // 2 is "0d 0a"
						p2 = strstr(p, "\r\n");
						continue;
					}
					else
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if(!entry->body)
                            return -1;
                        
						unsigned int slen = data + dataLen - p2;
						memcpy(entry->body + entry->bodyLen, p2, slen);
						entry->bodyTotal += len;
						entry->bodyLen += slen;
						entry->status &= 0xfffffffb;
						break;
					}
				}
			}
			else if(p2 = strstr_2(entry->header, "\r\nContent-Length: "))
			{
				p2 += 18;
				char *p3 = strstr(p2,"\r\n");
				char *p4 = NULL;
				unsigned int len = 0;
				while(*p2==' ')
                    p2++;
                
				for (p4 = p2; p4 < p3; p4++)
				{
					if(*p4>='0' && *p4<='9')
                        len = len*10 + (*p4-'0');
					else 
                        break;
				}
                
				entry->bodyTotal = len;
                entry->bodyLen = dataLen - (p-data);
				entry->body = (char*)malloc(entry->bodyLen + 1);
				if (!entry->body)
                    return -1;
                
                if (entry->bodyLen > 0)
				    memcpy(entry->body, p, entry->bodyLen);

				if (entry->bodyLen >= entry->bodyTotal)
				{
					entry->body[entry->bodyLen] = 0;
					return 1;
				}
			}
			else
			{
				return -1;
			}
		}
		else
		{
			if(entry->headerLen == 0)
			{
				entry->headerLen = dataLen;
				entry->header = (char* )malloc(dataLen + 1);
				if(!entry->header) 
                    return -1;
                
				memcpy(entry->header, data, dataLen);
			}
			else
			{
				entry->header = (char* )realloc(entry->header, entry->headerLen + dataLen + 1);
				memcpy(entry->header + entry->headerLen, data, dataLen);
				entry->headerLen += dataLen;
			}
		}
	}
	else
	{
		if (entry->status&0x02)
		{
			char *p = data;
			if (!(entry->status&0x04))
			{
				if(entry->bodyLen + dataLen < entry->bodyTotal)
				{
					memcpy(entry->body + entry->bodyLen, data, dataLen);
					entry->bodyLen += dataLen;
				}
				else
				{
					int offset = entry->bodyTotal - entry->bodyLen;
					memcpy(entry->body + entry->bodyLen, data, offset);
					entry->bodyLen = entry->bodyTotal;
					p = data + offset + 2;
					entry->status |= 0x04;
				}
			}
            
			if (entry->status&0x04)
			{
				char *p2 = NULL;
				while(*p=='\r' || *p=='\n') 
                    p++;
                
				p2 = strstr(p, "\r\n");
				while (p2)
				{
					if (p2+2 > data+dataLen) 
                        return 0;
                    
					unsigned int len = 0;
					char *p3 = NULL;
					for(p3=p; p3<p2; p3++)
					{
						if(*p3>='0' && *p3<='9') 
                            len=len*16 + (*p3-'0');
						else if(*p3>='a' && *p3<='f') 
                            len=len*16 + (*p3-'a'+10);
						else if(*p3>='A' && *p3<='F') 
                            len=len*16 + (*p3-'A'+10);
						else 
                            break;
					}
                    
					if(len == 0)
					{
						entry->body[entry->bodyLen] = 0;
						return 1;
					}
                    
					p2 += 2;
					if(p2+len <= data+dataLen)
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if(!entry->body)
                            return -1;
                        
						memcpy(entry->body+entry->bodyLen, p2, len);
						entry->bodyLen += len;
						entry->bodyTotal += len;
						entry->status |= 0x04;
						p = p2 + len + 2;
						p2 = strstr(p,"\r\n");
						continue;
					}
					else
					{
						entry->body = (char *)realloc(entry->body, entry->bodyTotal + len + 1);
						if(!entry->body) 
                            return -1;
                        
						unsigned int slen = data + dataLen - p2;
						memcpy(entry->body + entry->bodyLen, p2, slen);
						entry->bodyTotal += len;
						entry->bodyLen += slen;
						entry->status &= 0xfffffffb;
						break;
					}
				}
			}
		}
		else
		{
            entry->body = (char *)realloc(entry->body, entry->bodyLen + dataLen + 1);
            if (!entry->body)
            {
                return -1;
            }
			memcpy(entry->body + entry->bodyLen, data, dataLen);
			entry->bodyLen += dataLen;
			if (entry->bodyLen >= entry->bodyTotal)
			{
				entry->body[entry->bodyLen] = 0;
				return 1;
			}
		}
	}
    
	return 0;
}

int ofo_func(OFOC_t ofo, PIRS_t rset, void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(void *node, PacketInfo *packetInfo, int is_to_s))
{
    int result;
    unsigned int f=registerPacketInfo(ofo,rset,packetInfo);
	if(f&0x0f)
		result = callback(node, packetInfo, is_to_s);
	if(f&0xf0)
	{
		while(resultSetNext(rset,packetInfo))
		{
			result = callback(node, packetInfo, is_to_s);
		}
		clearResultSet(rset);
	}
	if(result==-1 || result==-2) 
        unregisterPacketInfo(ofo,packetInfo);
    return result;
}

char *memnfind(char *src, size_t srcLen, char *pat, size_t patLen)
{
	size_t i, len;
	char *p = src;
	char *p1 = NULL;
	char *p2 = NULL;
	size_t j = 0;
	if (src == NULL || pat == NULL || srcLen<patLen)
		return NULL;

	len = srcLen - patLen + 1;
	for (i = 0; i < len; i++)
	{
		if (*p != *pat)
		{
			p++;
			continue;
		}
		
		p1 = pat;
		p2 = p;
		j = 0;
		while (j < patLen) 
		{
			j++;
			if (*(++p2) != *(++p1))
				break;
		}
		if (j == patLen)
		{
			return p;
		}
		p++;
	}
	return NULL;
}

char *arrcpy(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN)
{
    if (NULL == src)
        return NULL;
        
    char *p1 = NULL, *p2 = NULL;
    int len = 0;
    
    p1 = strstr(src, startstr);
    if (NULL == p1)
        return NULL;
        
    p1 += addlen;
    p2 = strstr(p1, endstr);
    if (NULL == p2)
        return NULL;
  
    len = p2 - p1;
    if (len > 0)
    {
        if (len > MAX_LEN)
            len = MAX_LEN;
            
        memcpy(arr, p1, len);
        arr[len] = 0;
    }
    
    return p2;
}

int analyse_recv(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s, int (*callback)(Mail_info *mail_info))
{
    if (1 == mail_info->is_complished)
        return -1;
        
    int f = 0;
    if (is_to_s)
        return write_to_mail(mail_info, packetInfo->body, packetInfo->bodyLen, packetInfo->tcp);
    else
    {
        f = http_recive_mail(mail_info, packetInfo->body, packetInfo->bodyLen);
        if (1 == f)
        {
            if (NULL == mail_info->body || NULL == mail_info->header)
                return -1;
            
            mail_info->is_complished = 1;
            if (strstr(mail_info->header, "Content-Encoding: gzip\r\n"))
            {
                char *s = NULL;
			    int slen = 0;
				inflate_read(mail_info->body, mail_info->bodyLen, &s, &slen, 1);
				free(mail_info->body);
				mail_info->body = s;
				mail_info->bodyLen = slen;
            }
            
    		return callback(mail_info);;
    	}
        else if (f < 0)
            return -1;
    }
    
    return f;
}

int analyse_downattach(void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(Attach_info *attach_info))
{
    Attach_info *attach_info = (Attach_info *)node;
    int f = 0;
	if(!is_to_s)
	{
        if(attach_info->recive_length==0)
        {
            if(!strncmp(packetInfo->body, "HTTP/1.1 200 OK\r\n", 17))
                    attach_info->recive_length = 1;
            else
                    return -1;
        }
		f = http_recive_attach(attach_info,packetInfo->body,packetInfo->bodyLen);
		if(f==1)
		{            
            if (-1 == callback(attach_info))
                return -1;
			char * front,* back;
			int len = 0;
			int result = 0;

            len = get_downattach_name(attach_info->header, attach_info->attach_name);
            if (len <= 0)
                return -1;
			memcpy(attach_info->attname, attach_info->attach_name, len);
			attach_info->attname[len] = '\0';
     
			htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			//LOG_INFO("attach_info->attach_name: %s\n", attach_info->attach_name);
			htmldecode_full(attach_info->attname, attach_info->attname);
            char * s;
			int slen;
			if(strstr(attach_info->header,"Content-Encoding: gzip\r\n"))
			{
				inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				free(attach_info->body);
				attach_info->body=s;
				attach_info->bodyLen=slen;
			}
            write_attach(attach_info->path_of_here, attach_info->attach_name, attach_info->body, attach_info->bodyLen, 1);
		
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
			
		}
	}
	else
        write_data(packetInfo->body, packetInfo->bodyLen, &attach_info->ok_data, &attach_info->ok_length);

	return f;
}

int get_downattach_name(char *data, char name[MAX_PATH_LEN+1])
{
    int len = 0;
    int b_64 = 0;
    char *front = NULL;
    char *back = NULL;
    char *pflag = strstr_2(data, "content-disposition");
    if (NULL == pflag)
        return -1;
	front = strstr_2(pflag, "filename=\"");
	if(front == NULL)
	{
        front = strstr_2(pflag, "filename=");
        if (NULL == front)
        {
            front = strstr_2(pflag, "fileName*==?UTF-8?B?");
            if (NULL == front)
                return -1;
            b_64 = 1;
            front += 20;
            back = strstr(front, "?=");
        }
        else
        {
		    front += 9;
            back = strstr(front, "\r\n");
        }
	}
    else
    {
		front += 10;
		back = strstr(front, "\"\r\n");
		if(back == NULL)
			return 0;
    }
    len = back - front;
	len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
	memcpy(name, front, len);
	name[len] = '\0';
    if (b_64)
    {
        char *tmp = Base2UTF8_mail(name, len);
        if (NULL != tmp)
        {
            len = strlen(tmp);
            memcpy(name, tmp, len);
            name[len] = 0;
            free(tmp);
			tmp = NULL;
        }
    }
    return len;
}

int attac_mail(Mail_info *mail_info, int flag)
{
    char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
    Attach_info *attach_info, *attach_tmp;
    char *tmp = NULL;
    int i = 0;
	attach_info = attach_tab.head->next;
	while (attach_info != NULL) 
    {
		if (strstr(mail_info->mail_id, attach_info->ID_str) == NULL) 
        {
			attach_info = attach_info->next;
			continue;
		}
		i++;
		del_attach_node(attach_info);

        get_file_name(attach_info->attach_name, filename);
        
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
			return -1;
		//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		attachment->next = NULL;
		snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
		link(attach_info->path_of_here, writepath);
	    unlink(attach_info->path_of_here);
		attach_tmp = attach_info->next;
		delete_attach(attach_info);
		attach_info = attach_tmp;
		if(!flag) {
			mail_info->attach = attachment;
			flag =1;
		} else {
			attachment->next=mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
	}
	mail_info->num_of_attach = i;
    return 0;
}

int write_attach(char path[], char name[], char *data, int len, int up_or_down)
{
    struct timeval tv;
	struct timezone tz;
    int fd;
    mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    gettimeofday(&tv, &tz);
    char *attachpath = NULL;
    if (0 == up_or_down)
        attachpath = mail_temp_path;
    else
        attachpath = attach_down_path;
	snprintf(path, MAX_PATH_LEN, "%s/%lu-%lu",attachpath, tv.tv_sec, tv.tv_usec);
    fd = open(path, O_RDWR|O_CREAT, file_mode);
    if (fd == -1)
	{
		LOG_ERROR("%s write err!\n", name);
		return -1;
	}
	write(fd, data, len);
	close(fd);
	snprintf(name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);

}

void write_data(char *src, int srcLen, char **dest, unsigned int *destLen)
{
    if (NULL==src || NULL==dest)
        return ;
    if (NULL == *dest)
        *dest = (char *)malloc(srcLen+1);
    else
        *dest = (char *)realloc(*dest, *destLen+srcLen+1);
    memcpy(*dest+*destLen, src, srcLen);
    *destLen += srcLen;
    (*dest)[*destLen] = 0;
}

void store_account_db(Mail_info* node)
{
    WEBACCOUNT_T tmp_data;
    struct in_addr addr;

    memset(&tmp_data, 0, sizeof(tmp_data));
    tmp_data.p_data.readed = 0;
    addr.s_addr = node->source_ip;
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
        
    sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x",
    		node->client_mac[0]&0xff,node->client_mac[1]&0xff,node->client_mac[2]&0xff,
    		node->client_mac[3]&0xff,node->client_mac[4]&0xff,node->client_mac[5]&0xff);
    tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, inet_ntoa(addr));

    sprintf(tmp_data.p_data.clientPort, "%d", ntohs(node->source_port));
    addr.s_addr = node->dest_ip;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", ntohs(node->dest_port));
    tmp_data.p_data.captureTime = node->cap_time;

    if (strlen(node->url) > 0)
        strncpy(tmp_data.url, node->url, 255);
    else
        strcpy(tmp_data.url, "");

    if (strlen(node->username) > 64)
        strcpy(tmp_data.username, "");
    else
        strncpy(tmp_data.username, node->username, 64);

    if(strlen(node->passwd) > 64)
        strcpy(tmp_data.password, "");
    else
        strncpy(tmp_data.password, node->passwd, 64);

    tmp_data.p_data.proType = 202;
    tmp_data.p_data.deleted = 0;

    msg_queue_send_data(WEBACCOUNT, (void *)&tmp_data, sizeof(tmp_data));
}

