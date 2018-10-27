
#include "common.h"

char *clear_kh2(char *source)
{
    if (source == NULL)
        return NULL;
		
    char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
    int result;
    if (result != -1)
        result = cns_str_ereplace(&str, "\"(.*?)\"", "");
    if (result != -1)
        result = cns_str_ereplace(&str, "<", "");
    if (result != -1)
        result = cns_str_ereplace(&str, ">", "");
    if (result != -1)
        result = cns_str_ereplace(&str, "\"", "");
    if (result != -1)
        result = cns_str_ereplace(&str, ".*? ", "");

    return str;
}

static int get_tom_send_id(char *data, char ID[MAX_ID_LEN+1], int m_or_a)
{
    char *pat1 = NULL, *pat2 = NULL;
    
    if (m_or_a)
    {
        pat1 = "&filenames=";
        pat2 = "&";
    }
    else
    {
        pat1 = "tmpName:";
        pat2 = ",";
    }
    
    char *p1 = strstr(data, pat1);
    char *p2 = NULL;
    int len  = 0;
    
    if (NULL == p1)
        return -1;
    
    p1 += strlen(pat1);
    p2 = strstr(p1, pat2);
    if (NULL == p2)
        return -1;
    
    len = p2 - p1;
    if (len> MAX_ID_LEN)
		len = MAX_ID_LEN;
    
    memcpy(ID, p1, len);
	ID[len] = 0;
    
    return len;
}

static int get_tom_recv_id(char * data, char ID [ MAX_ID_LEN + 1 ])
{
    char *p1 = strstr(data, "uid=");
    if (NULL == p1)
        return -1;
    char *p2 = strstr(p1, "&");
    if (NULL == p2)
        return -1;
    int len = p2-p1;
    
    if (len > MAX_ID_LEN)
        len = MAX_ID_LEN;
    memcpy(ID, p1, len);
    ID[len] = 0;
    return len;
}

char *tom_conv_to_utf8(char *src)
{
    if (NULL == src)
        return NULL;
	char *tmp_str = NULL;
	char *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	tmp_str = (char *)malloc(len + 1);
	if (NULL == tmp_str)
		return NULL;
	htmldecode_full(src, tmp_str);

	len = strlen(tmp_str);
	utf8_len = len * 3 / 2 + 1;
	dest = (char *)malloc(utf8_len + 1);
	if (NULL == dest)
		return NULL;
	result = code_convert("gb18030", "utf-8", tmp_str, len, dest, utf8_len);
	free(tmp_str);
	tmp_str = NULL;

	if (-1 == result)
		return NULL;
	else 
		return dest;
}

char *tom_rcv_conv_to_utf8(char *src)
{
	char *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	//utf8_len = len * 3 / 2 + 1;
	//dest = (char *)malloc(utf8_len + 1);
	//内存报错，扩大内存缓冲   lihan 2017.3.3
	utf8_len = len * 4;
	dest = (char *)malloc(utf8_len);
	if (NULL == dest)
		return NULL;
	result = code_convert("gb18030", "utf-8", src, len, dest, utf8_len);

	if (-1 == result)
		return NULL;
	else 
		return dest;
}

int tom_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = tom_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
	
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;
	
	return 0;
}
int writefile_tom(Mail_info *mail_info)
{

	char ID[MAX_ID_LEN + 1], tmp_id[MAX_ID_LEN + 1], temp1[MAX_ID_LEN + 1];
	int len, len1, sidmid_len;
	char *tmp = NULL;
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	int i = 0, flag = 0;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL;
	int result;
	
    if (0x0712 == mail_info->mail_type)
    {
        len = get_tom_send_id(mail_info->mail_data, ID, 1);
        if (len < 0)
            return -1;
        
        memcpy(mail_info->mail_id, ID, len);
        mail_info->mail_id[len] = 0;
        p1 = strstr(mail_info->mail_data, "\r\n\r\n");
        p1 += 4;
        p1 = strstr(p1, "from=");
        if (NULL == p1)
            return -1;
        p1 += 5;
        p2 = strstr(p1, "&");
        len = p2 - p1;
        memcpy(mail_info->from, p1, len);
        mail_info->from[len] = 0;
    }
    else
    {
    	get_from(mail_info->from, mail_info->source_ip);

    	p1 = strstr(mail_info->mail_data, "&sid=");
    	if (p1 == NULL)
            return -1;
        
    	p1 += 5;
    	p2 = strstr(p1, " HTTP/1.1\r\n");
    	if (p2 == NULL)
    		return -1;
        
    	len = p2 - p1;
    	sidmid_len = len;
    	if (p2 == NULL)
    		return -1;
        
    	if (len > MAX_ID_LEN)
    		len = MAX_ID_LEN;
    	memcpy(ID, p1, len);
    	ID[len] = 0;
        
    	p2 += 11;
        p1 = strstr(mail_info->mail_data, "&mid=");
    	if (p1 == NULL)
    		return -1;
        
    	p1 += 5;
    	p2 = strstr(p1, "%250A0%250A0%250A");
    	if (p2 == NULL)
    		p2 = strstr(p1, "%250A");
        
    	if (p2 == NULL)
    		return -1;
        
    	len1 = p2 - p1;
    	if (len + len1 > MAX_ID_LEN)
    		len1 = MAX_ID_LEN - len;
        
    	sidmid_len += len1;
    	memcpy(ID + len, p1, len1);
    	ID[sidmid_len] = 0;
        p2 += 17;
    }
	p1 = strstr(p2, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len == 0)
		return -1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	p1 = strstr(p2, "&cc=");
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} 
		else 
		{
			mail_info->cc[0] = 0;
		}
	} 
	else 
	{
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "&bcc=");
	if (p1 != NULL) 
	{
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} 
		else 
		{
			mail_info->bcc[0] = 0;
		}
	} 
	else 
	{
		mail_info->bcc[0] = 0;
	}
	p1 = strstr(p2, "&subject=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	p1 = strstr(p2, "&text2=");
	if (p1 == NULL)
	{
		p1 = strstr(p2, "&text=");
    	if (p1 == NULL)
    		return -1;
        p1 += 6;
	}
    else
	    p1 += 7;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	convert_contents(mail_info->from);
    convert_contents(mail_info->to);
    convert_contents(mail_info->cc);
    convert_contents(mail_info->bcc);
	
	tmp = clear_kh2(mail_info->bcc);
    strcpy(mail_info->bcc, tmp);
    mail_info->bcc[strlen(tmp)]=0;
    free(tmp);
	
    if (0x0712 == mail_info->mail_type)
    {
        htmldecode_full(mail_info->subject, mail_info->subject);
        htmldecode_full(mail_info->content, mail_info->content);
    }
  
    tmp = conv_to_xml_symbol(mail_info->subject);
    strcpy(mail_info->subject, tmp);
    mail_info->subject[strlen(tmp)] = 0;
    free(tmp);
	tmp = conv_to_xml_symbol(mail_info->content);
    free(mail_info->content);
    mail_info->content = clear_html_tag(tmp);
    free(tmp);

	tmp = NULL;
	if (NULL == mail_info->content)
		return -1;
	create_dir(mail_info->save_path, "tom", mail_info->from);

	///* add affixflag infomation    lihan 2017.3.22
	Attach_info *attach_tmp;
	Attachment *attachment;
	Attach_info *attach_info = attach_tab.head->next;
	     
	while (attach_info != NULL) 
	{
		if (!strcmp(attach_info->ID_str, mail_info->mail_id))
		{
			i++;
			get_file_name(attach_info->attach_name, filename);//lihan add file name
			attachment = (Attachment *)malloc(sizeof(Attachment));
			
			if (attachment == NULL)
			{	
				return -1;
			}

			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			if (!flag ) 
			{
				attachment->next = NULL;
				mail_info->attach = attachment;
				flag++;
			} 
			else 
			{
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);
			
			link(attach_info->path_of_here, writepath);
			unlink(attach_info->path_of_here);
			del_attach_node(attach_info);
			attach_tmp = attach_info->next;
			delete_attach(attach_info);
			attach_info = attach_tmp;
			continue;
		}
		attach_info = attach_info->next;
	}
	
	mail_info->num_of_attach = i;//lihan add 2017.3.24
	write_to_file(mail_info);
	return 0;
}

int get_vip_tom_from(char *data, char *mail_from)
{
	char *p1, *p2;
	size_t len,len1;
	char temp[MAX_FROM_LEN + 1];

	p1 = strstr(data, "; user=");
	if (p1 == NULL)
		return -1;
	p1 += 7;
	p2 = strstr(p1, "; uid=");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_from, p1, len);
	mail_from[len] = 0;
	
	p1 = strstr(p2, "&rpdomain=");
	if (p1 == NULL)
		return -1;
	p1 += 10;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len1 = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len + len1 + 1 > MAX_FROM_LEN)
		len1 = MAX_FROM_LEN - len;
	mail_from[len] = '@';
	memcpy(mail_from + len + 1, p1, len1);
	mail_from[len + len1 + 1] = 0;

	return 0;
}

int writefile_vip_tom(Mail_info *mail_info)
{
	char ID[MAX_ID_LEN - 1], tmp_id[MAX_ID_LEN - 1], temp1[MAX_ID_LEN - 1];
	size_t sidmid_len, len, len1;
	Attach_info *attach_info, *attach_tmp;
	char *tmp = NULL;
	char filename[MAX_FN_LEN - 1];
	char writepath[MAX_PATH_LEN - 1];
	int i = 0, flag = 0;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL;
	int result = 0;

//	result = get_vip_tom_from(mail_info->mail_data, mail_info->from);
	get_from(mail_info->from, mail_info->source_ip);
	
	if (result == -1)
		return -1;

	p1 = strstr(mail_info->mail_data, "&sid=");
	if (p1 == NULL)
		return -1;
	p1 += 5;
	p2 = strstr(p1, " HTTP/1.1\r\n");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	sidmid_len = len;
	if (p2 == NULL)
		return -1;
	if (len > MAX_ID_LEN)
		len = MAX_ID_LEN;
	memcpy(ID, p1, len);
	ID[len] = 0;
	p2 += 11;

	p1 = strstr(mail_info->mail_data, "&mid=");
	if (p1 == NULL)
		return -1;
	p1 += 5;
	p2 = strstr(p1, "%250A0%250A0%250A");
	if (p2 == NULL)
		p2 = strstr(p1, "%250A");
	len1 = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len + len1 > MAX_ID_LEN)
		len1 = MAX_ID_LEN - len;
	sidmid_len += len1;
	memcpy(ID + len, p1, len1);
	ID[sidmid_len] = 0;
	p2 += 17;

	p1 = strstr(p2, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	
	p1 = strstr(p2, "&cc=");
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} else {
			mail_info->cc[0] = 0;
		}
	} 
	else 
	{
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "&bcc=");
	if (p1 != NULL) 
	{
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} 
		else 
		{
			mail_info->bcc[0] = 0;
		}
	} 
	else 
	{
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "&subject=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	p1 = strstr(p2, "&text2=");
	if (p1 == NULL)
		return -1;
	p1 += 7;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc((size_t)len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;

	result = tom_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp = tom_conv_to_utf8(mail_info->content);
	if (NULL == tmp)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp);
	free(tmp);
	tmp = NULL;
	if (NULL == mail_info->content)
		return -1;

	create_dir(mail_info->save_path, "tom", mail_info->from);

	attach_info = attach_tab.head->next;
	while (attach_info != NULL) {
		if (strncmp(ID, attach_info->ID_str, sidmid_len) != 0) {
			attach_info = attach_info->next;
			continue;
		}
		i++;
		del_attach_node(attach_info);
		tmp = tom_conv_to_utf8(attach_info->path_of_sender);
		if (tmp == NULL)
			return -1;
		get_file_name(tmp, filename);
		free(tmp);
		tmp = NULL;
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
			break;
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
		if(!flag){
			mail_info->attach = attachment;
			flag =1;
		} else {
			attachment->next=mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
	}
	mail_info->num_of_attach = i;
	write_to_file(mail_info);
	return 0;
}

int analyse_tom_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
	off_seq = seq - mail_info->start_seq;
	if (is_to_s) 
	{
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	}
	else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15))
	{
		int result;
		char *host_p;
		size_t len;

		len = strlen(mail_info->mail_data);
		if (strstr(mail_info->mail_data + len - 50, "=&attach") != NULL) {
			return -1;
		}
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		host_p = strstr(mail_info->mail_data, "Host: ");
		if (host_p == NULL) {
			return -1;
		}
		if (memfind(host_p, "tom.com", 50) != NULL)
			writefile_tom(mail_info);
		else if (memfind(host_p, "163.net", 50) != NULL)
			writefile_vip_tom(mail_info);
		del_mail_node(mail_info);
		return 0;
	}
	return -2;
//	return -1;
}

int analyse_tom_mail2(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;
	seq = ntohl(ptcp->seq);
	off_seq = seq - mail_info->start_seq;
	if (is_to_s)
    {
		if (!mail_info->is_complished) 
        {
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
    else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15))
    {
    		result = writefile_tom(mail_info);
    		del_mail_node(mail_info);
	}
	return result;
//	return -1;
}

int analyse_tom_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	char *p = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data, "form-data; name=\"removefile\"\r\n\r\n");
	if (p != NULL) {
		attach_info->attach_type = 0x0741;
		return 0;
	}

	p = strstr(attach_info->ok_data, "filename=\"");
	if (p==NULL)
		return 0;
	p = strstr(p, "\r\n\r\n");
	if (p==NULL) {
		return 0;
	}
	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1
	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);//2
	if (result == -1)
		return -1;
	if (!strlen(attach_info->path_of_sender))
	//	return -2;
		return -1;
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here,O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd,p,off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4
	return 0;
}

int analyse_tom_delete(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;
	if (is_to_s) {
		off_seq = seq - attach_info->start_seq;
		if (off_seq + data_len > attach_info->ok_len)
			return -1;
		memcpy(attach_info->ok_data + off_seq, data, data_len);
	} else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 17)) {
		char pattern[] = "Content-Disposition: form-data; name=\"removefile\"\r\n\r\n(.*)\r\n--------.*name=\"remove.x\"\r\n\r\n";
		char pattern_sid[] = "Content-Disposition: form-data; name=\"sid\"\r\n\r\n(.*)\r\n-------.*name=\"mid\"\r\n\r\n";
		char pattern_mid[] = "Content-Disposition: form-data; name=\"mid\"\r\n\r\n(.*)%0A0%0A0%0A";
		char ID_str[MAX_ID_LEN + 1];
		char tmp[MAX_ID_LEN + 1];
		Attach_info *attach_tmp;
		char filename[MAX_FN_LEN + 1];
		size_t len1, len2, len3;

		del_attach_node(attach_info);
		result = regcompile_1(attach_info->ok_data, pattern, filename, MAX_FN_LEN);
		if (result == -1) {
			return -1;
		}
		result = regcompile_1(attach_info->ok_data, pattern_sid, ID_str, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}
		result = regcompile_1(attach_info->ok_data, pattern_mid, tmp, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}
		
		len1 = strlen(ID_str);
		len2 = strlen(tmp);
		len3 = strlen(filename);

		if (len1 + len2 > MAX_ID_LEN) {
			len2 = MAX_ID_LEN - len1;
			len3 = 0;
		} else if (len1 + len2 + len3 > MAX_ID_LEN) {
			len3 = MAX_ID_LEN - len1 - len2;
		}

		memcpy(ID_str + len1, tmp, len2);
		memcpy(ID_str + len1 + len2, filename, len3);
		ID_str[len1 + len2 + len3] = 0;

		attach_tmp = find_attach(ID_str);
		if (attach_tmp != NULL) {
			delete_attach(attach_tmp);
		}
		delete_attach(attach_info);
		return 0;
	}
	return -1;
}

int analyse_tom_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;

	if (is_to_s) {
		if (attach_info->is_writing) {
			result = write_to_attach(attach_info, data, data_len, seq);
		} else {
			result = analyse_tom_attach_head(attach_info, data, data_len, seq);
		}
		return result;
	} else {
		if (!attach_info->is_get_ok) {
			if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 17)) {
				trim_attach2(attach_info->path_of_here, 300);
				int len;

				attach_info->is_writing = 0;
				attach_info->is_get_ok = 1;
				len = get_http_length(data);
				len += 50;  //12
				attach_info->ok_len = len;
				if (len <= 0) {
					return -1;
				}
				if (strstr(data, "\r\nContent-Encoding: gzip\r\n")) {
					attach_info->ok_gzip = 1;
				} else {
					attach_info->ok_gzip = 0;
				}

                if (attach_info->ok_data)
                {
                    free(attach_info->ok_data);
                    attach_info->ok_data = NULL;
                }
                
				attach_info->ok_data = (char *)malloc((size_t)(len + 1));
				memset(attach_info->ok_data, 0, len + 1);
				char *p = strstr(data, "\r\n\r\n");
				p += 4;
				len = data_len - (p - data);
				memcpy(attach_info->ok_data, p, len);
				attach_info->ok_start_seq = seq + p - data;
				if (strstr(p, "\r\n\r\n") != NULL || !memcmp(data + data_len - 2, "\0\0\0", 3)) {
					attach_info->is_get_ok = 0;
					attach_info->is_complished = 1;
					char tmp[MAX_ID_LEN + 1];
					char filename[MAX_FN_LEN + 1];
					size_t len1, len2, len3;

					result = regcompile_1(attach_info->ok_data, "name=\"sid\" value=\"(.*)\" >\n<input type=\"hidden\" name=\"mid\" value", attach_info->ID_str, MAX_ID_LEN);
					if (result == -1) {
						return -1;
					}
					result = regcompile_1(attach_info->ok_data, "name=\"mid\" value=\"(.*)%0A.{1,2}%0A0%0A", tmp, MAX_ID_LEN);
					if (result == -1) {
						return -1;
					}
					get_file_name(attach_info->path_of_sender, filename);

					len1 = strlen(attach_info->ID_str);
					len2 = strlen(tmp);
					len3 = strlen(filename);

					if (len1 + len2 > MAX_ID_LEN) {
						len2 = MAX_ID_LEN - len1;
						len3 = 0;
					} else if (len1 + len2 + len3 > MAX_ID_LEN) {
						len3 = MAX_ID_LEN - len1 - len2;
					}

					memcpy(attach_info->ID_str + len1, tmp, len2);
					memcpy(attach_info->ID_str + len1 + len2, filename, len3);
					attach_info->ID_str[len1 + len2 + len3] = 0;
				}
				return 0;
			}
			return -1;
		} else {
			int off_seq = seq - attach_info->ok_start_seq;

			if (off_seq < 0) {
				data_len += off_seq;
				if (data_len < 1)
					return 0;
				data -= off_seq;
				off_seq = 0;
			}
			if (off_seq + data_len > attach_info->ok_len)
				return -1;
			memcpy(attach_info->ok_data + off_seq, data, data_len);
			if (strstr(data, "\r\n\r\n") != NULL || !memcmp(data + data_len - 2, "\0\0\0", 3)) {
				attach_info->is_get_ok = 0;
				attach_info->is_complished = 1;
				char tmp[MAX_ID_LEN + 1];
				char filename[MAX_FN_LEN + 1];
				size_t len1, len2, len3;

				result = regcompile_1(attach_info->ok_data, "name=\"sid\" value=\"(.*)\" >\n<input type=\"hidden\" name=\"mid\" value", attach_info->ID_str, MAX_ID_LEN);
				if (result == -1) {
					return -1;
				}
				result = regcompile_1(attach_info->ok_data, "name=\"mid\" value=\"(.*)%0A.{1,2}%0A0%0A", tmp, MAX_ID_LEN);
				if (result == -1) {
					return -1;
				}
				get_file_name(attach_info->path_of_sender, filename);

				len1 = strlen(attach_info->ID_str);
				len2 = strlen(tmp);
				len3 = strlen(filename);

				if (len1 + len2 > MAX_ID_LEN) {
					len2 = MAX_ID_LEN - len1;
					len3 = 0;
				} else if (len1 + len2 + len3 > MAX_ID_LEN) {
					len3 = MAX_ID_LEN - len1 - len2;
				}

				memcpy(attach_info->ID_str + len1, tmp, len2);
				memcpy(attach_info->ID_str + len1 + len2, filename, len3);
				attach_info->ID_str[len1 + len2 + len3] = 0;
			}
			return 0;
		}
	}
}

int analyse_tom_attach1(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
    
    int f = 0;
    if (is_to_s)
    {
        if (1 == attach_info->is_complished)
            return -2;
        f = http_recive_attach(attach_info,data,data_len);

        if (1 ==f )
        {
            if (NULL == attach_info->header || NULL == attach_info->body)
                return -1;
            
            char *p1 = strstr(attach_info->body, "\r\n");
            int len = p1-attach_info->body;
            char *endflag = (char *)malloc(len+47+1);
            memcpy(endflag, attach_info->body, len);
            memcpy(endflag+len,"\r\nContent-Disposition: form-data; name=\"Upload\"", 47);
            endflag[len+47] = 0;
            //printf("endflag:%s\n", endflag);
            p1 = strstr(attach_info->body, "Content-Disposition: form-data; name=\"Filename\"\r\n\r\n");
            if (NULL == p1)
                return -1;
            p1 += 51;
            char *p2 = strstr(p1, "\r\n");
            len = p2-p1;
            if (len > MAX_PATH_LEN)
                len = MAX_PATH_LEN;
            memcpy(attach_info->attach_name, p1, len);
            attach_info->attach_name[len] = 0;
            htmldecode_full(attach_info->attach_name, attach_info->attach_name);
            //printf("attach_name:%s\n", attach_info->attach_name);
            p1 = strstr(p2, "\r\n\r\n");
            if (NULL == p1)
                return -1;
            p1 += 4;
            p2 = memnfind(attach_info->body+attach_info->bodyLen-200, 200, endflag, strlen(endflag));
            if (NULL == p2)
                return -1;
            len = p2-p1;
        	struct timeval tv;
        	struct timezone tz;
        	gettimeofday(&tv,&tz);
        	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
        	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        	int fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
    		write(fd, p1, len);
    		close(fd);
        	free(endflag);
			endflag = NULL;
        	free(attach_info->header);
            attach_info->header = NULL;
            attach_info->headerLen = 0;
            free(attach_info->body);
            attach_info->body = NULL;
            attach_info->bodyLen = 0;
            attach_info->bodyTotal = 0;
    		return 0;
    	}
    }
    else 
    {
        if (attach_info->ID_str[0]!=0 || get_tom_send_id(data, attach_info->ID_str, 0)>0)
        {
            attach_info->is_complished = 1;
            return 0;
        }
    }
    return 0;
    
}

int write_tom_psword_new(Mail_info * mail_info)
{
    char *p1 = arrcpy(mail_info->username, mail_info->mail_data, "username=", "&", 9, MAX_UN_LEN);
    if (NULL == p1)
        return -1;
    convert_contents(mail_info->username);
    //printf("p1=%s\n", p1);
    p1 = strstr(p1-1, "&password=");
    if (NULL != p1)
    {
        p1 += 10;
        int len = mail_info->mail_data+mail_info->mail_length-p1;
        if (len > MAX_PW_LEN)
            len = MAX_PW_LEN;
        memcpy(mail_info->passwd, p1, len);
        mail_info->passwd[len] = 0;
    }
   
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
	write_xml(mail_info);

	FILE *fp;
        char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	fp=fopen(passpath,"a+");
	if(fp==NULL)
        return -1;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
    return 0;
}

int write_tom_psword(Mail_info *mail_info)
{
    if (0x703 == mail_info->mail_type)
        return write_tom_psword_new(mail_info);
	char *p1,*p2;
	size_t len;

	p1 = mail_info->mail_data;
	p1 = strstr(p1,"&user=");
	if(!p1)
		return -1;
	p1 += 6;
	p2 = strstr(p1,"&");
	if(!p2)
		return -1;
	len = p2 - p1;
	if (len > MAX_UN_LEN - 8 )
		len = MAX_UN_LEN;
	memcpy(mail_info->username, p1, len);
	mail_info->username[p2-p1] = 0;
	while(len && mail_info->username[len] != '@') {
		len--;
	}
	if(!len) {
		strcat(mail_info->username, "@tom.com");
	}

	p1 = strstr(p2, "&pass=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1,"&");
	if(!p2)
		return -1;
	len = p2 - p1;
	if (len > MAX_PW_LEN)
		len = MAX_PW_LEN;
	memcpy(mail_info->passwd, p1, len);
	mail_info->passwd[len] = 0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);

	write_xml(mail_info);

	FILE *fp = NULL;
	char writepath[MAX_PATH_LEN + 1];
	snprintf(writepath, MAX_PATH_LEN, "%s/pass.txt", mail_data_path);
	fp = fopen(writepath, "a+");
	if(fp == NULL)
		return -1;
	fprintf(fp,"\nusername=%s\npassword=%s\n", mail_info->username, mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
	return 0;
}

int write_tom_vip_psword(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL;
	size_t len;

	p1 = mail_info->mail_data;
	p1 = strstr(p1,"&user=");
	if(!p1)
		return -1;
	p1 += 6;
	p2 = strstr(p1,"&");
	if(!p2) {
	//	return -1;
		p2 = p1 + strlen(p1);
	}
	len = p2 - p1;
	if (len + 20 > MAX_UN_LEN)
		len = MAX_UN_LEN;
	memcpy(mail_info->username, p1, len);
	mail_info->username[len]=0;
	while(len && mail_info->username[len]!='@') {
		len--;
	}
	if(!len){
		strcat(mail_info->username, "@163.net/@vip.tom.com");
	}

	p1 = strstr(p2, "&pass=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&");
	if(!p2)
		return -1;
	len = p2 - p1;
	memcpy(mail_info->passwd, p1, len);
	mail_info->passwd[len] = 0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);
	
	write_xml(mail_info);

	FILE *fp = NULL;
	char writepath[MAX_PATH_LEN + 1];
	snprintf(writepath, MAX_PATH_LEN, "%s/pass.txt", mail_data_path);
	fp = fopen(writepath, "a+");
	if(fp == NULL)
		return -1;
	fprintf(fp,"\nusername=%s\npassword=%s\n", mail_info->username, mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
	
	return 0;
}

int analyse_tom_psword1(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
    if(is_b_s && (1 == http_recive_mail(mail_info, data, datalen)))
    {
        char* p1 = NULL, *p2 = NULL;
        char* tmp_data = mail_info->body;
        char tmp_name[MAX_UN_LEN + 1] = {0};
        char tmp_password[MAX_UN_LEN + 1] = {0};
        
        if(!tmp_data)
            return -1;
        
        p1 = strstr(tmp_data, "username=");
        if(!p1)
            return -1;

        p1 += strlen("username=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_name, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_name, mail_info->username);
      
        p1 = strstr(tmp_data, "password=");
        if(!p1)
            return -1;

        p1 += strlen("password=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_password, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_password, mail_info->passwd);
        store_account_db(mail_info);
        
        return -1;
    }

    return 0;
}


int analyse_tom_psword2(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq =seq-mail_info->start_seq;
	char http_ok_head[11]="HTTP/1.1 ";
	int result;

	if(is_b_s && !mail_info->is_complished){
		result = write_to_mail(mail_info, data, datalen, tcp);
		return result;
	}else if(!strncmp(data,http_ok_head,9)){
	//	get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;

		write_tom_psword(mail_info);
		del_mail_node(mail_info);
		return 0;
	}
	return -1;
}

int tom_str_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	char *tmp2 = NULL;
	size_t len;

	tmp1 = tom_rcv_conv_to_utf8(str);
//	tmp1 = strdup(str);
	if (NULL == tmp1)
		return -1;

	tmp2 = conv_to_xml_symbol(tmp1);
	free(tmp1);
	tmp1 = NULL;
	if (tmp2 == NULL)
		return -1;
	len = strlen(tmp2);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp2, len);
	str[len] = 0;
	free(tmp2);
	tmp2 = NULL;
/*
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
*/
	return 0;
}

int writefile_tom_vip_rcvmail(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp_str = NULL;
	size_t len;
	int result;

	pstart = strstr(mail_info->recive_data, "\xd6\xf7\xa1\xa1\xcc\xe2\xa3\xba</th>");//search 主题
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pstart = strstr(pstart, "<span id=\"text_subject\">");
	if (pstart == NULL)
		return -1;
	pstart += 24;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;

	pstart = strstr(pend, "\xc8\xd5\xa1\xa1\xc6\xda\xa3\xba</th>");//search 日 期
	if (pstart == NULL)
		return -1;
	pstart += 13;
	pstart = strstr(pstart, "<span id=\"text_date\">");
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
	
	pstart = strstr(pend, "\xb7\xa2\xbc\xfe\xc8\xcb\xa3\xba</th>");//search 发件人
	if (pstart == NULL)
		return -1;
	pstart += 13;
	pstart = strstr(pstart, "<span id=\"text_form\">");
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	pstart = strstr(pend, "\xca\xd5\xbc\xfe\xc8\xcb\xa3\xba</th>");//search 收件人 
	if (pstart == NULL)
		return -1;
	pstart += 13;
	pstart = strstr(pstart, "<span id=\"text_to\">");
	if (pstart == NULL)
		return -1;
	pstart += 19;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	
	pstart = strstr(pend, "\xb3\xad\xa1\xa1\xcb\xcd\xa3\xba</th>");//search 抄送 
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pstart = strstr(pstart, "<span id=\"text_cc\">");
	if (pstart == NULL)
		return -1;
	pstart += 19;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
	memcpy(mail_info->cc, pstart, len);
	mail_info->cc[len] = 0;
	
	pstart = strstr(pend, "<div id=\"OrgInniHtml\"");
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pstart = strstr(pstart, ">");
	if (pstart == NULL)
		return -1;
	pstart += 1;
	pend = strstr(pstart, "\n</body>\n</html>");
	if(pend == NULL)
		return -1;
	*pend = 0;
	mail_info->content = strdup(pstart);
	if (NULL == mail_info->content)
		return -1;

	result = tom_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = tom_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;

	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = tom_conv_to_utf8(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (mail_info->content == NULL)
		return -1;

	clear_from(mail_info->from);

	create_dir(mail_info->save_path, "tom", mail_info->from);
	write_to_file(mail_info);
    return -1;
}

Mail_info *find_tom_mail(char id[MAX_ID_LEN+1], int flag)
{
	Mail_info *mail_info = mail_tab.head->next;
	while (mail_info != NULL) 
	{
		if (!strcmp(id, mail_info->mail_id))
        {            
            if ((0==flag&&NULL!=mail_info->content) ||(1==flag&&NULL==mail_info->content))
                return mail_info;
		}
		mail_info = mail_info->next;
	}
	return NULL;
}

int writefile_tom_rcvmail_new(Mail_info *mail_info)
{
    if (NULL==mail_info->mail_data || NULL==mail_info->recive_data)//OFO 重组乱序的包，不然看到mail_data内容 lihan 2.28
        return -1;        
    char *p1 = NULL,*p2 = NULL, *tmp = NULL;
    int len = 0;
    len = get_tom_recv_id(mail_info->mail_data, mail_info->mail_id);
    if (-1 == len)
        return -1;
    if (0x0722 == mail_info->mail_type)
    {
        p1 = strstr(mail_info->recive_data, "<input type=\"hidden\" id=\"fromINBOX");
        if (NULL == p1)
        return -1;
        char patternfrom[] = "<input type=\"hidden\" id=\"fromINBOX.+?\" value=\"(.*)\">.*?<input type=\"hidden\" id=\"toINBOX";
        char patternto[] = "<input type=\"hidden\" id=\"toINBOX.+?\" value=\"(.*?)\">.*?<input type=\"hidden\" id=\"ccINBOX";
        char patterncc[] = "<input type=\"hidden\" id=\"ccINBOX.+?\" value=\"(.*?)\">.*?<input type=\"hidden\" id=\"subjectINBOX";
        char patternsubject[] = "<input type=\"hidden\" id=\"subjectINBOX.+?\" value=\"(.*?)\">.*?<input type=\"hidden\" id=\"uidINBOX";
        if (-1 != regcompile_1(p1,patternfrom,mail_info->from,MAX_FROM_LEN))
            clear_from(mail_info->from);
        //printf("from:%s\n", mail_info->from);
        if (-1 != regcompile_1(p1,patternto,mail_info->to,MAX_TO_LEN))
            clear_from(mail_info->to);
        //printf("to:%s\n", mail_info->to);
        if (-1 != regcompile_1(p1,patterncc,mail_info->cc,MAX_CC_LEN))
            clear_from(mail_info->cc);
        //printf("cc:%s\n", mail_info->cc);
        regcompile_1(p1,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
        //printf("subject:%s\n", mail_info->subject);  //........
		
		///////////////////////add time  lihan 2017.2.28  入库提示错误，加时间 //////////
		////////////////////////<div class="hg" name="date">2017-02-27 13:53:09</div>//////////////
		char *pstart = NULL;
	    char *pend = NULL;
	    size_t len;
		pstart = strstr(mail_info->recive_data, "<div class=\"hg\" name=\"date\">");//search date ............ date lihan
		//printf("pstart:......%s",pstart);
	    if(pstart == NULL)
		return -1;
	    pstart += 28;
	    pend = strstr(pstart, "<");
		//printf("pend:......%s",pend);
	    if (pend == NULL)
		return -1;
	    len = pend - pstart;
	    len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	    memcpy(mail_info->sent_time, pstart, len);
	    mail_info->sent_time[len] = 0;
		//printf("time:......%s",mail_info->sent_time);//
		///////////////////////add time  lihan 2017.2.28  入库提示错误，加时间 //////////
		
        Mail_info *content_node = find_tom_mail(mail_info->mail_id, 0);
        if (NULL == content_node)
            return -2;
        mail_info->content = content_node->content;
        content_node->content = NULL;
        create_dir(mail_info->save_path, "tom", mail_info->from);
        write_to_file(mail_info);
		delete_mail_info(content_node);
        return -1;
    }
    else if (0x0723 == mail_info->mail_type)
    {
        p1 = strstr_2(mail_info->recive_data, "<body>");
        if (NULL == p1)
            return -1;
        p1 += 6;
        p2 = strstr_2(p1, "</body>");
        len = p2 - p1;
        mail_info->content = (char *)malloc(len+1);
        memcpy(mail_info->content,p1, len);
        mail_info->content[len] = 0;
        tmp = clear_html_tag(mail_info->content);
        free(mail_info->content);
        mail_info->content =  tmp;
        //printf("content:%s\n", mail_info->content);
        Mail_info *main_node = find_tom_mail(mail_info->mail_id, 1);
        if (NULL == main_node)
            return -2;
        main_node->content = mail_info->content;
        mail_info->content = NULL;
        //printf("id:%s\n", mail_info->mail_id);
        create_dir(main_node->save_path, "tom", main_node->from);
	    write_to_file(main_node);
        delete_mail_info(main_node);
        return -1;
    }
    
}

int writefile_tom_rcvmail(Mail_info *mail_info)
{
    if (NULL==mail_info->recive_data && NULL!=mail_info->body)
    {
        mail_info->recive_data = mail_info->body;
        mail_info->body = NULL;
        mail_info->recive_length = mail_info->bodyLen;
    }
    
    if (0x0722==mail_info->mail_type || 0x0723==mail_info->mail_type)
        return writefile_tom_rcvmail_new(mail_info);

	if (!strncmp(mail_info->mail_data, "GET /coremail/fcg/ldmsapp?funcid=readlett&sid=", 46))
	{
		char * i, * j;
		i = strstr(mail_info->mail_data, "&mid=");
		if(i == NULL)
		{
			return -1;
		}
		i += 5;
		j = strstr(i, "%");
		if(j == NULL)
		{
			return -1;
		}
		int len = j - i;
		len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
		memcpy(mail_info->mail_id, i, len);
		mail_info->mail_id[len] = 0;
		//htmldecode_full(mail_info->mail_id, mail_info->mail_id);
		//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
	}
	
    char *hostp = NULL;

	mail_info->is_complished = 1;
	hostp = strstr(mail_info->mail_data, "Host: ");
	if (hostp == NULL)
		return -1;
    if (memfind(hostp, "163.net", 50) != NULL)
		return writefile_tom_vip_rcvmail(mail_info);
    
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp_str = NULL;
	size_t len;
     ////<div class="hg" name="date">2017-02-27 13:53:09</div>        lihan 2017.2.28 /////////
	pstart = strstr(mail_info->recive_data, "<span id=\"text_date\">");//search 发送时间 
	if(pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
	
	pstart = strstr(pend, "<span id=\"text_form\">");//search 发信人
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	pstart = strstr(pend, "<th>\xd6\xf7\xa1\xa1\xcc\xe2\xa3\xba</th>");//search 主题
	if (pstart == NULL)
		return -1;
	pstart += 17;
	pstart = strstr(pstart, ">");
	if (pstart == NULL)
		return -1;
	pstart += 1;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;

	char *tmp_p1 = NULL;
	tmp_p1 = clear_html_symbol(mail_info->subject);
	memset(mail_info->subject, 0, MAX_SUBJ_LEN + 1);
	strcpy(mail_info->subject, tmp_p1);
	free(tmp_p1);
	tmp_p1 = NULL;
	//printf("mail_info->subject: %s\n", mail_info->subject);

	pstart = strstr(pend, "<span id=\"text_to\">");//search 收件人 
	if (pstart == NULL)
		return -1;
	pstart += 19;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	
	pstart = strstr(pend, "<span id=\"text_cc\">");//search 抄送人 
	if (pstart == NULL)
		return -1;
	pstart += 19;
	pend = strstr(pstart, "<");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
	memcpy(mail_info->cc, pstart, len);
	mail_info->cc[len] = 0;

	pstart = strstr(pend, "<div id=\"OrgInniHtml\" ");
	if (pstart != NULL) {
	    pstart = strstr(pstart, ">");
	    if (pstart == NULL)
		    return -1;
	    pstart += 1;
    	pend = strstr(pstart, "</div>");
		if (pend == NULL)
			return -1;
	    *pend = 0;
    } else {
        pstart = strstr(pend, "<body>");
        if (pstart == NULL)
            return -1;
        pstart += 6;
        pend = strstr(pstart, "</body>");
        if (pend == NULL)
            return -1;
        *pend = 0;
    }
	mail_info->content = strdup(pstart);
	if (NULL == mail_info->content)
		return -1;

    int result = 0;
	result = tom_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;

	tmp_p1 = clear_kh2(mail_info->from);
	memset(mail_info->from, 0, MAX_FROM_LEN + 1);
	strcpy(mail_info->from, tmp_p1);
	free(tmp_p1);
	//printf("mail_info->from: %s\n", mail_info->from);	

	result = tom_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;

	tmp_p1 = clear_kh2(mail_info->to);
	memset(mail_info->to, 0, MAX_TO_LEN + 1);
	strcpy(mail_info->to, tmp_p1);
	free(tmp_p1);

	//printf("mail_info->to: %s\n", mail_info->to);	

	result = tom_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		return -1;

	result = tom_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;

	tmp_p1 = clear_kh2(mail_info->cc);
	memset(mail_info->cc, 0, MAX_CC_LEN + 1);
	strcpy(mail_info->cc, tmp_p1);
	free(tmp_p1);

	//printf("mail_info->cc: %s\n", mail_info->cc);

	result = tom_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	//printf("mail_info->subject: %s\n", mail_info->subject);

/*
	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = tmp_str;
	tmp_str = NULL;
*/

    tmp_str = clear_html_tag(mail_info->content);
    if (tmp_str == NULL)
        return -1;
    free(mail_info->content);
	mail_info->content = tom_rcv_conv_to_utf8(tmp_str);
    free(tmp_str);
    tmp_str = NULL;
    if (mail_info->content == NULL)
        return -1;

	clear_from(mail_info->from);

	create_dir(mail_info->save_path, "tom", mail_info->from);
	write_to_file(mail_info);
    return -1;
}

int analyse_tom_rcvmail(void *mail_info,PacketInfo *packetInfo,int is_to_s)
{
    return analyse_recv((Mail_info *)mail_info, packetInfo, is_to_s, writefile_tom_rcvmail);
}

int get_tom_attid(Attach_info *attach_info)
{
    char *data = attach_info->ok_data;
    if (0x0763 == attach_info->attach_type)
    {
        get_tom_recv_id(data, attach_info->ID_str);
        if (0==attach_info->attach_name)
            arrcpy(attach_info->attach_name, data, "filename=", "&", 9, MAX_PATH_LEN);
    }
    else
    {
		int len;
		char *front, *back;
		front = strstr(data, "&mid=");
		if(front == NULL)
			return 0;
		front += 5;
		back = strstr(front, "%");
		if(back == NULL)
			return 0;
		len = back - front;
		len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
		memcpy(attach_info->ID_str, front, len);
		attach_info->ID_str[len] = '\0';
    }
}

int analyse_tom_down_attach(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_downattach(node, packetInfo, is_to_s, get_tom_attid);
}

int analyse_tom(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
    if (0 == data_len)
        return 0;

	unsigned int type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;

		switch (type) 
		{
    		case 0x11:
    			result = analyse_tom_mail(mail_info, data, data_len, ptcp, is_to_s);
    			break;
            case 0x12:
                result = analyse_tom_mail2(mail_info, data, data_len, ptcp, is_to_s);
        		break;
    		case 0x01:
    			result = analyse_tom_psword1(mail_info,data,data_len,ptcp,is_to_s);
    			break;
    		case 0x02:
            case 0x03:
    			result = analyse_tom_psword2(mail_info,data,data_len,ptcp,is_to_s);
    			break;
    		case 0x21:
            case 0x22:
            case 0x23:
    			result = analyse_tom_rcvmail((void *)mail_info, packetInfo, is_to_s);
    			break;
            default:
                break;
		}
		
		if (result == -1)
			delete_mail_info(mail_info);
	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		if (type == 0x61)
			result = analyse_tom_attach(attach_info, data, data_len, ptcp, is_to_s);
        
        if (type == 0x62)
        {
            result = analyse_tom_attach1(attach_info, data, data_len, ptcp, is_to_s);
        }
        
		if (type == 0x41)
			result = analyse_tom_delete(attach_info, data, data_len, ptcp, is_to_s);
        
		if (type == 0x64 || type == 0x63)
		{
            result = analyse_tom_down_attach((void *)attach_info, packetInfo, is_to_s);
		}
        
		if (result == -1)
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}
