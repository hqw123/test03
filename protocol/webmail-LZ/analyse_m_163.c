#include "common.h"
/*
char *conv_163_to_utf8(char *src)
{
	char *tmp_str = NULL, *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	utf8_len = len * 3 / 2 + 1;
	dest = (char *)malloc(utf8_len + 1);
	if (NULL == dest) {
		fprintf(stderr, "webmail:conv_163_to_utf8(): malloc() return NULL\n");
		return NULL;
	}
	result = code_convert("gb18030", "utf-8", src, len, dest, utf8_len);
	if (-1 == result) {
		fprintf(stderr, "webmail:conv_163_to_utf8(): code_convert() return NULL\n");
		return NULL;
	} else { 
		return dest;
	}
}

int str_163_convert1(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = conv_to_xml_symbol(str);
	if (tmp1 == NULL) {
		fprintf(stderr, "webmail:str_163_convert1(): conv_to_xml_symbol() return NULL\n");
		return -1;
	}
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);

	return 0;
}
*/
int writefile163_m(Mail_info *mail_info)
{
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL, *tmp_str = NULL, *sit;
	size_t len, total_len;
	int result, fd, n, i = 0, flag = 0;
	Attachment *attachment = NULL;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

	if(!strstr(mail_info->mail_data,"action%22%3Edeliver%"))
		return -1;

	htmldecode_full(mail_info->mail_data, mail_info->mail_data);
	
	p1 = strstr(mail_info->mail_data, "<string name=\"id\">");
	sit=p1;
	if (p1 != NULL) 
	{
		p1 += 18;
		p2 = strstr(p1, "</string>");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		if (len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(ID, p1, len);
		ID[len] = 0;
		p2 += 8;
	} 
	else 
	{
		ID[0] = 0;
		LOG_WARN("webmail:writefile163(): can not find ID\n");
	}

	p1 = strstr(mail_info->mail_data, "<string name=\"account\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailfrom start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailfrom end\n");
		return -1;
	}
	p3 = memfind(p1, "&lt;", len);
	if (p3 != NULL) 
	{
		p2 = memfind(p1, "&gt;", len);
		if (p2 != NULL && p2 > p3 && p2 - p1 < len) 
		{
			p1 = p3 + 4;
			len = p2 - p1;
		}
	}
	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	p2 += 8;

	p1 = strstr(p2, "<array name=\"to\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailto start\n");
		return -1;
	}
	p1 += 17;
	p3 = strstr(p1, "</array>");
	if (p3 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailto end\n");
		return -1;
	}
	total_len = 0;
	p2 = p1;
	while (p2 < p3) 
	{
		p1 = strstr(p2, "<string>");
		if (p1 == NULL)
			break ;
		p1 += 8;
		p2 = strstr(p1, "</string>");
		if (p2 == NULL)
			break ;
		len = p2 - p1;
		if (p2 == NULL || (total_len + len + 1) > MAX_TO_LEN)  //为�?��?个�?�箱?��????��??��??
			break ;
		memcpy(mail_info->to + total_len, p1, len);
		total_len += len;
		mail_info->to[total_len] = ';';
		total_len++;
		mail_info->to[total_len] = 0;
		p2 += 9;
	}
	p2 = p3 + 17;

	p1 = strstr(mail_info->mail_data, "<array name=\"cc\">");
	if (p1 != NULL) 
	{
		p1 += 17;
		p3 = strstr(p1, "</string></array>");
		if (p3 == NULL)
			return -1;
		total_len = 0;
		p2 = p1;
		while (p2 < p3) 
		{
			p1 = strstr(p2, "<string>");
			if (p1 == NULL)
				break ;
			p1 += 8;
			p2 = strstr(p1, "</string>");
			if (p2 == NULL)
				break ;
			len = p2 - p1;
			if (p2 == NULL || (total_len + len + 1) > MAX_CC_LEN)
				break ;
			memcpy(mail_info->cc + total_len, p1, len);
			total_len += len;
			mail_info->cc[total_len] = ';';
			total_len++;
			mail_info->cc[total_len] = 0;
			p2 += 9;
		}
		p2 = p3 + 17;
	} 
	else 
	{
		mail_info->cc[0] = 0;
	}

	p1 = strstr(mail_info->mail_data, "<array name=\"bcc\">");
	if (p1 != NULL) 
	{
		p1 += 18;
		p3 = strstr(p1, "</string></array>");
		if (p3 == NULL)
			return -1;
		total_len = 0;
		p2 = p1;
		while (p2 < p3) 
		{
			p1 = strstr(p2, "<string>");
			if (p1 == NULL)
				break;
			p1 += 8;
			p2 = strstr(p1, "</string>");
			if (p2 == NULL)
				break;
			len = p2 - p1;
			if (p2 == NULL || (total_len + len + 1) > MAX_BCC_LEN)
				break;
			memcpy(mail_info->bcc + total_len, p1, len);
			total_len += len;
			mail_info->bcc[total_len] = ';';
			total_len++;
			mail_info->bcc[total_len] = 0;
			p2 += 9;
		}
		p2 = p3 + 17;
	} 
	else 
	{
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "<string name=\"subject\">");
	if (p1 == NULL)
		p1 = strstr(mail_info->mail_data, "<string name=\"subject\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailsubject start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) {
		LOG_WARN("webmail:writefile163(): can not find mailsubject end\n");
		return -1;
	}
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	p2 += 8;

	p1 = strstr(p2, "<string name=\"content\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailcontent start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailcontent end\n");
		return -1;
	}
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL) 
	{
		LOG_WARN("webmail:writefile163()\n");
		return -1;
	}
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += 8;

	create_dir(mail_info->save_path, "163" ,mail_info->from);

	if (strstr(p2, "<object name=\"attachments\">") != NULL)
	//if (strstr(sit, "<object name=\"attrs\">") != NULL)
	{
		int fd, atta_fd;
		struct stat st;
		char *mapped = NULL;
		char *p1, *p2;
		char filename[MAX_FN_LEN + 1];
		char writepath[MAX_PATH_LEN + 1];
		Attachment *attachment;
		int flag = 0, i = 0;

		attach_info = find_attach(ID);
		if (attach_info == NULL)
			return -1;       //?��?��?��?��???��??��?????
		
		fd = open(attach_info->path_of_here, O_RDWR);
		if (fstat(fd, &st) < 0) 
		{
			return -1;
		}

		mapped = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (mapped == NULL) 
		{
			close(fd);
			return -1;
		}
		p1 = mapped;
				
		while (1) 
		{
			p1 = strstr(p1, "filename=\"");
			if (p1 == NULL)
				break;
            
			p1 += 10;
			if (*p1 == '\"')
				continue;
            
			p2 = strstr(p1, "\"\r\nContent-Type: ");
			if (p2 == NULL)
				break;
            
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL) 
			{
				LOG_WARN("webmail:writefile163(): attachment node malloc() return NULL\n");
				return -1;
			}
			if (!flag) 
			{
				mail_info->attach = attachment;
				attachment->next = NULL;
				flag = 1;
			} 
			else 
			{
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
            
			len = p2 - p1;
			if (len > MAX_PATH_LEN)
				len = MAX_PATH_LEN;
            
			memcpy(attachment->path_of_sender, p1, len);
			attachment->path_of_sender[len] = 0;
			i++;
			tmp_str = conv_163_to_utf8(attachment->path_of_sender);
			if (tmp_str == NULL) 
			{
				LOG_WARN("webmail:writefile163(): conv_163_to_utf8() return NULL\n");
				return -1;
			}
			get_file_name(tmp_str, filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
			free(tmp_str);
			tmp_str = NULL;
			p1 = strstr(p2, "\r\n\r\n");
			if (p1 == NULL) 
			{
				LOG_WARN("webmail:writefile163(): can not find attach content start\n");
				return -1;
			}
			p1 += 4;
			len = st.st_size - (p1 - mapped);
			p2 = memfind(p1, "Content-Disposition: form-data; name", len);//��????��??��??boundary ??��?��??�好��??��????件信?��????头已��?丢�?��?
			if (p2 == NULL) 
			{
				LOG_WARN("webmail:writefile163(): can not find attach content end\n");
				return -1;
			}
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			atta_fd = open(writepath, O_RDWR | O_CREAT, file_mode);
			if (atta_fd == -1) 
			{
				p1 = p2;
				continue;
			}
			write(atta_fd, p1, p2 - p1);
			close(atta_fd);
			trim_attach(writepath, 45);
			p1 = p2;
		}
		munmap(mapped, st.st_size);
		close(fd);
		mail_info->num_of_attach = i;
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);
	} 
	else 
	{
		//printf("22222\n");
	
		char filename[MAX_FN_LEN + 1];
		Attach_info *attach_tmp;
		Attachment *attachment;
		Attach_info *attach_info = attach_tab.head->next;
		int i = 0, flag = 0;

		while (attach_info != NULL) 
		{
			//printf("attach info ...\n");
			//printf("%s    ...    %s\n", attach_info->ID_str, ID);
			if (!strcmp(attach_info->ID_str, ID))
			{
				//printf("11111111\n");
				i++;
				get_file_name(attach_info->path_of_sender, filename);
				attachment = (Attachment *)malloc(sizeof(Attachment));
				if (attachment == NULL)
					break;
				//printf("22222222\n");
				//snprintf(attachment->loc_name, MAX_FN_LEN, "attach%d_%s", i, filename);
				snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
				snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				if (!flag) 
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
				snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
				//printf("attachment->loc_name : %s\n", attachment->loc_name);
				//printf("attachment->loc_filename : %s\n", attachment->loc_filename);
				//printf("writepath : %s\n", writepath);
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
		
		mail_info->num_of_attach = i;
	}

	result = str_163_convert1(mail_info->to, MAX_TO_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailto convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->cc, MAX_CC_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailcc convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailbcc convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailsubject convert failed\n");
		return -1;
	}

	if (mail_info->content != NULL) 
	{
		tmp_str = conv_to_xml_symbol(mail_info->content);
		if (tmp_str == NULL) 
		{
			LOG_WARN("webmail:writefile163(): mailcontent convert_to_xml_symbol() failed\n");
			return -1;
		}
		free(mail_info->content);
		mail_info->content = clear_html_tag(tmp_str);
		free(tmp_str);
		tmp_str = NULL;
		if (mail_info->content == NULL) 
		{
			LOG_WARN("webmail:writefile163(): mailcontent clear_html_tag() failed\n");
			return -1;
		}
	}

	write_to_file_m(mail_info);
}

int analyse_m_163_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("analyse_m_163_mail...\n");
	int result;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			if (!strncmp(data, "<?xml version=\"1.0\"?><object/>", 32)) 
			{
				return -1;
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		//printf("analyse_163_mail ... mail up ...\n");
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		writefile163_m(mail_info);   //��??? ?????? ?? ???��??
		del_mail_node(mail_info);

		return 0;
	} 
	else 
	{
		return -1;
	}
}

int writefile163_rcvmail_m(Mail_info *mail_info)
{
	size_t len;
	int result;
	char *front, *back, *pstart, *pend;
	char *tmp = NULL;

	strcpy(mail_info->connect_id,mail_info->mail_id);

	pstart = strstr(mail_info->recive_data, "\n'from':['");
	if (pstart == NULL)
		return -1;
	pstart += 10;
	pend = strstr(pstart, "'],\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	pstart = strstr(pend, "\n'to':['");
	if (pstart == NULL)
		return -1;
	pstart += 8;
	pend = strstr(pstart, "'],\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	//printf("mail_info->to : %s\n", mail_info->to);

	pstart = strstr(pend, "\n'cc':['");
	if (pstart != NULL) {
		pstart += 8;
		pend = strstr(pstart, "'],\n");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
		memcpy(mail_info->cc, pstart, len);
		mail_info->cc[len] = 0;
	} else {
		mail_info->cc[len] = 0;
	}
	//printf("mail_info->cc : %s\n", mail_info->cc);

	pstart = strstr(pend, "\n'bcc':['");
	if (pstart != NULL) {
		pstart += 8;
		pend = strstr(pstart, "'],\n");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		len = (len > MAX_BCC_LEN ? MAX_BCC_LEN : len);
		memcpy(mail_info->bcc, pstart, len);
		mail_info->bcc[len] = 0;
	} else {
		mail_info->bcc[0] = 0;
	}
	//printf("mail_info->bcc : %s\n", mail_info->bcc);
	makeStr(mail_info->from);
	makeStr(mail_info->to);
	makeStr(mail_info->cc);
	makeStr(mail_info->bcc);

	pstart = strstr(pend, "\n'subject':'");
	if (pstart == NULL)
		return -1;
	pstart += 12;
	pend = strstr(pstart, "',\n'");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	pstart = strstr(pend, "\n'html':{\n");
	if (pstart == NULL)
	{
		pstart = strstr(pend, "\n'text':{\n");
		if(pstart == NULL)
			return -1;
	}
	pstart = strstr(pstart, "\n'content':'");
	if (pstart == NULL)
		return -1;
	pstart += 12;
	pend = strstr(pstart, "'},\n'");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	tmp=(char *)malloc(len+1);
	if(tmp!=NULL)
	{
		memset(tmp,0,len+1);
		memcpy(tmp,pstart,len);
		mail_info->content=clear_html_tag(tmp);
		free(tmp);
		tmp = NULL;
	}
	//printf("mail_info->content : %s\n", mail_info->content);

	pstart = strstr(mail_info->recive_data, "\n'sentDate':new Date(");
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "),");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (len > MAX_TIME_LEN)
		return -1;
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
	int i;
	pend = mail_info->sent_time;
	for (i = 0; i < 5; i++) 
	{
		pstart = strstr(pend, ",");
		if (pstart == NULL)
			break;
		switch (i) 
		{
			case 0:
				*pstart = '-';
				break;
			case 1:
				*pstart = '-';
				{
					char *p = pstart - 1;
					(*p)++;
					if (*p > '9') {
						*p -= 10;
						memmove(p, p+1, MAX_TIME_LEN - (p - mail_info->sent_time + 1) - 1); 
						*p = '1';
					}
				}
				break;
			case 2:
				*pstart = ' ';
				break;
			case 3:
			case 4:
				*pstart = ':';
				break;
		}
		pend = pstart;
	}

	create_dir(mail_info->save_path, "163" ,mail_info->from);
	write_to_file_m(mail_info);
	del_mail_node(mail_info);
	
	return 0;
}

int analyse_m_163_rcvmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;
	
	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			return write_to_mail(mail_info, data, data_len, ptcp);
		}
	} 
	else 
	{
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{
			if(strstr(data, "Content-Encoding: gzip"))
				flag = 1;
			else
				flag = 0;
            
			if(strstr(data, "Transfer-Encoding: chunked\r\n"))
				flagg = 1;
			else
				flagg = 0;
		}
		if (!mail_info->is_complished)
		{
			if(flagg == 0)
			{
				//printf("\ngzip ...\n");
				result = write_to_okdata(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				//printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 1;
			}
            
			if (result == -1)
			{
				//printf("write_to_okdata ... Error!\n");
				return -1;
			}
		}
		if (data_len < 10 /*|| (ntohl(ptcp->seq) + data_len - mail_info->http_seq >= mail_info->recive_length)*/ || ptcp->fin || !memcmp(data + data_len - 5, "0\r\n\r\n", 5) || !memcmp(data + data_len -2, "\0\0", 2) || !strncmp(data + data_len - 2, "}}",2))
		{
			//printf("analyse_163_rcvmail3 over...\n");
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					//printf("111111\n");
					Chunked(mail_info);
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(mail_info->recive_data, mail_info->recive_length, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(mail_info->recive_data, mail_info->recive_length, &dest);
							if(result == -1) 
                                result = decomp_gzip(mail_info->recive_data, mail_info->recive_length, &dest);
						}
					}
				}
				else
				{
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length - 2, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(mail_info->recive_data, mail_info->recive_length - 2, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(mail_info->recive_data, mail_info->recive_length - 2, &dest);
							if(result == -1) 
                                result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 2, &dest);
						}
					}
				}
                
				if (result == -1)
				{
					LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
                
				free(mail_info->recive_data);
				mail_info->recive_data = dest;         //printf("\nmail_info->recive_data = %s\n",dest);
				dest = NULL;
			}
            
			get_cookie(mail_info->mail_data, mail_info->cookie_data);
			htmldecode_full(mail_info->mail_data, mail_info->mail_data);
            
			char * i,* j;
			int len;
			i = strstr(mail_info->mail_data, "<string name=\"id\">");
			if(i == NULL)
				return -1;
			i += 18;
			j = strstr(i, "</string>");
			if(j == NULL)
				return -1;
			len = j - i;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(mail_info->mail_id, i, len);
			mail_info->mail_id[len] = '\0';
			htmldecode_full(mail_info->mail_id, mail_info->mail_id);
			writefile163_rcvmail_m(mail_info);
			//del_mail_node(mail_info);
			
			return 0;
		}
	}
}

int analyse_m_163_down_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("                         analyse_163_down_attach\n");
	unsigned int seq = ntohl(ptcp->seq);
	static int dataLen = 0;
	static int isChunked = -1;

	if (attach_info->is_writing == 1)
	{//printf("\n1\n");
		attach_info->ok_len += data_len;
		if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
		{//printf("\n2\n");
			/*memcpy(attach_info->recive_data+(attach_info->ok_len-data_len-dataLen), data, attach_info->recive_length-(attach_info->ok_len-data_len-dataLen));
			if(attach_info->ok_gzip)
			{printf("\n3\n");
				char *tmp = (char *)malloc(attach_info->recive_length*30);
				memset(tmp,0,attach_info->recive_length*30);
				decomp_gzip_2(attach_info->recive_data,attach_info->recive_length-1000,&tmp);
				if(tmp == NULL) 
					return;
				free(attach_info->recive_data);
				attach_info->recive_data = tmp;
				attach_info->recive_length=strlen(attach_info->recive_data)+1000;
			}printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
				return -1;
			write(fd, attach_info->recive_data, attach_info->recive_length-1000);
			close(fd);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;*/
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
			{
				return -1;
			}
			lseek(fd, 0, SEEK_END);
			if(isChunked)
			{
				data_len -= 7;
			}
			write(fd, data, data_len);
			close(fd);
			UpdateAttachNew_m(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}
		else
		{//printf("\n4\n");//printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
			//memcpy(attach_info->recive_data+(attach_info->ok_len-data_len-dataLen), data, data_len);
			if(ptcp->rst == 1) return -1;
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
			{
				return -1;
			}
			lseek(fd, 0, SEEK_END);
			write(fd, data, data_len);
			close(fd);
		}
		
		/*if(ptcp->fin == 1 || strstr(data + data_len - 4, "\r\n\r\n"))
		{
			UpdateAttachNew_m(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}*/
	}
	else
	{//printf("\n5\n");
		if(!strncmp(data, "HTTP/1.", 7))
		{//printf("\n6\n");
			if(strncmp(data+8," 200 OK\r\n",9)) return -1;
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

			front = strstr(data, "; filename=\"");
			if(front == NULL)
				return -1;
			else
			{
				front += 12;
				back = strstr(front, "\"\r\n");
				if(back == NULL)
					return 0;
				len = back - front;
				len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
				memcpy(attach_info->attname, front, len);
				attach_info->attname[len] = '\0';
			}

			htmldecode_full(attach_info->attname, attach_info->attname);
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",attach_down_path, tv.tv_sec, tv.tv_usec);
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);

			front = strstr(data, "\r\n\r\n");
			front += 4;
			attach_info->recive_length = get_http_length(data);
			attach_info->recive_length += 1000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL)
				return -1;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			if(strstr(data,"Transfer-Encoding: chunked\r\n"))
			{
				isChunked = 1;
				front = strstr(front,"\r\n");
				front += 2;
			}
			if(strstr(data,"Content-Encoding: gzip\r\n"))
			{
				attach_info->ok_gzip = 1;
			}
			/*if(front == NULL)
			{
				front = strstr(data, "Connection: keep-alive\r\n\r\n");
				if(front == NULL)
					return 0;
				front += 26;
			}
			else
				front += 21;*/
			attach_info->ok_len = data_len;
			dataLen = front-data;
			attach_info->is_writing = 1;
			if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
			{
				memcpy(attach_info->recive_data, front, attach_info->recive_length-1000);
				if(attach_info->ok_gzip)
				{
					char *tmp = (char *)malloc(attach_info->recive_length*30);
					memset(tmp,0,attach_info->recive_length*30);
					decomp_gzip_2(attach_info->recive_data,attach_info->recive_length-1000,&tmp);
					if(tmp == NULL) 
						return -1;
					free(attach_info->recive_data);
					attach_info->recive_data = tmp;
					attach_info->recive_length=strlen(attach_info->recive_data)+1000;
				}//printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
				fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
				if (fd == -1)
					return -1;
				write(fd, attach_info->recive_data, attach_info->recive_length-1000);
				close(fd);
				UpdateAttachNew_m(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
				return -1;
			}
			else
			{
				//memcpy(attach_info->recive_data, front, dataLen);
				fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
				if (fd == -1)
					return -1;
				write(fd, front, data_len - (front - data));
				close(fd);
			}
		}
		else
		{//printf("\n7\n");
			if(data_len>0 && strstr(data,"Range: bytes=")) return -1;
			int len;
			char *front, *back;
			front = strstr(data, "&mid=");
			if(front == NULL)
				return 0;
			front += 5;
			back = strstr(front, "&part=");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(attach_info->ID_str, front, len);
			attach_info->ID_str[len] = '\0';
			htmldecode_full(attach_info->ID_str, attach_info->ID_str);
		}
	}
	
	return 1;
}

int analyse_m_163_rcvmail_attach(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	static int n;
	static int attach_length = -1, getted_size = 0;

	if (is_to_s)
	{
		if(data_len>0 && strstr(data,"Range: bytes=")) return -1;
		if(!strncmp(data, "GET /", 5))
		{
			int len;
			char *front, *back;
			front = strstr(data, "&mid=");
			if(front == NULL)
				return 0;
			front += 5;
			back = strstr(front, "&");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(mail_info->mail_id, front, len);
			mail_info->mail_id[len] = '\0';
			htmldecode_full(mail_info->mail_id, mail_info->mail_id);
		}
	}
	else
	{
		if(!strncmp(data,"HTTP/1.1 4",10)) return -1;
		if(!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			if(strstr(data, "; filename=\"") == NULL) return -1;
			mail_info->recive_length = get_http_length(data);
			n = judge_chunk(data);
			//printf("mail_info->recive_length = %d\n", mail_info->recive_length);
			if(mail_info->recive_length <= 0)
			{
				//printf("mail_info->recive_length < 0\n");
				return -1;
			}
			mail_info->recive_length += 1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL)
			{
				//printf("mail_info->recive_data == NULL\n");
				return -1;
			}
			memset(mail_info->recive_data, 0, mail_info->recive_length);
			mail_info->http_seq = seq;
		}
		if (mail_info->recive_data != NULL)
		{
			if(ptcp->rst == 1) return -1;
			off_seq = seq-mail_info->http_seq;
			range = off_seq+data_len;
			if (range>mail_info->recive_length)
			{
				//mail_info->recive_data = realloc(mail_info->recive_data,mail_info->recive_length+8047);
				mail_info->recive_data = (char *)realloc(mail_info->recive_data,range+1);
				if(mail_info->recive_data == NULL)
					return -1;
				mail_info->recive_length=range;
				memcpy(mail_info->recive_data + off_seq, data, data_len); 
			}
			else
			{
				memcpy(mail_info->recive_data+off_seq, data, data_len);
			}
		}
		if (/*ptcp->fin == 1 || */(data_len>0&&!memcmp(mail_info->recive_data+range-7,"\r\n0\r\n\r\n",7)) ||
		    (mail_info->recive_data != NULL&&mail_info->recive_length-1000 == range-(strstr(mail_info->recive_data,"\r\n\r\n")-mail_info->recive_data+4)))
		{
			mail_info->is_complished = 1;
			attach_len = mail_info->recive_length - 1000;
			write_attach_down_2(mail_info, attach_len,n);
			del_mail_node(mail_info);
		}

		return 0;
	}
}

int analyse_m_163_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	//char file_name_pattern[] = "filename=\"(.{1,150})\"\r\nContent-Type: ";
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	char *p = NULL;
	char *temp = NULL;
	struct timeval tv;
	struct timezone tz;
	int result;
	char ID[MAX_ID_LEN + 1];
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int off_seq;
	size_t len;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	//p = strstr(attach_info->ok_data, "filename=\"");
	p = strstr(attach_info->ok_data, "filename=\"");
	if (p == NULL)
		return 0;
	p = strstr(p, "\r\n\r\n");
	if (p == NULL) {
		return 0;
	}
	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1

	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);
	if (result == -1)
		return -1;
	result = regcompile_1(attach_info->ok_data, "&composeId=(.*) HTTP/1.1\r\n", ID, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}
	strcpy(attach_info->ID_str, ID);//printf("\nattach_info->ID_str = %s\n",attach_info->ID_str);

	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);//3
	fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd,p,off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4
	return 0;
}

int analyse_m_163_attach(Attach_info *attach_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int result;

	if (is_b_s){
		if (attach_info->is_writing) {//printf("\n%d\n",datalen);
			result = write_to_attach(attach_info, data, datalen+1, seq);
			//result = write_to_attach(attach_info, data, datalen+47, seq);
		} else {
			result = analyse_m_163_attach_head(attach_info,data,datalen,seq);
		}
		return result;
	} else if (!attach_info->is_get_ok){
		trim_attach(attach_info->path_of_here, 47);
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
			attach_info->is_writing = 0;
			attach_info->is_get_ok = 1;
			attach_info->is_complished = 1;
			return 0;
		} else {
			return -1;
		}
	}
}

int analyse_m_163(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned short type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
			case 0x11:
				//printf("analyse_163_mail ...\n");
				result = analyse_m_163_mail(mail_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x22:
				//printf("analyse_m_163_rcvmail ...\n");
				result = analyse_m_163_rcvmail(mail_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x24:
				result = analyse_m_163_rcvmail_attach(mail_info, data, data_len, ptcp, is_to_s);
				break;
		}
		
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			delete_mail_info(mail_info);
		}
	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		switch (type) 
		{
		case 0x63:
			//printf("analyse_163_attach ...\n");
			result = analyse_m_163_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x64: //163 down attach
			//printf("analyse_163_down_attach ...\n");
			result = analyse_m_163_down_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		}
		if (result == -1) 
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}

