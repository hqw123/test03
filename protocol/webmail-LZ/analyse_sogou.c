
#include "common.h"

extern int clear_tag(char *str);
extern char *sohu_conv_to_utf8(char *src);
extern int strtonum(char * size);

int Get_Attach_Num_sogou()
{
	Attach_info *sjs = attach_tab.head->next;
	int i = 0, flag = 0;

	while (sjs != NULL) 
	{
		i++;
		sjs=sjs->next;
	}
	
	return i;
}

void down_content(char * cont)
{
	char *p = cont, *q = cont;
	while(*p)
	{
		if(*p == '\\')
		{
			if(*(p+1) == '\"')
				*q = '\"';
			else
			if(*(p+1) == '\r')
				*q = '\r';
			else
			if(*(p+1) == '\n')
				*q = '\n';
			else
			if(*(p+1) == '\t')
				*q = '\t';
			p += 2;
				
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

char *sohu_old_conv_to_utf8(char *src)
{
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

int sohu_old_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = sohu_old_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
/*
	tmp2 = conv_to_xml_symbol(tmp1);
	free(tmp1);
	tmp1 = NULL;
	if (tmp2 == NULL)
		return -1;
*/
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;

	return 0;
}

char *sogou_conv_to_utf8(char *src)
{
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

char *sogou_rcv_conv_to_utf8(char *src)
{
	char *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	utf8_len = len * 3 / 2 + 1;
	dest = (char *)malloc(utf8_len + 1);
	if (NULL == dest)
		return NULL;
	result = code_convert("gb18030", "utf-8", src, len, dest, utf8_len);

	if (-1 == result)
		return NULL;
	else 
		return dest;
}

int sogou_str_convert(char *str, int max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = sogou_conv_to_utf8(str);
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

int sogou_str_convert2(char *str, int max_len)
{
	char *tmp1 = NULL;
	char *tmp2 = NULL;
	size_t len;

	tmp1 = sogou_rcv_conv_to_utf8(str);
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

int get_sogou_from(char *data, char *mail_from)
{
	char *p1,*p2;
	size_t len;

	p1 = strstr(data, "; SOHUID=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p1 = strstr(p1, "|");
	if (p1 == NULL)
		return -1;
	p1++;
	p2 = strstr(p1, "|");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_FROM_LEN - 11)
		return -1;
	strncpy(mail_from, p1, len);
	mail_from[len] = 0;
	strcat(mail_from, "@sogou.com");

	return 0;
}

int get_old_sohu_from(char *data, char *mail_from)
{
	char *p1,*p2;
	size_t len;

	p1 = strstr(data, "; SOHUID=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p1 = strstr(p1, "|");
	if (p1 == NULL)
		return -1;
	p1++;
	p2 = strstr(p1, "|");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_FROM_LEN - 10)
		return -1;
	strncpy(mail_from, p1, len);
	mail_from[len] = 0;
	strcat(mail_from, "@sohu.com");

	return 0;
}

int get_old_sohu_vip_from(char *data, char *mail_from)
{
	char *p1,*p2;
	size_t len;

	p1 = strstr(data, "; VIPID=");
	if (p1 == NULL)
		return -1;
	p1 = strstr(p1, "|");
	if (p1 == NULL)
		return -1;
	p1++;
	p2 = strstr(p1, "|");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_FROM_LEN)
		return -1;
	strncpy(mail_from, p1, len);
	mail_from[len] = 0;

	return 0;
}

int writefile_sogou(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL , *sit=NULL;
	char *tmp_str;
	int result;
	Attach_info *attach_info, *attach_tmp;
	char ID[MAX_ID_LEN];
	char filename[MAX_FN_LEN];
	char writepath[MAX_PATH_LEN];
	int flag = 0;
	int i = 0;
	size_t len;
	Attachment *attachment = NULL;
	int fd, atta_fd;
	struct stat st;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *mapped = NULL;
	if(strstr(mail_info->mail_data,"&is_send=0&")) return -1;
	get_sogou_from(mail_info->mail_data, mail_info->from);
	
	//printf("from : %s\n",mail_info->from);
	
	sit = strstr(mail_info->mail_data, "SOHUID=");

	p1 = strstr(sit, "&to=");
	if (p1 == NULL)
		return -1;
	//printf("1 ...\n");
	p1 += 4;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	//printf("2 ...\n");
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	
	//printf("to : %s\n",mail_info->to);

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
	else 
	{
		mail_info->cc[0] = 0;
	}
	
	//printf("cc : %s\n",mail_info->cc);

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
	else 
	{
		mail_info->bcc[0] = 0;
	}
	
	//printf("bcc : %s\n",mail_info->bcc);

	p1 = strstr(sit, "&subject=");
	if (p1 == NULL)
		return -1;
	//printf("3 ...\n");
	p1 += 9;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	//printf("4 ...\n");
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	//printf("subject : %s\n",mail_info->subject);
	
	p2 += 9;
	p1 = strstr(sit, "&text=");
	if (p1 == NULL)
		return -1;
	//printf("5 ...\n");
	p1 += 6;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	//printf("7 ...\n");
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	
	//printf("content : %s\n",mail_info->content);

	create_dir(mail_info->save_path, "sogou", mail_info->from);
	p1 = strstr(mail_info->mail_data, "%22attach%22%3A%20%5B");
	if (p1 == NULL)
		return -1;
	//printf("8 ...\n");
	p1 += 21;
	p2 = strstr(p1, "%5D");
	if(p2 == NULL)
		return -1;
	len = p2 - p1;
	memcpy(mail_info->mail_id , p1 , len);
	htmldecode_full(mail_info->mail_id,mail_info->mail_id);
	if(strlen(mail_info->mail_id)>0) strcat(mail_info->mail_id,",");
	//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
	/*if(!(p2 == NULL || p2 - p1 > MAX_ID_LEN))
	{
		//printf("9 ...\n");
		*p2 = 0;
		strcpy(ID, p1);
	}*/
	
	

	attach_info = attach_tab.head->next;
/*	while (attach_info != NULL)
	{
		if (!strcmp(attach_info->ID_str, ID)) 
		//if (attach_info->source_port + 512 == mail_info->source_port)
		{
			del_attach_node(attach_info);
		} 
		else 
		{
			attach_info = attach_info->next;
			continue;
		}

		fd = open(attach_info->path_of_here, O_RDWR);
		if (fstat(fd, &st) < 0) 
		{
			fprintf(stderr, "webmail:writefile_sogou(): fstat() return error");
			return ;
		}

		mapped = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (mapped == NULL) 
		{
			close(fd);
			fprintf(stderr, "webmail:writefile_sogou(): mmap() return error");
			return -1;
		}
		p1 = mapped;		
		while (1) 
		{
			if(p1==NULL)
				break;
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
				break;
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
				continue ;
			memcpy(attachment->path_of_sender, p1, len);
			attachment->path_of_sender[len] = 0;
			tmp_str = sogou_conv_to_utf8(attachment->path_of_sender);
			if (tmp_str == NULL)
				continue;
			get_file_name(tmp_str, filename);
			
			free(tmp_str);
			tmp_str = NULL;
			i++;
			//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			p1 = strstr(p2, "\r\n\r\n");
			p1 += 4;
			unsigned int n = st.st_size - (p1 - mapped);
			p2 = memfind(p1, "Content-Disposition: form-data; name", n);
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			atta_fd = open(writepath, O_RDWR | O_CREAT, file_mode);
			
			//printf("%s\n", p1);
			
			if (atta_fd == -1)
				break;
			if(p2 == NULL)
				write(atta_fd, p1, st.st_size);
			else
				write(atta_fd, p1, p2 - p1);
			close(atta_fd);
			trim_attach(writepath, 45);
			p1 = p2;
		}
		munmap(mapped, st.st_size);
		close(fd);
		unlink(attach_info->path_of_here);
		attach_tmp = attach_info->next;
		delete_attach(attach_info);
		attach_info = attach_tmp;
	}*/
// 
	while (attach_info != NULL) 
	{
		strcat(attach_info->ID_str,",");
		//printf("attach_info->ID_str : %s\n",attach_info->ID_str);
		if (strstr(mail_info->mail_id, attach_info->ID_str))
		{
			i++;
			filename[0] = 0;
			get_file_name(attach_info->path_of_sender, filename);
			
			//printf("filename : %s\n",filename);
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL)
				break;
			
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			
			if (!flag) 
			{
				attachment->next = NULL;
				mail_info->attach = attachment;
				flag = 1;
			} 
			else 
			{
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			//printf("attach path / writepath : %s\n",writepath);
			link(attach_info->path_of_here, writepath);//关联路径
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
	//LOG_INFO("num_of_attach : %d \n",mail_info->num_of_attach);
// 

	result = sogou_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = sogou_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = sogou_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	/*result = sogou_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;*/
	
	tmp_str = sohu_conv_to_utf8(mail_info->subject);
	if (tmp_str == NULL)
		return -1;
	char *sjs = clear_html_tag(tmp_str);

	memset(mail_info->subject, 0, sizeof(mail_info->subject));
	memcpy(mail_info->subject, sjs, strlen(sjs));
	
/*
	int ii = 0;
	while(*sjs)
	{
		mail_info->subject[ii++] = *sjs;
		sjs++;
	}
	mail_info->subject[ii] = '\0';
*/

	free(sjs);
	sjs = NULL;
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->subject)
		return -1;

	tmp_str = sohu_conv_to_utf8(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;
	/*tmp_str = conv_xml_symbol(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = tmp_str;
	tmp_str = NULL;*/
	
	write_to_file(mail_info);
}

int writefile_old_sohu(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL;
	char *tmp_str;
	int result;
	int len;

	get_old_sohu_from(mail_info->mail_data, mail_info->from);

	p1 = strstr(mail_info->mail_data, "&To=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	p1 = strstr(p2, "&Cc=");
	if (p1 != NULL) {
		p1 += 4;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} else {
			mail_info->cc[0] = 0;
		}
	} else {
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "&Bcc=");
	if (p1 != NULL) {
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} else {
			mail_info->bcc[0] = 0;
		}
	} else {
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "&Subject=");
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
	p2 += 15;
	
	p1 = strstr(p2, "&mess=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;

	create_dir(mail_info->save_path, "sohu", mail_info->from);

	char ID[MAX_ID_LEN + 1];
	Attach_info *attach_info;
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	int flag = 0;
	int i = 0;

	Attachment *attachment = NULL;

	p1 = strstr(mail_info->mail_data, "SOHUID=");
	if (p1 == NULL)
		return -1;
	p1 += 7;
	p2 = memfind(p1, "; ", 100);
	if (p2 == NULL)
		p2 = memfind(p1, "\r\n\r\n", 100);
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_ID_LEN)
		len = MAX_ID_LEN;
	memcpy(ID, p1, len);
	ID[len] = 0;

	attach_info = attach_tab.head->next;
	while (attach_info != NULL){
		if (!strncmp(attach_info->ID_str, ID, strlen(ID))) {
			del_attach_node(attach_info);
		} else {
			attach_info = attach_info->next;
			continue;
		}

		i++;
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
			break;
		tmp_str = sohu_old_conv_to_utf8(attach_info->path_of_sender);
		if (tmp_str == NULL)
			break;
		get_file_name(tmp_str, filename);
		free(tmp_str);
		tmp_str = NULL;
		//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		attachment->next = NULL;
		snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
		link(attach_info->path_of_here, writepath);
		unlink(attach_info->path_of_here);
		if(!flag){
			mail_info->attach = attachment;
			flag =1;
		} else {
			attachment->next=mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		delete_attach(attach_info);
		attach_info = attach_info->next;
	}

	mail_info->num_of_attach = i;

	result = sohu_old_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;

	tmp_str = clear_html_tag(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = sohu_old_conv_to_utf8(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (mail_info->content == NULL)
		return -1;
	write_to_file(mail_info);
	return 0;
}

int writefile_old_vip_sohu(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL;
	char *tmp_str;
	int result;
	Attach_info *attach_info, *attach_tmp;
	char ID[MAX_ID_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	int flag = 0;
	int i=0;
	Attachment *attachment = NULL;
	int fd, atta_fd;
	struct stat st;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *mapped;
	size_t len;

	get_old_sohu_vip_from(mail_info->mail_data, mail_info->from);

	p1 = strstr(mail_info->mail_data, "&To=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	p1 = strstr(p2, "&Cc=");
	if (p1 != NULL) {
		p1 += 4;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} else {
			mail_info->cc[0] = 0;
		}
	} else {
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "&Bcc=");
	if (p1 != NULL) {
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} else {
			mail_info->bcc[0] = 0;
		}
	} else {
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "&Subject=");
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
	
	p1 = strstr(p2, "&mess=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;

	create_dir(mail_info->save_path, "sohu", mail_info->from);

	p1 = strstr(mail_info->mail_data, "; VIPID=");
	if (p1 == NULL)
		return -1;
	p1 += 8;
	p2 = strstr(p1, "; JSESSIONID=");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_ID_LEN)
		len = MAX_ID_LEN;
	memcpy(ID, p1, len);

	attach_info = attach_tab.head->next;
	while (attach_info != NULL){
		if (!strcmp(attach_info->ID_str, ID)) {
			del_attach_node(attach_info);
		} else {
			attach_info = attach_info->next;
			continue;
		}

		fd = open(attach_info->path_of_here, O_RDWR);
		if (fstat(fd, &st) < 0) {
			LOG_WARN("webmail:write_old_sohu_vip(): %s fstat error\n", attach_info->path_of_here);
			return -1;
		}

		mapped = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (mapped == NULL) {
			close(fd);
			return -1;
		}
		p1 = mapped;
		while (1) {
			p1 = strstr(p1, "filename=\"");
			if (p1 == NULL)
				break;
			p1 += 10;
			if (*p1 == '\"')
				continue;
			p2 = strstr(p1, "\"\r\nContent-Type: ");
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL)
				break;
			if (!flag) {
				mail_info->attach = attachment;
				attachment->next = NULL;
				flag = 1;
			} else {
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			strncpy(attachment->path_of_sender, p1, p2 - p1);
			attachment->path_of_sender[p2 - p1] = 0;
			tmp_str = sohu_old_conv_to_utf8(attachment->path_of_sender);
			if (tmp_str == NULL)
				break;
			get_file_name(tmp_str, filename);
			free(tmp_str);
			tmp_str = NULL;
			i++;
			//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			p1 = strstr(p2, "\r\n\r\n");
			p1 += 4;
			len = st.st_size - (p1 - mapped);
			p2 = memfind(p1, "Content-Disposition: form-data; name", len);
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			atta_fd = open(writepath, O_RDWR | O_CREAT, file_mode);
			if (atta_fd == -1)
				break;
			write(atta_fd, p1, p2 - p1);
			close(atta_fd);
			trim_attach(writepath, 45);
			p1 = p2;
		}
		munmap(mapped, st.st_size);
		close(fd);
		unlink(attach_info->path_of_here);
		attach_tmp = attach_info->next;
		delete_attach(attach_info);
		attach_info = attach_tmp;
	}

	mail_info->num_of_attach = i;

	result = sohu_old_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = sohu_old_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = sohu_old_conv_to_utf8(mail_info->content);
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
}

int analyse_sogou_mail(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;
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
	else if(!strncmp(data,http_ok_head,15)) 
	{
		char *host_p = NULL;
		char *res;

		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;

		host_p = strstr(mail_info->mail_data, "\r\nHost: ");
		if (host_p == NULL) 
		{
			return -1;
		}

		if (memfind(host_p, "sogou", 50) != NULL)
		{
			writefile_sogou(mail_info);
		}
		else 
		if (memfind(host_p, "vip", 50) == NULL)
			writefile_old_sohu(mail_info);
		else
			writefile_old_vip_sohu(mail_info);

		del_mail_node(mail_info);
		
		return 0;
	}
	
	return -1;
}

int analyse_sogou_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	//printf("analyse_sogou_attach_head \n");
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	char *p = NULL;
	char *p1 = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;
	size_t len;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data, "filename=\"");
	if (p == NULL)
		return 0;
	p1 = strstr(p, "\r\n\r\n");
	if (p1 == NULL) 
	{
		return 0;
	}
	p1 += 4;
	regcompile_2(attach_info->ok_data,file_name_pattern, &attach_info->path_of_sender);
	//printf("attach_info->path_of_sender : %s\n",attach_info->path_of_sender);
	
	attach_info->start_seq = p1 - attach_info->ok_data + attach_info->start_seq;//1
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd,p1,off_seq + datalen - (p1 - attach_info->ok_data));
	close(fd);

	/*p = strstr(attach_info->ok_data, "; SOHUID=");
	if (p != NULL) 
	{
		p += 9;
		p1 = strstr(p, "; DIGITALID=");
		if (p1 == NULL)
			return -1;
		len = p1 - p;
		if (len > MAX_ID_LEN)
			len = MAX_ID_LEN;
	} 
	else 
	{
		p = strstr(attach_info->ok_data, "; VIPID=");
		if (p == NULL)
			return -1;
		p += 8;
		p = strstr(attach_info->ok_data, "JSESSIONID=");
		if (p == NULL)
			return -1;
		p += 11;
		p1 = strstr(p, ";");
		if(p1 == NULL)
			return -1;
		len = p1 - p;
		if (len > MAX_ID_LEN)
			len = MAX_ID_LEN;
	//}
	memcpy(attach_info->ID_str, p, len);
	attach_info->ID_str[len] = 0;
	
	printf("attach_info->ID_str = %s\n", attach_info->ID_str);*/

	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4

	return 0;
}

int analyse_sogou_attach(Attach_info *attach_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq =ntohl(tcp->seq);
	int result;
	
	//printf("%s\n",data);

	if (is_b_s) 
	{ //attach_body
		if (attach_info->is_writing) 
		{
			//printf("111\n");
			//printf("%s\n",data);
			if(!memcmp(data+datalen-2,"--",2) || strstr(data,"\r\n----"))
				datalen -= 153;
			result = write_to_attach(attach_info, data, datalen, seq);
		} 
		else 
		{
			//printf("222\n");
			//printf("%s\n",data);
			result = analyse_sogou_attach_head(attach_info,data,datalen,seq);
		}
		
		return result;
	} 
	else 
	{    //attach_end and get id start 
		if(!attach_info ->is_get_ok)
		{
			if(!strncmp(data , "HTTP/1.1 200 OK\r\n", 17))
		   	{
				attach_info ->is_writing = 0;
				attach_info->is_get_ok = 1;
// 				trim_attach(attach_info->path_of_here, 151);//
				
				attach_info->recive_length = 5000;
				attach_info->recive_data = (char *)malloc(5001);
				if (attach_info->recive_data == NULL) 
				{
					LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
					return -1;
				}
				memset(attach_info->recive_data, 0, 5001);
				char* p1 = strstr(data,"\r\n\r\n");
				if(p1 == NULL)
					return -1;
				p1 += 4;
				memcpy(attach_info->recive_data, p1, data+datalen-p1);
				if(strstr(data, "Content-Encoding: gzip"))
				{
					attach_info->recive_length = get_http_length(data);
					char* dest = NULL;
					result = decomp_gzip_3(attach_info->recive_data, attach_info->recive_length, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(attach_info->recive_data, attach_info->recive_length, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(attach_info->recive_data, attach_info->recive_length, &dest);
							if(result == -1) 
                                result = decomp_gzip(attach_info->recive_data, attach_info->recive_length, &dest);
						}
					}
                    
					if (result == -1)
					{
						LOG_WARN("webmail:analyse_sogou_rcvmail1: decomp_zip return error!\n");
						return -1;
					}
                    
					free(attach_info->recive_data);
					attach_info->recive_data = dest;
					dest = NULL;
				}
				//printf("\nattach_info->recive_data = %s\n",attach_info->recive_data);
				p1 = strstr(attach_info->recive_data,", \"id\": ");
				if(p1 == NULL)
					return -1;
				p1 += 8;
				char* p2 = strstr(p1,", \"");
				if(p2 == NULL)
					return -1;
				memcpy(attach_info->ID_str,p1,p2-p1);
				attach_info->ID_str[p2-p1] = 0;
				
				attach_info->is_complished = 1;
				//printf("sogou attach upload end..\n");
				return 0;
		   	}
		}
   	}
   
   	return -1;
}

int analyse_old_sohu_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	char *p = NULL;
	char *p1 = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	int result;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	size_t len1, len2;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data,"filename=\"");
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
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd,p,off_seq + datalen - (p - attach_info->ok_data));
	close(fd);

	p = strstr(attach_info->ok_data, "SOHUID=");
	if (p == NULL)
		return -1;
	p += 7;
	p1 = memfind(p, "; ", 100);
	if (p1 == NULL)
		p1 = memfind(p, "\r\n\r\n", 100);
	if (p1 == NULL)
		return -1;
	len1 = p1 - p;
	if (len1 > MAX_ID_LEN)
		return -1;
	memcpy(attach_info->ID_str, p, len1);
	attach_info->ID_str[len1] = 0;

	p = strstr(attach_info->ok_data, "Servlet?li_id=");
	if (p == NULL)
		return -1;
	p += 14;
	p1 = strstr(p, " HTTP/1.1\r\n");
	if (p1 == NULL)
		return -1;
	len2 = p1 - p;
	if (len1 + len2 > MAX_ID_LEN)
		return -1;
	memcpy(attach_info->ID_str + len1, p, len2);
	attach_info->ID_str[len1 + len2] = 0;

	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4

	return 0;
}

int analyse_old_sohu_attach(Attach_info *attach_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
   unsigned int seq =ntohl(tcp->seq);
   int result;

   if (is_b_s) { //attach_body
		if (attach_info->is_writing) {
			result = write_to_attach(attach_info, data, datalen, seq);
		} else {
			result = analyse_old_sohu_attach_head(attach_info,data,datalen,seq);
		}
		return result;
   } else if(!attach_info ->is_get_ok){
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";
		if(!strncmp(data , http_ok_head ,17)){
			attach_info ->is_writing = 0;
			attach_info->is_get_ok = 1;
			if (!strlen(attach_info->path_of_here))
				return -1;
			trim_attach(attach_info->path_of_here, 47);
			attach_info->is_complished = 1;
			return 0;
		}
	}
	return -1;
}

int analyse_sogou_down_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_b_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	static int getted_size, attach_size;
	int result;
	if (attach_info->is_writing == 1)
	{
	
		
		if(attach_info->ok_length < attach_info->recive_length)
		{
		
			result = write_to_attach(attach_info, data, data_len, seq);
			attach_info->ok_length += data_len;
		}

		if(attach_info->ok_length >= attach_info->recive_length /*|| ptcp->fin == 1*/)
		{
			
			//printf("getted_size  : %d  attach_size :%d\n",attach_info->ok_length ,attach_info->recive_length);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			//getted_size = 0;
			//attach_size = 0;
			return -1;
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

			front = strstr(data, "filename=\"");
			if(front == NULL)
				return -1;
			front += 10;
			back = strstr(front, "\"\r\nCache-Control:");
			if(back == NULL)
			{
				back = strstr(front, "\r\nCache-Control:");
				if(back == NULL)
					return -1;
			}
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			memcpy(attach_info->attname, front, len);
			attach_info->attname[len] = 0;
			
			char temp_name[MAX_PATH_LEN];
// 			htmldecode_full(attach_info->attach_name, attach_info->attach_name);
// 			printf("attach_info->attname1 : %s \n",attach_info->attach_name);
			
			if(strstr(attach_info->attname , "?="))
			{
				front = strstr(attach_info->attname  ,"?=");
				if(front != NULL)
				{
					int i = 0;
					back = front -1;
					while(*back != '?')
					{
						back--;
					}
					i = front - back -1;
					memcpy(temp_name , back+1,len);
					temp_name[i] = 0;
// 					printf("attach_info->attname2 : %s len = %d\n",temp_name,i);
					char *attachname = Base2UTF8_mail(temp_name,i);
// 					printf("attach_info->attname3 : %s \n",attachname);
					if(attachname != NULL)
// 						htmldecode_full(attachname, attach_info->attname);
						memcpy(attach_info->attname , attachname , strlen(attachname));
					else 
					{
						front = strstr(temp_name ,"=2E");
                        if (front != NULL)
                        {
    						len = front - temp_name;
    						memcpy(attach_info->attname , temp_name , len );
    						attach_info->attname[len] = '.';
    						memcpy(attach_info->attname + len +1, front+3 , i - len -2 );
    						attach_info->attname[i-2] = 0;
    // 						printf("attach_info->attname4: %s \n",attachname);
                        }
					}
				}
					
			}
			
			//printf("attach_info->attname : %s \n",attach_info->attname);
			
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",
					 attach_down_path, tv.tv_sec, tv.tv_usec);
			
			/*memset(temp_name, MAX_PATH_LEN, 0);
			strcpy(temp_name, attach_info->attach_name);
			temp_name[len] = '\0';*/
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);
    		
			front = strstr(data, "Content-Length: ");
			if(front == NULL)
			{
				return -1;
			}
			front += 16;
			back = strstr(front, "\r\n");
			if(back == NULL)
			{
				return -1;
			}
			char size_str[16];
			memset(size_str, 0, 16);
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			memcpy(size_str, front, len);
			size_str[len] = '\0';
			attach_info->recive_length = strtonum(size_str);
			
			//printf("attach_info->recive_length : %d\n", attach_info->recive_length);
// 			printf("attach_size : %d\n",attach_size);
			front = strstr(data, "Accept-Ranges:");
			if(front == NULL)
			{
				return -1;
			}
			front += 14;
			front = strstr(front, "\r\n\r\n");
			if(front == NULL)
			{
				return -1;
			}
			front += 4;
			attach_info->start_seq = seq + (front - data);
			fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
			{
				return -1;
			}
			attach_info->ok_length = data_len - (front - data);
			write(fd, front, attach_info->ok_length);
			close(fd);
			
			//printf("attach_info->ok_length first : %d\n", attach_info->ok_length);
			

			attach_info->is_writing = 1;
		}
		else
		{
			int len;
			char *front, *back;
			front = strstr(data, "/download/");
			if(front == NULL)
				return 0;
			front += 10;
			memcpy(attach_info->ID_str, front, 64);
			attach_info->ID_str[64] = '\0';
			//printf("attach_info->ID_str: %s\n", attach_info->ID_str);
		}
	}
	
	return 0;
}

int analyse_old_sohu_delete(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq;
	char *p1 = NULL, *p2 = NULL;
	char ID[MAX_ID_LEN];
	Attach_info *attach_info;
	int len1, len2;

	if (is_b_s) {
		if (!mail_info->is_complished) {
			p1 = strstr(data, "&id=");
			if (p1 == NULL) {
				return -1;
			}
			p1 += 4;
			p2 = strstr(p1, " HTTP/1.1\r\n");
			if (p2 == NULL) {
				return -1;
			}
			len1 = p2 - p1;
			memcpy(ID, p1, len1);
			ID[len1] = 0;

			attach_info = attach_tab.head->next;
			while (attach_info != NULL) {
				len2 = strlen(attach_info->ID_str);
				if (!strncmp(attach_info->ID_str + (len2 - len1), ID, len1)) {
					del_attach_node(attach_info);
					delete_attach(attach_info);
					break;
				} else {
					attach_info = attach_info->next;
					continue;
				}
			}
			del_mail_node(mail_info);
			return 0;
		}
	}
	return -1;
}

int writefile_sogou_rcvmail(Mail_info *mail_info)
{
    if (NULL==mail_info->recive_data && NULL!=mail_info->body)
    {
        mail_info->recive_data = mail_info->body;
        mail_info->body = NULL;
        mail_info->recive_length = mail_info->bodyLen;
    }
// 	printf("writefile_sogou_rcvmail...\n");
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp_str = NULL;
	size_t len;
	int result;
	char tmp[50] = {0};
	time_t timeint;
	
	pstart = strstr(mail_info->recive_data, "\"mid\": \""); //mid
	if (pstart == NULL)
		return -1;
	pstart += 8;
	memcpy(mail_info->mail_id, pstart, 64);
	mail_info->mail_id[64] = 0;
	//printf("mail_info->mail_id : %s\n", mail_info->mail_id);

	pstart = strstr(mail_info->recive_data, "\"from\": ["); //search 发件人
	if (pstart == NULL)
		return -1;

	pstart += 9;
	pstart = strstr(pstart, ", \"");
	if (pstart == NULL)
		return -1;
	pstart += 3;
	pend = strstr(pstart, "\"]");
	if (pend == NULL)
		return -1;
// 	pend -= 2;
	
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;
	//printf("mail_info->from : %s \n",mail_info->from);

	pstart = strstr(mail_info->recive_data, "\"to\": [");//search 收件人 
	if (pstart == NULL)
		return -1;
	pstart += 7;
    char *pendflag = strstr(pstart, "\"]]");
    int off_len = 0;
    do
    {
    	pstart = strstr(pstart, ", \"");
    	if (pstart == NULL)
    		return -1;
    	pstart += 3;
    	pend = strstr(pstart, "\"]");
    	if (pend == NULL)
    		return -1;
    	
    	len = pend - pstart;
    	len = (len+off_len> MAX_TO_LEN ? MAX_TO_LEN-off_len: len);
    	memcpy(mail_info->to+off_len, pstart, len);
        off_len += len;
    	mail_info->to[off_len] = ',';
        off_len++;
        pstart = pend;
    }while (pendflag-pend>0);
    mail_info->to[off_len-1] = 0;
    off_len = 0;
	//printf("mail_info->to : %s \n",mail_info->to);	
	pstart = strstr(mail_info->recive_data, "\"cc\": [");//search 抄送人 
	if (pstart == NULL)
		return -1;
	if(strstr(mail_info->recive_data, "\"cc\": []"))
		mail_info->cc[0] = 0;
	else
	{
    	pstart += 7;
        pendflag = strstr(pstart, "\"]]");
        off_len = 0;
        do
        {
        	pstart = strstr(pstart, ", \"");
        	if (pstart == NULL)
                return -1;
        	pstart += 3;
        	pend = strstr(pstart, "\"]");
        	if (pend == NULL)
        		return -1;
        	len = pend - pstart;
        	len = (len+off_len> MAX_CC_LEN ? MAX_CC_LEN-off_len:len);
        	memcpy(mail_info->cc+off_len, pstart, len);
            off_len += len;
        	mail_info->cc[off_len] = ',';
            off_len++;
            pstart = pend;
        }while(pendflag-pend > 0);
        mail_info->cc[off_len-1] = 0;
        off_len = 0;
	}
	//printf("mail_info->cc : %s \n",mail_info->cc);
	
	pstart = strstr(mail_info->recive_data, "\"date\": \"");//search 发送时间 
	if (pstart == NULL)
		return -1;
	
	pstart += 9;
	pend = strstr(pstart, "\",");
	if (pend == NULL)
		return -1;
	
	len = pend - pstart;
	len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(tmp, pstart, len);
	tmp[len] = 0;
	
	int flag_time=0;
	if(strstr(tmp, "GMT"))
	{
		tmp[strlen(tmp) - 4] = '\0';
		flag_time = 8;
	}
	else
	if(strstr(tmp, "+0800"))
	{
		tmp[strlen(tmp) - 12] = '\0';
		flag_time = 8;
	}
	else
	if(strstr(tmp, "-0700"))
	{
		tmp[strlen(tmp) - 12] = '\0';
		flag_time = 7;
	}
	
	struct tm time_struct, *tm_ptr;
    	time_t timeval;
    	strptime(tmp, "%a, %d %b %Y %H:%M:%S %Z", &time_struct);
    	if (flag_time==7)
     	{
      		timeval=mktime(&time_struct) + 15*3600;
      	}
    	else 
    	if(flag_time==8)
     	{
      		timeval=mktime(&time_struct);
     	}
    	tm_ptr=localtime(&timeval);
    	sprintf(mail_info->sent_time, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year+1900,
					tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
	
	pstart = strstr(mail_info->recive_data, "\"subject\": \"");//search 主题
	if (pstart == NULL)
		return -1;
	
	pstart += 12;
	pend = strstr(pstart, "\", ");
	if (pend == NULL)
		return -1;
	
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	pstart = strstr(mail_info->recive_data, "\"content\": \"");
	if (pstart == NULL)
		return -1;
	
	pstart += 12;
	pend = strstr(pstart, "\", \"attach\"");
	if (pend == NULL)
		return -1;
	
	//*pend = 0;
	pstart = strstr(pend, "\"display\": \"");
	if (NULL == pstart)
        return -1;
    pstart += 12;
    pend = strstr(pstart, "\"}");
    len = pend-pstart;
    mail_info->content = (char *)malloc(len+1);
    memcpy(mail_info->content, pstart, len);
    mail_info->content[len] = 0;
	//mail_info->content = strdup(pstart);

	result = sogou_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = sogou_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = sogou_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		return -1;
	result = sogou_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;

	//printf("mail_info->subject : %s\n", mail_info->subject);
	
	result = clear_tag(mail_info->subject);
	if (result == -1)
		return -1;
	
	//printf("mail_info->subject : %s\n", mail_info->subject);
	
	result = clear_tag(mail_info->content);
	if (result == -1)
		return -1;

	down_content(mail_info->subject);
	down_content(mail_info->content);
    tmp_str = clear_html_tag(mail_info->content);
    free(mail_info->content);
    mail_info->content = tmp_str;
	clear_from(mail_info->from);
	
	//printf("mail_info->subject : %s\n", mail_info->subject);

	create_dir(mail_info->save_path, "sogou", mail_info->from);
	write_to_file(mail_info);
    return -1;
}

int analyse_sogou_rcvmail(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_recv((Mail_info *)node, packetInfo, is_to_s, writefile_sogou_rcvmail);
}



int analyse_sogou_rcvmail_attach(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
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
			front = strstr(data, "/download/");
			if(front == NULL)
				return 0;
			front += 10;
			memcpy(mail_info->mail_id, front, 64);
			mail_info->mail_id[64] = '\0';
			//printf("mail_info->mail_id: %s\n", mail_info->mail_id);
		}
	}
	else
	{
		if(!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			if(!strstr(data,"attachment;filename=\"")) return -1;
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
					return 0;
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
}

void analyse_sogou(PacketInfo *packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
{
    if (0 == datalen || NULL == tmp)
        return;

	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned short int lowtype;
	int result = 0;

	if(!mora) 
	{
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype & 0X00FF;
		switch(lowtype)
		{
		case 0x11:
			//printf("analyse_sogou_mail\n");
			result = analyse_sogou_mail(mail_info, data, datalen, tcp, is_b_s);
			//printf("attach_num : %d\n", Get_Attach_Num_sogou());
			break;
		case 0x41:
			//printf("analyse_old_sohu_delete\n");
			result = analyse_old_sohu_delete(mail_info, data, datalen, tcp, is_b_s);
			break;
		case 0x21:
			//printf("analyse_sogou_rcvmail\n");
            result = analyse_sogou_rcvmail((void *)mail_info, packetInfo, is_b_s);
			break;
		case 0x22:
			//printf("analyse_sogou_rcvmail_attach ...\n");
			result = analyse_sogou_rcvmail_attach(mail_info, data, datalen, tcp, is_b_s);
			break;
		default:
			break;
		}
		
		if (result == -1)
			delete_mail_info(mail_info);
	} 
	else 
	{
		attach_info=(Attach_info *)tmp;
		lowtype = attach_info->attach_type;
		lowtype = lowtype & 0X00FF;
		switch(lowtype) 
		{
    		case 0x61:
    			//printf("analyse_sogou_attach\n");
    			result = analyse_sogou_attach(attach_info, data, datalen, tcp, is_b_s); //old vip attach
    			//printf("attach_num : %d\n", Get_Attach_Num_sogou());
    			break;
    		case 0x62:
    			//printf("analyse_old_sohu_attach\n");
    			result = analyse_old_sohu_attach(attach_info, data, datalen, tcp, is_b_s); //new vip version
    			break;
    		case 0x63:
     			//printf("analyse_sogou_down_attach\n");
    			result = analyse_sogou_down_attach(attach_info, data, datalen, tcp, is_b_s); //down attach
    			break;
    		default:
    			break;
		}
        
		if (result == -1) 
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}

