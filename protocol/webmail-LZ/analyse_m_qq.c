#include "common.h"
unsigned int recive_data_length_m=0;
#if 0
void DbgShow(char buf[],char file[])
{
	char path[]="//workflord//yubo//webmail//test_print//";
	strcat(path,file);
	FILE * fp;
	fp=fopen(path,"wt");
	if(fp==NULL)
	{
		printf("Cann't Open the file:%s",file);
		return;
	}
	fputs(buf,fp);
	fclose(fp);
}
#endif
/*
char *qq_conv_to_utf8(char *src)
{
	char *tmp_str = NULL;
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

int qq_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = qq_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);

	return 0;
}

int qq_str_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	char *tmp2 = NULL;
	size_t len;

	tmp1 = qq_conv_to_utf8(str);
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

	return 0;
}
*/
int writefile_qq_m(Mail_info *mail_info)
{
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *tmp_str = NULL;
	size_t len;
	int result, fd, n, i = 0, flag = 0;
	Attachment *attachment;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

	p1 = strstr(mail_info->mail_data, "; qqmail_alias=");
	if (p1 == NULL)
	{
		p1 = strstr(mail_info->mail_data, "; qm_username=");
		if(p1 == NULL)
			return -1;
		p1 += 14;
		p2 = strstr(p1, "\r\n");
		if (p2 == NULL)
			return -1;
		len = p2 - p1;
		if (p2 == NULL || len > MAX_FROM_LEN - 8)
			return -1;
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
		strcat(mail_info->from, "@qq.com");
	}
	else
	{
		p1 += 15;
		p2 = strstr(p1, "@");
		if (p2 == NULL)
			return -1;
		len = p2 - p1;
		if (p2 == NULL || len > MAX_FROM_LEN - 8)
			return -1;
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
		strcat(mail_info->from, "@qq.com");
	}
	//printf("mail_info->from = %s\n",mail_info->from);
	p2++;

	p1 = strstr(p2, "&to=");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "%3B%3B&showcc=");
	if (p2 == NULL)
	{
		p2 = strstr(p1, "&cc=");
		if(p2 == NULL)
			return -1;
	}
	len = p2 - p1;
	if(len == 0) return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	htmldecode_full(mail_info->to, mail_info->to);
	//printf("mail_info->to = %s\n",mail_info->to);

	p1 = strstr(p2, "&cc=");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "&cc=");
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "%3B%3B&showbcc=");
		if(p2 == NULL)
		{
			p2 = strstr(p1, "&bcc=");
		}
		if (p2 != NULL) 
		{
			len = p2 - p1;
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
			htmldecode_full(mail_info->cc, mail_info->cc);
			//printf("mail_info->cc = %s\n",mail_info->cc);
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

	p1 = strstr(p1, "&bcc=");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "&bcc=");
	if (p1 != NULL)
	{
		p1 += 5;
		p2 = strstr(p1, "%3B%3B&subject=");
		if(p2 == NULL)
		{
			p2 = strstr(p1, "&subject=");
		}
		if (p2 != NULL) 
		{
			len = p2 - p1;
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
			htmldecode_full(mail_info->bcc, mail_info->bcc);
			//printf("mail_info->bcc = %s\n",mail_info->bcc);
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

	p1 = strstr(p1, "&subject=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&content=");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject = %s\n",mail_info->subject);

	create_dir(mail_info->save_path, "qq" ,mail_info->from);

	p2 += 9;
	p1 = strstr(p2, "&Redirect");
	if (p1 == NULL)
	{
		p1 = strstr(p2, "&savesendbox=");
		if(p1 == NULL)
			return -1;
	}
	len = p1 - p2;
	mail_info->content = (char *)malloc(len + 1);
        memset(mail_info->content,0,len+1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p2, len);
	mail_info->content[len] = 0;
	//htmldecode_full(mail_info->content, mail_info->content);
	//printf("mail_info->content = %s\n",mail_info->content);

	/////////////
	char *p3=NULL;
	p1 =strstr(p2, "&fmailid=");
	if(p1 == NULL)
	{
		p1 =strstr(p2, "&cattachelist=");
		p1+=14;
	}
	else
		p1+=9;
	if(p1)
	{
		p2=strstr(p1,"&editorigin=");
		if(p2 == NULL)
			p2=strstr(p1,"&device=");
		if(p2)
		{
			*p2='|';
			p2[4]='\0';
			while(1)
			{
				p3=strstr(p1,"|");
				if(p3==NULL) 
					break;
				len=p3-p1;
				if(len<40 || len>55) break; 
				strncpy(ID,p1,len);
				ID[len]=0;
				attach_info=find_attach(ID);
				if(attach_info ==NULL)
				{
					p1=p3+1;
					continue;
				}
				Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
				if(attachment==NULL) break;
				attachment->next = NULL;

				if(attach_info->path_of_sender!=NULL)
				{
					//snprintf(attachment->loc_filename,MAX_FN_LEN,"attach%d_%s",i,attach_info->path_of_sender);
					snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->path_of_sender);
					snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				}
				else
				{
					//snprintf(attachment->loc_filename,MAX_FN_LEN,"attach%d_%s",i,"unknow");
					snprintf(attachment->loc_name, MAX_FN_LEN, "%s", "unknow");
					snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				}

				snprintf(writepath,MAX_PATH_LEN,"%s/%s",mail_info->save_path,attachment->loc_filename);
				link(attach_info->path_of_here,writepath);
				unlink(attach_info->path_of_here);
				delete_attach(attach_info);
				if(!flag)
				{
					mail_info->attach = attachment;
					flag = 1;
				}
				else
				{
					attachment->next = mail_info->attach->next;
					mail_info->attach->next = attachment;
				}
				i++;
				p1=p3+1;
			}
		}
	}

	mail_info->num_of_attach = i;

	result = qq_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = qq_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;

	write_to_file_m(mail_info);
}

int writefile_qq_group_m(Mail_info *mail_info)
{//printf("\nwritefile_qq_group\n");
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL;
	char *tmp_str;
	int len, qq_num_len = -1;
	int result;
	char filepath[MAX_PATH_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char ID[MAX_ID_LEN + 1];
	Attachment *attachment;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd;
	int n, i = 0;
	int flag = 0;

	//printf("%s\n", mail_info->mail_data);

	p1 = strstr(mail_info->mail_data, "; qqmail_alias=");
	if (p1 == NULL)
	{
		p1 = strstr(mail_info->mail_data, "; qm_username=");
		if(p1 == NULL)
			return -1;
		p1 += 14;
		p2 = strstr(p1, "\r\n");
		if (p2 == NULL)
			return -1;
		len = p2 - p1;
		if (p2 == NULL || len > MAX_FROM_LEN - 8)
			return -1;
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
		strcat(mail_info->from, "@qq.com");
	}
	else
	{
		p1 += 15;
		p2 = strstr(p1, "@");
		if (p2 == NULL)
			return -1;
		len = p2 - p1;
		if (p2 == NULL || len > MAX_FROM_LEN - 8)
			return -1;
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
		strcat(mail_info->from, "@qq.com");
	}
	p2++;
	//printf("mail_info->from : %s\n", mail_info->from);

	p1 = strstr(p2, "qqgroupid=");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "qqgroupid=");
	if (p1 == NULL)
		return -1;
	p1 += 10;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	htmldecode_full(mail_info->to,mail_info->to);

	mail_info->bcc[0] = 0;
	mail_info->cc[0] = 0;

	p1 = strstr(p2, "&subject=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
//	p2 += boun_len;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	create_dir(mail_info->save_path, "qq", mail_info->from);

	p1 = strstr(p2, "&content=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;

	char *p3=NULL;
	p1 =strstr(mail_info->mail_data, "&fmailid=");
	if(p1)
	{
		p1+=9;
		p2=strstr(p1,"&");
		if(p2)
		{
			*p2='|';
			p2[4]='\0';
			while(1)
			{
				p3=strstr(p1,"|");
				if(p3==NULL) 
					break;
				len=p3-p1;
				if(len<40 || len>55) break; 
				strncpy(ID,p1,len);
				ID[len]=0;
				attach_info=find_attach(ID);
				if(attach_info ==NULL)
				{
					p1=p3+1;
					continue;
				}
				Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
				if(attachment==NULL) break;
				attachment->next = NULL;

				if(attach_info->path_of_sender!=NULL)
				{
					//snprintf(attachment->loc_filename,MAX_FN_LEN,"attach%d_%s",i,attach_info->path_of_sender);
					snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->path_of_sender);
					snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				}
				else
				{
					//snprintf(attachment->loc_filename,MAX_FN_LEN,"attach%d_%s",i,"unknow");
					snprintf(attachment->loc_name, MAX_FN_LEN, "%s", "unknow");
					snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
				}

				snprintf(writepath,MAX_PATH_LEN,"%s/%s",mail_info->save_path,attachment->loc_filename);
				link(attach_info->path_of_here,writepath);
				unlink(attach_info->path_of_here);
				delete_attach(attach_info);
				if(!flag)
				{
					mail_info->attach = attachment;
					flag = 1;
				}
				else
				{
					attachment->next = mail_info->attach->next;
					mail_info->attach->next = attachment;
				}
				i++;
				p1=p3+1;
			}
		}
	}
	mail_info->num_of_attach = i;

	result = qq_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = qq_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;

	write_to_file_m(mail_info);
	return 0;
}

int analyse_m_qq_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;
	static int flag = -1;
	static int flagg = -1;
	char *dest = NULL;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15) && !mail_info->is_complished)
	{
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		if (strstr(mail_info->mail_data, "qqgroupid="))
		{
			writefile_qq_group_m(mail_info);
		}
		else
		{
			writefile_qq_m(mail_info);
		}
		
		//del_mail_node(mail_info);
		return 0;
	} 
	else 
	{
		return -1;
	}
}
int analyse_m_qq_attach_head(Attach_info *attach_info,char *data,unsigned int data_len,unsigned int seq)
{
	int fd;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	char  *p1=NULL ,*p2=NULL;
	char file_name_pattern[]="; filename=\"(.*)\"\r\nContent-Type: ";
	char attID_pattern[]="; name=\"fmailid\"\r\n\r\n(.*)\r\n----";
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ;
	int range = 0;

	off_seq = seq-attach_info->start_seq;
	range = off_seq + data_len;
	if(range > attach_info->ok_len)  
        return -1;
	memcpy(attach_info->ok_data + off_seq, data, data_len);
	
	p1 = strstr(attach_info->ok_data,"; filename=\"");
	if(p1 == NULL) 
		return 0;
	p2 = strstr(p1,"\r\n\r\n");
	if(p2 == NULL) 
		return 0;

	p2 += 4;
	attach_info->start_seq = p2-attach_info->ok_data+attach_info->start_seq;
	regcompile_2(attach_info->ok_data,file_name_pattern, &attach_info->path_of_sender); //2
	int result = regcompile_1(attach_info->ok_data, "; name=\"fmailid\"\r\n\r\n(.*)\r\n----", attach_info->ID_str, MAX_ID_LEN);
	if (result == -1) {
		attach_info->ID_str[0] = 0;
	}
	gettimeofday(&tv,&tz);
	snprintf(attach_info->path_of_here,MAX_PATH_LEN,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);//3
	fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
	if(fd == -1)  
		return  -1;
	write(fd,p2,off_seq + data_len - (p2-attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1;  //4
	
	return 0;

}

int analyse_m_qq_attach(Attach_info * attach_info,char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;
	char *p1=NULL ,*p2=NULL;
	int len;
	char *dest = NULL;

	if (is_to_s) 
	{
		if(attach_info->is_writing)
		{
			if(!memcmp(data+data_len-4,"--\r\n",4) && data_len>250)
				data_len -= 250;
			result = write_to_attach(attach_info,data,data_len,seq);
		} 
		else 
		{
			result = analyse_m_qq_attach_head(attach_info,data,data_len,seq); 
		}
		return result;
	}
	else 
	if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15))
	{
		if(strlen(attach_info->ID_str) == 0)
		{
			attach_info->recive_length = 5000;
			attach_info->recive_data = (char *)malloc(5001);
			if (attach_info->recive_data == NULL) 
			{
				LOG_WARN("webmail:write_to_okdata: malloc()1 failed!\n");
				return -1;
			}
			memset(attach_info->recive_data, 0, 5001);
			p1 = strstr(data,"\r\n\r\n");
			if(p1 == NULL)
				return -1;
			p1 += 4;
			memcpy(attach_info->recive_data, p1, data+data_len-p1);
			if(strstr(data, "Content-Encoding: gzip"))
			{
				attach_info->recive_length = get_http_length_1(data);
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
					LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
                
				free(attach_info->recive_data);
				attach_info->recive_data = dest;
				dest = NULL;
			}
			//printf("\nattach_info->recive_data = %s\n",attach_info->recive_data);
			p1 = strstr(attach_info->recive_data,"/groupattach\\/");
			if(p1 == NULL)
				return -1;
			p1 += 14;
			p2 = strstr(p1,"\"");
			if(p2 == NULL)
				return -1;
			memcpy(attach_info->ID_str,p1,p2-p1);
			attach_info->ID_str[p2-p1] = 0;
		}
		attach_info->is_complished = 1;
		trim_attach(attach_info->path_of_here,151);
		return 0;
	}
}

int writefile_qq_group_rcvmail_m(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp_str = NULL;
	size_t len;
	int result;

	//printf("%s\n", mail_info->recive_data);
	pstart = strstr(mail_info->mail_data, "; qqmail_alias=");
	if (pstart == NULL)
		return -1;
	pstart += 15;
	pend = strstr(pstart, ";");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (pend == NULL || len + 8 > MAX_UN_LEN)
		return -1;
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;

	pstart=strstr(mail_info->recive_data,"<span class=\"mh_info_time\">");
	if (pstart==NULL) 
		return -1;
	pstart += 27;
	pend = strstr(pstart,"</span>");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
	//printf("mail_info->sent_time : %s\n", mail_info->sent_time);

	pstart = strstr(mail_info->recive_data, "name=\"qqgroupid\"");
	if (pstart == NULL)
		return -1;
	pstart = strstr(pstart, "value=\"");
	if (pend == NULL)
		return -1;
	pstart += 7;
	pend = strstr(pstart, "\"");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;
	//printf("mail_info->from : %s\n", mail_info->from);

	pstart = strstr(pend, "name=\"subject\"");
	if (pstart == NULL)
		return -1;
	pstart = strstr(pstart, "value=\"");
	if (pend == NULL)
		return -1;
	pstart += 7;
	pend = strstr(pstart, "\"/>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	pstart = strstr(mail_info->recive_data, "<div class=\"floor_content\">");
	if (pstart == NULL)
		return -1;
	pstart += 27;
	pend = strstr(pstart, "<div class=\"navbar_bot\">");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	*pend = 0;
	tmp_str = strdup(pstart);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	
	if (mail_info->content == NULL)
		return -1;
	//printf("mail_info->content : %s\n", mail_info->content);
		
	/*result = qq_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = qq_conv_to_utf8(tmp_str);
	free(tmp_str);
	if (mail_info->content == NULL)
		return -1;*/
	

	create_dir(mail_info->save_path, "qq", mail_info->from);
	write_to_file_m(mail_info);
	//write_oracle_db_cookieinfo(mail_info);
}

 #if 0  

int writefile_qq_rcvmail(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = NULL;
	int is_english = 0;
	size_t len;
	int result;

	 //----------
        //all information code is gb2312 charset=gb2312
          pstart=strstr(mail_info->recive_data,"QMReadMail.init(");
          pstart=strstr(pstart,"fromaddr\t\t: \"");
          pstart+=13;
          pend=strstr(pstart,"\",\n");
          len=pend-pstart;
          memcpy(mail_info->from,pstart,len);
          mail_info->from[len]=0;
          printf("%s\n",mail_info->from);
          
       //------------
	pstart = strstr(mail_info->recive_data, "<div><b>\xb7\xa2\xbc\xfe\xc8\xcb:</b> ");
	if (pstart == NULL) {
		pstart = strstr(mail_info->recive_data, "<div><b>From: </b> ");
		if (pstart == NULL)
			return -1;
		else {
			is_english = 1;
			pstart += 19;
		}
	} else {
		pstart += 20;
	}
	pend = strstr(pstart, ";</div>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	if (!is_english) {
		pstart = strstr(pend, "<div><b>\xb7\xa2\xcb\xcd\xca\xb1\xbc\xe4:</b> ");
		if (pstart == NULL)
			return -1;
		pstart += 22;
	} else {
		pstart = strstr(pend, "<div><b>Date: </b> ");
		if (pstart == NULL)
			return -1;
		pstart += 19;
	}
	pend = strstr(pstart, "</div>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;

	if (!is_english) {
		pstart = strstr(pend, "<div><b>\xca\xd5\xbc\xfe\xc8\xcb:</b> ");
		if (pstart == NULL)
			return -1;
		pstart += 20;
	} else {
		pstart = strstr(pend, "<div><b>To: </b> ");
		if (pstart == NULL)
			return -1;
		pstart += 17;
	}
	pend = strstr(pstart, "; </div>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;

	if (!is_english) {
		pstart = strstr(pend, "<div><b>\xb3\xad\xcb\xcd:</b> ");
		if (pstart != NULL) {
		    pstart += 18;
	        pend = strstr(pstart, "; </div>");
	        if (pend == NULL)
	        	return -1;
    	    len = pend - pstart;
    	    len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
        	memcpy(mail_info->cc, pstart, len);
        	mail_info->cc[len] = 0;
        }
	} else {
		pstart = strstr(pend, "<div><b>Cc: </b> ");
		if (pstart != NULL) {
		    pstart += 17;
	        if (pend == NULL)
	        	return -1;
    	    len = pend - pstart;
    	    len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
        	memcpy(mail_info->cc, pstart, len);
        	mail_info->cc[len] = 0;
        }
	}

	if (!is_english) {
		pstart = strstr(pend, "<div><b>\xd6\xf7\xcc\xe2:</b> ");
		if (pstart == NULL)
			return -1;
		pstart += 18;
	} else {
		pstart = strstr(pend, "<div><b>Subject: </b> ");
		if (pstart == NULL)
			return -1;
		pstart += 22;
	}
	pend = strstr(pstart, "</div>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;

	pstart = strstr(pend, "<div id=\"contentDiv\"");
	if (pstart == NULL)
		return -1;
	pstart += 20;
	pstart = strstr(pstart, ">\n\x09\x09\x09\x09\x09\x09");
    if (pstart == NULL)
        return -1;
	pstart += 8;
//	pend = strstr(pstart, "\n\x09\x09\x09\x09\n</div>");
	pend = strstr(pstart, "<div id=\"attachment\"");
	if (pend == NULL)
		return -1;
	*pend = 0;
	mail_info->content = strdup(pstart);
	if (mail_info->content == NULL)
		return -1;

	result = qq_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		result -1;
	result = qq_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp = qq_conv_to_utf8(mail_info->content);
	if (tmp == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp);
	free(tmp);
	tmp = NULL;

	clear_from(mail_info->from);

	create_dir(mail_info->save_path, "qq", mail_info->from);
	write_to_file_m(mail_info);
}
#endif

int writefile_qq_rcvmail_m(Mail_info *mail_info)
{//printf("\nwritefile_qq_rcvmail\n");
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = NULL;
	//int is_english = 0;
	size_t len;
	int result;
	char code_encoding[20]={"charset=gb2312"};
		
	//printf("%s\n", mail_info->recive_data);

	pstart = strstr(mail_info->recive_data, "\"from\":{");
	if (pstart==NULL)
	{
		pstart = strstr(mail_info->recive_data, "<div class=\"mailunit\">");
		if (pstart==NULL) 
			return -1;
		pend = strstr(pstart,"<div class=\"attach\">");
		if(pend == NULL)
		{
			pend = strstr(pstart,"<div class=\"quickreply\">");
			if (pend == NULL)
				return -1;
		}
		tmp = (char*)malloc(pend - pstart);
		memset(tmp, 0, pend - pstart);
		memcpy(tmp, pstart, pend - pstart);
		if (tmp == NULL)
			return -1;
		mail_info->content = clear_html_tag(tmp);
		free(tmp);
		tmp = NULL;
		//printf("mail_info->content : %s\n", mail_info->content);

		pstart = strstr(mail_info->recive_data, "<div class=\"mailhead\">");
		if (pstart==NULL) 
			return -1;
		pend = strstr(pstart,"<div class=\"mailunit\">");
		if (pend == NULL)
			return -1;
		char *str;
		str = (char*)malloc(pend - pstart + 1);
		memset(str, 0, pend - pstart);
		memcpy(str, pstart, pend - pstart);

		mail_info->recive_data == NULL;
                len = pstart - pstart;
		mail_info->recive_data=(char *)malloc(pend - pstart +1);
		memset(mail_info->recive_data, 0, pend - pstart);
		memcpy(mail_info->recive_data, pstart, pend - pstart);

		pstart = strstr(mail_info->recive_data, "<h3>");
		if (pstart==NULL) 
			return -1;
		pstart += 4;
		pend = strstr(pstart,"</h3>");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
		memcpy(mail_info->subject, pstart, len);
		mail_info->subject[len] = 0;
		//printf("mail_info->subject : %s\n", mail_info->subject);

		pstart = strstr(pend, "<span class=\"mh_info_nick\">");
		if (pstart==NULL) 
			return -1;
		pstart = strstr(pstart, "&lt;");
		if (pstart==NULL)
			return -1;
		pstart += 4;
		pend = strstr(pstart,"&gt;");
		if (pend == NULL)
			return -1;
		len=pend-pstart;
		len=(len>MAX_FROM_LEN ? MAX_FROM_LEN : len);
		memcpy(mail_info->from,pstart,len);
		mail_info->from[len]=0;
		//printf("mail_info->from : %s\n",mail_info->from);

		pstart=strstr(pend,"&lt;");
		if (pstart==NULL) 
			return -1;
		pstart+=4;
		pend = strstr(pstart,"&gt;");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
		memcpy(mail_info->to, pstart, len);
		mail_info->to[len] = 0;
		//printf("mail_info->to : %s\n", mail_info->to);

		pstart=strstr(pend,"&lt;");
		if (pstart!=NULL) 
		{
			pstart+=4;
			pend = strstr(pstart,"&gt;");
			if (pend == NULL)
				return -1;
			len = pend - pstart;
			len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
			memcpy(mail_info->cc, pstart, len);
			mail_info->cc[len] = 0;
			//printf("mail_info->cc : %s\n", mail_info->cc);
		}

		pstart=strstr(pend,"<p>");
		if (pstart==NULL) 
			return -1;
		pstart += 15;
		pend = strstr(pstart,"</p>");
		if (pend == NULL)
			return -1;
		len=pend-pstart;
		len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
		memcpy(mail_info->sent_time, pstart, len);//ch_time
		mail_info->sent_time[len] = 0;
		//printf("mail_info->sent_time : %s\n", mail_info->sent_time);
	}
	else
	{
		pstart = strstr(mail_info->recive_data, "\"subj\":\"");
		if (pstart==NULL) 
			return -1;
		pstart+=8;
		pend=strstr(pstart,"\",\"re");
		if (pend==NULL) 
			return -1;
		len = pend - pstart;
		len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
		memcpy(mail_info->subject, pstart, len);
		mail_info->subject[len] = 0;
		//printf("mail_info->subject : %s\n", mail_info->subject);

		pstart = strstr(pend, "\"abs\":\"");
		if (pstart==NULL) 
			return -1;
		pstart += 7;
		pend = strstr(pstart,"\",\"date");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		mail_info->content = (char*)malloc(len);
		memset(mail_info->content, 0, len);
		memcpy(mail_info->content, pstart, len);
		if (mail_info->content == NULL)
			return -1;
		//printf("mail_info->content : %s\n", mail_info->content);
	
		pstart=strstr(pend,"\"date\":");
		if (pstart==NULL) 
			return -1;
		pstart += 7;
		pend = strstr(pstart,",\"sz");
		if (pend == NULL)
			return -1;
		len=pend-pstart;
		len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
		char sendtime[100];
		memset(sendtime,0,100);
		strncpy(sendtime,pstart,len);
		sendtime[len]=0;
		memset(mail_info->sent_time,0,MAX_TIME_LEN + 1);
		convert_time_to_string(atoi(sendtime),mail_info->sent_time);
		//printf("mail_info->sent_time : %s\n", mail_info->sent_time);

		pstart = strstr(pstart, "\"from\":{");
		if (pstart==NULL)
			return -1;
		pstart = strstr(pstart, "\"addr\":\"");
		if (pstart==NULL)
			return -1;
		pstart += 8;
		pend = strstr(pstart,"\"},");
		if (pend == NULL)
			return -1;
		len=pend-pstart;
		len=(len>MAX_FROM_LEN ? MAX_FROM_LEN : len);
		memcpy(mail_info->from,pstart,len);
		mail_info->from[len]=0;
		//printf("mail_info->from : %s\n",mail_info->from);
	
		pstart=strstr(pend,"\"toLst\":[");
		if (pstart==NULL) 
			return -1;
		pstart=strstr(pstart,"\"addr\":\"");
		if (pstart==NULL) 
			return -1;
		pstart+=8;
		pend = strstr(pstart,"\"}");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
		memcpy(mail_info->to, pstart, len);
		mail_info->to[len] = 0;
		//printf("mail_info->to : %s\n", mail_info->to);
	
		pstart=strstr(pend, "\"ccLst\":[");
		if (pstart!=NULL) 
		{
			pstart=strstr(pstart,"\"addr\":\"");
			if (pstart==NULL) 
				return -1;
			pstart+=8;
			pend = strstr(pstart,"\"}");
			if (pend == NULL)
				return -1;
			len = pend - pstart;
			len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
			memcpy(mail_info->cc, pstart, len);
			mail_info->cc[len] = 0;
			//printf("mail_info->cc : %s\n", mail_info->cc);
		}
	
	}
	result = qq_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	/*result = qq_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		result -1;
	result = qq_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp = qq_conv_to_utf8(mail_info->content);
	if (tmp == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp);
	free(tmp);
	tmp = NULL;*/

	clear_from(mail_info->from);

	//printf("mail_info->content2 : %s\n", mail_info->content);

	create_dir(mail_info->save_path, "qq", mail_info->from);
	write_to_file_m(mail_info);
	//write_oracle_db_cookieinfo(mail_info);
}

int analyse_m_qq_rcvmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\nanalyse_qq_rcvmail\n");
	int result;
	char *dest = NULL;
	char *pt = NULL;
	static int flagg = -1;

	if (is_to_s) 
	{
		if(!strncmp(data, "GET /cgi-bin/read_reminder?", 27))
		{
			mail_info->is_complished=1;
		}
		else
		{
			if(!strncmp(data, "GET /cgi-bin/readmail?", 22))
			{
				char *p1, *p2;
				int len_id;
				p1 = data;
				if(p1 == NULL) 
					return -1;
				p1 = strstr(p1,"mailid=");
				if (p1 == NULL) 
					return -1;
				p1+=7;
				p2 = strstr(p1, " HTTP/1.1");
				if (p2 == NULL) 
					return -1;
				len_id = p2 - p1;
				if (len_id < 0 || len_id > MAX_ID_LEN) 
					return -1;
				memcpy(mail_info->mail_id, p1,len_id);
				mail_info->mail_id[len_id] = 0;
				//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			if (result == -1)
				return -1;
		}
	} 
	else 
	{
		if(!strncmp(data,"HTTP/1.",7))
		{
			if(strstr(data, "Content-Encoding: gzip\r\n"))
				flagg = 1;
			else
				flagg = 0;
		}
		if (!mail_info->is_complished) 
		{
			result = write_to_okdata(mail_info, data, data_len, ptcp);
			if (result == -1)
				return -1;
		}
		if (ptcp->fin == 1 && !strncmp(mail_info->mail_data, "GET /cgi-bin/readmail?", 22))
			mail_info->is_complished = 1;
	}
	if (mail_info->is_complished) 
	{
		if(flagg)
		{
			result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 3, &dest);
			if (result == -1)
				return -1;
	
			free(mail_info->recive_data);
			mail_info->recive_data = dest;
		}
		//printf("%s\n\n**************\n", mail_info->mail_data);
		if(mail_info->recive_data != NULL && strstr(mail_info->recive_data,"\"fid\":\"3\"") && strstr(mail_info->recive_data,"\"rlyAllLst\":["))
			return -1;
        
		int flag = -1;
		dest = NULL;
		pt = strstr(mail_info->mail_data, "&folderid=8");
		if (pt != NULL)
			flag = 0;
		else
			flag = 1;
		get_cookie(mail_info->mail_data, mail_info->cookie_data);
		if (flag == 0)
		{
			//printf("2222222222222222222222\n");
			writefile_qq_group_rcvmail_m(mail_info);
		}
		else
		{
			//printf("1111111111111111111111\n");
			writefile_qq_rcvmail_m(mail_info);
		}

		return 0;
	}
}

int write_qq_attach_down_m(Mail_info *mail_info,unsigned int length, int is_chunk)
{//printf("mail_info->recive_data\n");
	
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->recive_data;
	char *p2;
	char filename[MAX_FN_LEN]="0";
	int len;
	char tmpname[MAX_FN_LEN]="0";
	if(p1==NULL) 
		return -1;
	p2 = strstr(p1,"attachment; filename=");
	if(p2==NULL)
	{
		p2 = strstr(p1,"attachment; filename=\"");
		if(p2 == NULL)
			return -1;
		p1 = p2;
		p1 += 22;
		p2 = strstr(p1,"\"");
	}
	else
	{
		p1 = p2;
 		p1 += 21;
		p2 = strstr(p1,"\r\n");
	}
	if(p2==NULL) 
		return -1;
	len = p2-p1;
	if(len>MAX_FN_LEN) 
		len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,filename);
	
	p1 = strstr(p2, "\r\n\r\n");
	if(p1==NULL) 
		return -1;
	p1 +=4;
	
	char str[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	//printf("attch_path : %s\n", str);
	
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
		if(p1==NULL) 
			return -1;
		p1 += 2;
		write(fd,p1,length);
		close(fd);
	}
   
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu",tv.tv_sec, tv.tv_usec);

	//UpdateAttach(str_file, mail_info->mail_id);
	UpdateAttachNew_m(str_file, filename, mail_info->mail_id);
}

int analyse_m_qq_attach_rcvmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq = seq - mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	
	if (is_to_s)
	{
		char tmp_id[MAX_ID_LEN + 1];
		int result;
		if (!strncmp(data, "GET /cgi-bin/download?mailid", 28))
		{
			char *p1, *p2;
			int len;
			p1 = data;
			if (p1==NULL) return -1;
			p2=memfind(p1, "mailid=",150);
			if (p2==NULL)
				return -1;
			p1=p2+7;
			p2 = strstr(p1,"&");
			if (p2==NULL)
				return -1;
			len = p2 - p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(tmp_id, p1, len);
			tmp_id[len] = 0;
			htmldecode_full(tmp_id,mail_info->mail_id);
			//printf("mail_info->mail_id111 : %s\n", mail_info->mail_id);
		}
		else 
		if(!strncmp(data, "GET /cgi-bin/download?sid", 25))
		{
			char *p1, *p2;
			int len;
			p1 = data;
			if (p1==NULL)
				return -1;
			p2=memfind(p1, "&mailid=",150);
			if (p2==NULL)
				return -1;
			p1=p2+8;
			p2 = strstr(p1," HTTP/1.1");
			if (p2==NULL)
				return -1;
			len = p2 - p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(tmp_id, p1, len);
			tmp_id[len] = 0;
			htmldecode_full(tmp_id,mail_info->mail_id);
			//printf("mail_info->mail_id222 : %s\n", mail_info->mail_id);
		}
		else
		if (!strncmp(data, "GET /cgi-bin/groupattachment?", 29))
		{
			char *p1, *p2;
			int len;
			p1 = data;
			if (p1==NULL) return -1;
			p2 = strstr(p1, "mailid=");
			if (p2==NULL)
				return -1;
			p1 = p2+7;
			p2 = strstr(p1,"&");
			if (p2==NULL)
				return -1;
			len = p2 - p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(tmp_id, p1, len);
			tmp_id[len] = 0;
			htmldecode_full(tmp_id,mail_info->mail_id);
			//printf("mail_info->mail_id444 : %s\n", mail_info->mail_id);
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n", 15))
		{
			//printf("****** 200 OK ******\n");
			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length <= 0)
				return -1;
			mail_info->recive_length += 1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			
			if(mail_info->recive_data == NULL)
				return -1;
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq;
		}
		if (mail_info->recive_data != NULL)
		{
			//printf("****** rebuild data ******\n");
			off_seq = seq - mail_info->http_seq;
			range = off_seq + data_len;
			if (range > mail_info->recive_length)
				return -1;
			memcpy(mail_info->recive_data + off_seq, data, data_len);
			recive_data_length_m = recive_data_length_m + data_len;
		}
		if (mail_info->recive_length-1000 == recive_data_length_m-(strstr(mail_info->recive_data,"\r\n\r\n")+4-mail_info->recive_data))
		{
			//printf("****** down_load attach over111 ****** \n%s\n", data);
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			if (attach_len <= 0) 
				return -1;
			write_qq_attach_down_m(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}
		else
		if (ptcp->fin == 1)
		{
			//printf("****** down_load attach over222 ****** \n%s\n", data);
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			if (attach_len <= 0)
				return -1;
			write_qq_attach_down_m(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}
		/*else
		if (ptcp->fin == 1 ||(ptcp->psh == 1 && strncmp(data, "HTTP/1.1 206 Partial Content", 28)))
		{
			//printf("****** down_load attach over333 ****** \n%s\n", data);
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			if (attach_len <= 0)
				return -1;
			write_qq_attach_down_m(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}*/
	}
}
void write_qq_psword_m(Mail_info *mail_info)
{//printf("\ngo in qq_pswordss\n");
	//判断是否是手机登录qqwebmail
	if(strstr(mail_info->mail_data, "&ts=") == NULL)
		return;

	char patternusername[]="&uin=(.*)&aliastype=";
	char patternpassword[]="&pwd=(.*)&mss=";
        memset(mail_info->username,0,MAX_UN_LEN+1);
        regcompile_1(mail_info->mail_data, patternusername, mail_info->username,MAX_UN_LEN); 
        convert_contents(mail_info->username);
        char *p=strstr(mail_info->username,"@qq.com");
        if(p == NULL)
        {
            int lengths = strlen(mail_info->username);
            strncpy(mail_info->username+lengths,"@qq.com",7);
            mail_info->username[lengths+7]=0;
        }
	int result = regcompile_1(mail_info->mail_data, patternpassword, mail_info->passwd,MAX_PW_LEN);
	if (result == -1) 
	{
		return;
	}
	htmldecode_full(mail_info->passwd,mail_info->passwd);
        //printf("usernamess = %s and password = %s",mail_info->username,mail_info->passwd);
	write_xml_m(mail_info);

	FILE *fp;
//	chdir(mail_data_path);
        char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	fp=fopen(passpath,"a+");
	if(fp==NULL) return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
}

int analyse_m_qq_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//printf("\ngo in login state\n");
	unsigned int seq = ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	char http_ok_head[11]="HTTP/1.1 ";
	
	if(is_b_s && !mail_info->is_complished)
	{
		if (mail_info->mail_length == 0)
		{
			mail_info->mail_length = 5000;
			mail_info->mail_data = (char *)malloc(5000);
			if(mail_info->mail_data ==NULL)
			{
				return -1;
			}
			memset(mail_info->mail_data,0,5000);
			mail_info->start_seq = seq;
		}
		if(mail_info->mail_length == 5000) 
		{
			int len;
			char *tmp;
			len = get_http_length(data);
			if (len > 0)
			{
				mail_info->mail_length += len;
				tmp = (char *)malloc(mail_info->mail_length);
				if(tmp == NULL)
				{
					return -1;
				}
				memset(tmp,0,mail_info->mail_length);
				memcpy(tmp,mail_info->mail_data,5000);
				free(mail_info->mail_data);
				mail_info->mail_data = tmp;
			}
		}
		off_seq = seq - mail_info->start_seq;
		range=off_seq+datalen;
		if(range>mail_info->mail_length)
		{
			return -1;
		}
		memcpy(mail_info->mail_data+off_seq,data,datalen);
	}
	else if(!strncmp(data,http_ok_head,9))
	{
		//printf("Data recive successfully!");
		write_qq_psword_m(mail_info);
		return -1;
	}
	return 0;
}
		
int analyse_m_qq(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned short type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
		case 0x02:
			//printf("\nanalyse_qq_psword\n");
			result = analyse_m_qq_psword(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x11:
			//printf("\nanalyse_qq_mail\ndata11 = %s\n",data);
			result = analyse_m_qq_mail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x21:
			//printf("\nanalyse_qq_rcvmail\n");
			result = analyse_m_qq_rcvmail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x29:
			//printf("\nanalyse_qq_attach_rcvmail\n");
			result = analyse_m_qq_attach_rcvmail(mail_info,data, data_len, ptcp, is_to_s);
			break;
		}
		
		if (result == -1)
			delete_mail_info(mail_info);
	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		if(type==0x61)
		{
			result=analyse_m_qq_attach(attach_info,data,data_len,ptcp,is_to_s);
		}
		if(result == -1)
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
    }
}

