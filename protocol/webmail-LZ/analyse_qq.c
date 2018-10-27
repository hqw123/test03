
#include "common.h"

unsigned  int recive_data_length = 0;
char attach_tmpname[MAX_FN_LEN + 1] = {0};

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
// 
void getMailbox(char *str, char *first, char last)
{
    int i = 0, j = 0;
    while(str[j] != '\0')
    {
        if(!strncmp(&str[j++], first, strlen(first)))
        {
            while(str[j] != last)
            	str[i++] = str[j++];
            str[i++] = '|';
        }
    }
    str[i-1] = '\0';
}
//yanglei add
void getMailbox1(char *str, char last)
{
	int i = 0;
	while(str[i] != '\0')
	{
		if(str[i] == last)
			str[i] = '|';
		i++;
	}
}
//yanglei add
void getMailbox2(char *str, char *first, char last)
{
    int i = 0, j = 0;
    while(str[j] != '\0')
    {
        if(!strncmp(&str[j++], first, strlen(first)))
        {
	    j = j + strlen(first) - 1;
            while((str[j] != last)&&(str[j] !='\0'))
            	str[i++] = str[j++];
            str[i++] = '|';
        }
    }
    str[i-1] = '\0';
}

char *get_info(char *src, char *front_str, char *back_str, char *dst, int MAX_LEN)
{
   
}

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
	{
#if 0
		if (dest)
		{
			free(dest);
			dest = NULL;
		}
#endif		
		return NULL;
	}
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
	tmp1 = NULL;

	return 0;
}

int qq_str_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	char *tmp2 = NULL;
	size_t len;

	tmp1 = qq_conv_to_utf8(str);
	if (NULL == tmp1)
	{
		tmp2 = conv_to_xml_symbol(str);
	}
	else
	{
		tmp2 = conv_to_xml_symbol(tmp1);
		free(tmp1);
	}

	if (tmp2 == NULL)
		return -1;
    
	len = strlen(tmp2);
	if (len > max_len)
		len = max_len;
    
	memcpy(str, tmp2, len);
	str[len] = 0;
	free(tmp2);
	tmp2 = NULL;

	return 0;
}

int get_boundary(char *src, char *boundary)
{
	char *p1 = NULL;
	char *p2 = NULL;
	int boun_len;
	
	if(!src)
		return -1;

	p1 = strstr(src, "; boundary=");
	if (p1 == NULL)
		return -1;
	p1 += 11;
	p2 = strstr(p1, "\r\n");
	if (p2 == NULL)
		return -1;
	boun_len = p2 - p1;
	if (p2 == NULL || boun_len > MAX_BOUN_LEN)
		return -1;
	memcpy(boundary, p1, boun_len);
	boundary[boun_len] = 0;

	return boun_len;
}

int writefileqq(Mail_info *mail_info)
{
	//printf("\nwritefileqq\n");
// 	Attach_info *attach_info;
// 	char boundary[MAX_BOUN_LEN + 1];
	char *p1 = NULL, *p2 = NULL, *tmp_str = NULL;
	size_t len, boun_len;
	int result, fd, n, i = 0, flag = 0;
// 	Attachment *attachment;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char attach_tag[MAX_BOUN_LEN + 101];
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

/* 	boun_len = get_boundary(mail_info->mail_data, boundary);
	if (boun_len == -1) 
	{
		return -1;
	}
	snprintf(attach_tag, MAX_BOUN_LEN + 100, "%s\r\nContent-Disposition: form-data; name=\"Uploader", boundary);
*/
// 
	p1 = strstr(mail_info->mail_data, "?sid=" );
  	// save id
	if (p1 == NULL)
	{
		LOG_WARN("webmail:writefileqq(): can not find ID\n");
		return -1;
	}
	else
	{
		p1 +=5;
		p2 = strstr(p1, "&");
		if(!strstr(p2, " HTTP/1.1"))
			p2 = strstr(p1, " ");
		if(p2 == NULL)
			return -1;
		len = p2 - p1;
		if(len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(mail_info->mail_id,p1,len);
		mail_info->mail_id[len] = 0;
	}
 	//printf("mail_info->mail_id : %s \n",mail_info->mail_id);
// 
	p1 = strstr(mail_info->mail_data, "; qm_username=");
	if (p1 == NULL)
	{
		//printf("bb\n");
		p1 = strstr( mail_info->mail_data, "qqmail_alias=");
		if(p1 == NULL)
			return -1;
		else p1 += 13;
		//printf("aaa\n");
		p2 = strstr(p1 , "@");
	}	
	else 
	{
		p1 += 14;
		p2 = strstr(p1, ";");
		if(p2 == NULL)
			p2 = strstr(p1 , "\r\n");
	}
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	//printf("len : %d\n",len);
	if (p2 == NULL || len > MAX_FROM_LEN - 8)
		return -1;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	strcat(mail_info->from, "@qq.com");
	p2++;
 	//printf("mail_info->from : %s \n",mail_info->from);

	p1 = strstr(p2, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL || len > MAX_TO_LEN - 8)
		return -1;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
 	//printf("mail_info->to : %s \n",mail_info->to);

	p1 = strstr(p2, "&cc=");
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1,"&");
		if (p2 == NULL)
			mail_info->cc[0] = 0;
		else
		{
			len = p2 - p1;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
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
		p2 = strstr(p1,"&");
		if (p2 == NULL)
			mail_info->bcc[0] = 0;
		else
		{
			len = p2 - p1;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
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
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
  	//printf("mail_info->subject : %s \n",mail_info->subject);
	create_dir(mail_info->save_path, "qq" ,mail_info->from);
	
	p1 = strstr(p2, "&content__html=");
	if (p1 == NULL)
		return -1;
    
	p1 = strstr(p1, "<DIV>");
	if (p1 == NULL)
	{
		p1 = strstr(p2, "&content__html=");
		p1 += 15;
		p2 = strstr(p1, "&");
		if(p2 == NULL)
			return -1;
		len = p2 - p1;
	}
	else
    {
    	p1 += 5;
    	p2 = strstr(p1, "</DIV>");
    	if (p2 == NULL)
    		return -1;
    	len = p2 - p1;
	}
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;

    memset(mail_info->content, 0, len+1);
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	
// 
// 	char  *tmp_str;
	Attach_info *attach_tmp;
	Attachment *attachment;
	Attach_info *attach_info = attach_tab.head->next;
	
	
	while (attach_info != NULL) 
	{
		//printf("attach_info->ID_str : %s\n",attach_info->ID_str);
		if (!strcmp(attach_info->ID_str, mail_info->mail_id))
		{
			i++;
			filename[0] = 0;
			get_file_name(attach_info->path_of_sender, filename);
			if(filename[0] == 0)
				strcpy(filename ,attach_info->path_of_sender);
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
	//printf("num_of_attach : %d \n",mail_info->num_of_attach);

/*	result = qq_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = qq_str_convert2(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;*/
/*	result = qq_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;*/
	
	/*tmp_str = qq_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);*/

	char *tmp_p1 = NULL;
	tmp_p1 = clear_html_tag(mail_info->content);
	free(mail_info->content);
	mail_info->content = clear_html_symbol(tmp_p1);
	free(tmp_p1);
	tmp_p1 = NULL;

	htmldecode_full(mail_info->content ,mail_info->content);
	if (NULL == mail_info->content)
		return -1;

// 	printf("mail_info->subject : %s \n",mail_info->subject);
// 	printf("mail_info->content : %s \n",mail_info->content);
	getMailbox(mail_info->to, "<", '>');
	getMailbox(mail_info->cc, "<", '>');
	getMailbox(mail_info->bcc, "<", '>');
	getMailbox1(mail_info->to, ';');
	getMailbox1(mail_info->cc, ';');
	getMailbox1(mail_info->bcc, ';');
// 	printf("information %s %s %s %s \n",mail_info->to,mail_info->from,mail_info->cc,mail_info->bcc);
	write_to_file(mail_info);
}


int writefile_qq_group(Mail_info *mail_info)
{//printf("\nwritefile_qq_group\n");
// 	Attach_info *attach_info;
// // 	char boundary[MAX_BOUN_LEN + 1];
	char *p1 = NULL, *p2 = NULL;
	char *tmp_str;
	int len, qq_num_len = -1;
	int boun_len;
	int result;
	char attach_tag[MAX_BOUN_LEN + 101];
	char filepath[MAX_PATH_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char ID[MAX_ID_LEN + 1];
// 	Attachment *attachment;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd;
	int n, i = 0;
	int flag = 0;

	
	
	//printf("%s\n", mail_info->mail_data);

	p1 = strstr(mail_info->mail_data, "?sid=" );
  	// save id
	if (p1 == NULL)
	{
		LOG_WARN("webmail:writefileqq(): can not find ID\n");
		return -1;
	}
	else
	{
		p1 +=5;
		p2 = strstr(p1, "&sid");
		if(p2 == NULL)
			return -1;
		len = p2 - p1;
		if(len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(mail_info->mail_id,p1,len);
		mail_info->mail_id[len] = 0;
	}
// 
	p1 = strstr(mail_info->mail_data, "; qm_username=");
	if (p1 == NULL)
		return -1;
	p1 += 14;
	p2 = strstr(p1, ";");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL || len > MAX_FROM_LEN - 8)
		return -1;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	strcat(mail_info->from, "@qq.com");
	p2++;

	p1 = strstr(p2, "&qqgroupid=");
	if (p1 == NULL)
		return -1;
	p1 += 11;
	p2 = strstr(p1, "&");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (p2 == NULL || len > MAX_TO_LEN - 8)
		return -1;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	


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
	

	create_dir(mail_info->save_path, "qq" ,mail_info->from);

	

	p1 = strstr(p2, "&content__html=");
	if (p1 == NULL)
		return -1;
	p1 = strstr(p1, "<DIV>");
	if (p1 == NULL)
		return -1;
	p1 += 5;
	p2 = strstr(p1, "</DIV>");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;

	mail_info->content = (char *)malloc(len + 1);
         memset(mail_info->content,0,len+1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	
// 
// 	char  *tmp_str;
	Attach_info *attach_tmp;
	Attachment *attachment;
	Attach_info *attach_info = attach_tab.head->next;
	
	
	while (attach_info != NULL) 
	{
		//printf("attach_info->ID_str : %s\n",attach_info->ID_str);
		if (!strcmp(attach_info->ID_str, mail_info->mail_id))
		{
			i++;
			filename[0] = 0;
			get_file_name(attach_info->path_of_sender, filename);
			if(filename[0] == 0)
				strcpy(filename ,attach_info->path_of_sender);
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
// 		
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
// 	printf("information %s %s %s %s \n",mail_info->to,mail_info->from,mail_info->subject,mail_info->content);
	write_to_file(mail_info);
	return 0;
}

int analyse_qq_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;

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
// 		printf("\nwritefileqq\n");
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		if (mail_info->mail_type == 0x0B11)
		{
			writefileqq(mail_info);
		}
		else 
		if (mail_info->mail_type == 0x0B12)
		{
// 			printf("group_mail ...\n");
			writefile_qq_group(mail_info);
		}
		
		//del_mail_node(mail_info);
		return 0;
	} 
	else 
	{
		return -1;
	}
}

int analyse_qq_attach_head(Attach_info *attach_info,char *data,unsigned int data_len,unsigned int seq)
{
// 	printf("analyse_qq_attach_head  data : %s\n",data);
	int fd;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	char  *p1=NULL ,*p2=NULL;
	char file_name_pattern[]="; filename=\"(.*)\"\r\nContent-Type: ";
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ;
	int range = 0;

	off_seq = seq-attach_info->start_seq;
	range = off_seq+data_len;
	if(range > attach_info->ok_len)
        return -1;
	memcpy(attach_info->ok_data+off_seq, data, data_len);
	
	if(attach_info->ID_str[0] == 0)
	{
		p1 =strstr(attach_info->ok_data,"?sid=");
		if(p1==NULL)
			return -1;
		p1 += 5;
		p2=strstr(p1,"&");
		if(p2==NULL)
			return -1;
		int len = p2-p1;
		if(len>MAX_ID_LEN)
			return -1;
		strncpy(attach_info->ID_str,p1,len);
		attach_info->ID_str[len]=0;
		//printf("ID :%s \n",attach_info->ID_str);
	}

	p1 = strstr(attach_info->ok_data,"; filename=\"");
	if(p1 == NULL) 
	{
		p1 = strstr(attach_info->ok_data , "type=try&newflash=1&name=");
		if(p1 != NULL )
		{
			
			p1 += 25;
			p2 = strstr(p1 ,"&" );
			if(p2 == NULL)
				return 0;
			memset(attach_tmpname , 0 ,MAX_FN_LEN + 1 );
			int len = p2 - p1; 
			memcpy(attach_tmpname , p1 , len);
			attach_tmpname[len] = 0;
			//printf("attach_tmpname1 : %s\n",attach_tmpname);
			attach_info->ID_str[0] = 0;
			del_attach_node(attach_info);
			delete_attach(attach_info);
			return 0;
			/*if( !strstr(p1 , "HTTP/1.1\r\nAccept:"))
			{	
				del_attach_node(attach_info);
				delete_attach(attach_info);
				return 0;
			}
			printf("find the head..\n");*/
		}
		else if(strstr( attach_info->ok_data, "try&name=") )
		{
			p1 = strstr( attach_info->ok_data, "try&name=");
			p1 += 9;
			p2 = strstr(p1 , "&");
			if(p2 == NULL)
				return 0;
			memset(attach_tmpname , 0 ,MAX_FN_LEN + 1 );
			int len = p2 - p1; 
			memcpy(attach_tmpname , p1 , len);
			attach_tmpname[len] = 0;
			//printf("attach_tmpname2 : %s\n",attach_tmpname);
			attach_info->ID_str[0] = 0;
			del_attach_node(attach_info);
			delete_attach(attach_info);
			return 0;
		}
		else if(attach_tmpname[0] != '\0' )
		{
			attach_info->path_of_sender = (char *)malloc(MAX_FN_LEN + 1);
			strncpy(attach_info->path_of_sender , attach_tmpname ,MAX_FN_LEN + 1 );
			htmldecode_full(attach_info->path_of_sender ,attach_info->path_of_sender);
			//printf("attach_info->path_of_sender : %s\n",attach_info->path_of_sender);
			memset(attach_tmpname , 0 ,MAX_FN_LEN + 1 );
			p1 = attach_info->ok_data;
		}
		else
		{	
			
				p1 = strstr(attach_info->ok_data,"MAIL-FILENAME: " );
				if(p1 == NULL)
					return 0;
				p1 += 15;
				p2 = strstr(p1 , "\r\n");
				if(p2 == NULL)
					return 0;
				attach_info->path_of_sender = (char *)malloc(MAX_FN_LEN + 1);
				memcpy(attach_info->path_of_sender , p1 , p2 - p1);
				attach_info->path_of_sender[p2-p1] = 0;	
				htmldecode_full(attach_info->path_of_sender ,attach_info->path_of_sender);
				//printf("attach_info->path_of_sender2 : %s\n",attach_info->path_of_sender);
			
		}
	}
	else
	{
		regcompile_2(attach_info->ok_data,file_name_pattern, &attach_info->path_of_sender); //2
	}

	p2 = strstr(p1,"\r\n\r\n");
	if(p2 == NULL) 
		return 0;
	p2 += 4;
	attach_info->start_seq = p2-attach_info->ok_data+attach_info->start_seq;  //1
	gettimeofday(&tv,&tz);
	snprintf(attach_info->path_of_here,MAX_PATH_LEN,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);//3
	//printf("qq attach_info->path_of_here : %s\n",attach_info->path_of_here);
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

int analyse_qq_attach(Attach_info * attach_info,char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
// 	printf("\nanalyse_qq_attach\n");
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;
	char *p1=NULL ,*p2=NULL;
	int len;

	if (is_to_s) 
	{
		if(attach_info->is_writing)
		{
			result = write_to_attach(attach_info,data,data_len,seq);
		} 
		else 
		{
			result = analyse_qq_attach_head(attach_info,data,data_len,seq); 
		}
		return result;
	}
	else 
	if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15) && attach_info->is_writing)
	{
		attach_info->is_complished = 1;
 		if(strstr(attach_info->path_of_sender , ".rar") || strstr(attach_info->path_of_sender , ".pdf") || strstr(attach_info->path_of_sender , ".zip"))
			trim_attach(attach_info->path_of_here,0);
		else
 			trim_attach(attach_info->path_of_here,151);
		//printf("qq attach upload end ...\n");
		return 0;
	}
}

int analyse_qq_attach_2(Attach_info * attach_info,char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	if (is_to_s) 
	{
		int f = http_recive_attach(attach_info, data, data_len);
		if (f == 1)
		{
			attach_info->is_complished = 1;
			if(strstr(attach_info->header,"Content-Type: multipart/form-data"))
			{
				int fd;
				struct timeval tv;
				struct timezone tz;
				mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ;
				int len;
				char boundary[51];
				char * p1, *p2;

				p1 =strstr(attach_info->header,"?sid=");
				if(p1==NULL)
					return -1;
				p1 += 5;
				p2=strstr(p1,"&");
				if(p2==NULL)
					return -1;
				len = p2-p1;
				if(len>MAX_ID_LEN)
					return -1;
				strncpy(attach_info->ID_str,p1,len);
				attach_info->ID_str[len]=0;
				
				p1 = attach_info->body;
				p2 = strstr(attach_info->body,"\r\n");
				len = p2-p1;
				if(len>50) len=50;
				memcpy(boundary,p1,len);
				boundary[len]=0;

				p1 = strstr(p2,"Content-Disposition: form-data; name=\"Filename\"");
				if(!p1) return -1;
				p1 = strstr(p1,"\r\n\r\n");
				if(!p1) return -1;
				p1+=4;
				p2 = strstr(p1,"\r\n");
				attach_info->path_of_sender=(char *)malloc(p2-p1+1);
				memcpy(attach_info->path_of_sender,p1,p2-p1);
				attach_info->path_of_sender[p2-p1]=0;

				p1 = strstr(p1,"Content-Disposition: form-data; name=\"UploadFile\";");
				if(!p1) return -1;
				p1 = strstr(p1,"\r\n\r\n");
				if(!p1) return -1;
				p1+=4;
				p2 = memfind(p1,boundary,attach_info->bodyLen-(p1-attach_info->body));
				if(!p2) return -1;
				p2-=2;
				
				gettimeofday(&tv, &tz);
				snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
				fd = open(attach_info->path_of_here, O_WRONLY|O_CREAT,file_mode);
				if(fd==-1) return -1;
				write(fd,p1,p2-p1);
				return 0;
			}
			else return -1;

		}
	}
	return 0;
	/*else 
	if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15) && attach_info->is_writing)
	{
		attach_info->is_complished = 1;
 		if(strstr(attach_info->path_of_sender , ".rar") || strstr(attach_info->path_of_sender , ".pdf") || strstr(attach_info->path_of_sender , ".zip"))
			trim_attach(attach_info->path_of_here,0);
		else
 			trim_attach(attach_info->path_of_here,151);
		printf("qq attach upload end ...\n");
		return 0;
	}*/
}

int writefile_qq_group_rcvmail(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp_str = NULL;
	size_t len;
	int result;

	//printf("%s\n", mail_info->recive_data);
	pstart = strstr(mail_info->body, "var g_uin=\"");
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pend = strstr(pstart, "\";");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (pend == NULL || len + 8 > MAX_UN_LEN)
		return -1;
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	strcat(mail_info->to, "@qq.com");

	pstart = strstr(mail_info->body, "subject : \"");
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pend = strstr(pstart, "\",");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	pstart = strstr(pend, "from : {");
	if (pstart == NULL)
		return -1;
	pstart += 8;
	pstart = strstr(pstart, "addr : \"");
	if (pend == NULL)
		return -1;
	pstart += 8;
	pend = strstr(pstart, "\",");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;
	//printf("mail_info->from : %s\n", mail_info->from);

	pstart = strstr(mail_info->body, "<div class=\"gpcontent");
	if (pstart == NULL)
	{
		pstart = strstr(mail_info->body,"<div id=\"contentDiv gpcontent_1\"");
		if(pstart==NULL) return -1;
	}
	pend = strstr(pstart+20, "<div class=\"");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	*pend = 0;
	mail_info->content = strdup(pstart);
	
	result = qq_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = qq_conv_to_utf8(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (mail_info->content == NULL)
		return -1;
	
	//printf("mail_info->content : %s\n", mail_info->content);
	
	create_dir(mail_info->save_path, "qq", mail_info->from);
	write_to_file(mail_info);
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
	write_to_file(mail_info);
}
#endif

int writefile_qq_rcvmail(Mail_info *mail_info)
{//printf("\nwritefile_qq_rcvmail\n");
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = NULL;
	//int is_english = 0;
	size_t len;
	int result;
	char code_encoding[20]={"charset=gb2312"};

	pstart = strstr(mail_info->body, "from: { \n");
	if (pstart==NULL)
	{
		pstart = strstr(mail_info->body,"from : { \n");
		if(pstart==NULL)
			return -1;
	}
        pstart += 9;
	pstart = strstr(pstart, "addr : \"");
	if (pstart==NULL)
		return -1;
	pstart += 8;
	pend = strstr(pstart,"\",\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len>MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from,pstart,len);
	mail_info->from[len]=0;
	//printf("mail_info->from : %s\n",mail_info->from);

	pstart=strstr(pend,"date: \"");
	if (pstart==NULL) 
		return -1;
	pstart += 7;
	pend = strstr(pstart,"\",\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);//ch_time
	mail_info->sent_time[len] = 0;
	//printf("mail_info->sent_time : %s\n", mail_info->sent_time);

	pstart=strstr(pend,"to: [");
	if (pstart==NULL) 
		return -1;
	pstart+=5;
	pstart = strstr(pstart, "addr : \"");
	if (pstart==NULL)
		return -1;
	pstart += 8;
	pend = strstr(pstart,"\",\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	//printf("mail_info->to : %s\n", mail_info->to);

        pstart=strstr(pend, "cc: [");
        if (pstart==NULL) 
		return -1;
        pstart+=6;
	pend = strstr(pstart, "],\n");
	if (pend == NULL) 
		return -1;
	len = pend - pstart;
	if(len != 0)
	{
		pstart = strstr(pstart, "addr : \"");
		if (pstart==NULL)
			return -1;
		pstart += 8;
		pend = strstr(pstart,"\",\n");
		//pend = strstr(pstart, "],\n");
		if (pend == NULL) 
			return -1;
		len = pend - pstart;
		len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
		memcpy(mail_info->cc, pstart, len);
		mail_info->cc[len] = 0;
		//printf("mail_info->cc : %s\n", mail_info->cc);
	}

        pstart=strstr(pend, "subject: \"");
        if (pstart==NULL) 
		return -1;
        pstart+=10;
        pend=strstr(pstart,"\",\n");
        if (pend==NULL) 
		return -1;
        len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	pstart = strstr(mail_info->body, "<div id=\"mailContentContainer\"");
	if (pstart==NULL) 
		return -1;
	pstart += 30;
	pstart = strstr(pstart, ">");
	if (pstart==NULL) 
		return -1;
	pstart += 1;
	//pend = strstr(pstart, "id=\"");
	pend = strstr(pstart,"<script>");
	if (pend == NULL)
		return -1;
	*pend = 0;
	mail_info->content = strdup(pstart);
	if (mail_info->content == NULL)
		return -1;
	//printf("mail_info->content : %s\n", mail_info->content);

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

	//printf("mail_info->content : %s\n", mail_info->content);
//printf("\n%s:cookie = %s\n",mail_info->to,mail_info->cookie_data);
	create_dir(mail_info->save_path, "qq", mail_info->from);
	getMailbox2(mail_info->to, "addr : \"", '"');
	getMailbox2(mail_info->cc, "addr : \"", '"');
	getMailbox2(mail_info->bcc, "addr : \"", '"');
	write_to_file(mail_info);
}

int analyse_qq_rcvmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\nanalyse_qq_rcvmail\n");
	int result;
	char *dest = NULL;
	char *pt = NULL;
	static int flagg = -1;
	static int flag = 0;

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
				p2 = strstr(p1, "&");
				if (p2 == NULL) 
					return -1;
				len_id = p2 - p1;
				if (len_id < 0 || len_id > MAX_ID_LEN) 
					return -1;
				memcpy(mail_info->mail_id, p1,len_id);
				mail_info->mail_id[len_id] = 0;
				if(strstr(data, "&t=readmail_group"))
					flag=1;
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			if (result == -1)
				return -1;
		}
	} 
	else if(mail_info->mail_id[0])
	{
		int f = http_recive_mail(mail_info,data,data_len);
		if (f == 1)
		{
			//printf("mail recive down--\n");
			char * s;
			int slen;
			if(strstr(mail_info->header,"Content-Encoding: gzip\r\n"))
			{
				inflate_read(mail_info->body,mail_info->bodyLen,&s,&slen,1);
				//int f=inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				//if(f!=Z_OK){ printf("gzip decode error");return -1;}
				free(mail_info->body);
				mail_info->body=s;
				mail_info->bodyLen=slen;
			}
            
			get_cookie(mail_info->mail_data, mail_info->cookie_data);
			if (flag)
			{
				writefile_qq_group_rcvmail(mail_info);
			}
			else
			{
				writefile_qq_rcvmail(mail_info);
			}
            
			return -1;
		}
        else if (f < 0)
            return -1;
	}
	return 0;
}

//
char * get_qqreal_data(char *data  ,int is_ok_chunked,unsigned int data_len)
{
	//printf("get_real_data... \n");
	char *p1 = NULL;
	char *recive_tmp = (char *)malloc(data_len );
	p1 = strstr(data, "\r\n\r\n");
	
	p1 +=4;
	if(is_ok_chunked)
	{	p1 = strstr(p1,"\r\n");
		p1 +=2;
	}
	memcpy(recive_tmp, p1, data_len);
	recive_tmp[data_len] = 0;
	free(data);
	data = recive_tmp;
	return data;
}
//
int write_qq_attach_down(Mail_info *mail_info)
{//printf("mail_info->recive_data\n");
	
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = mail_info->header;
	char *p2 , *dest = NULL;
	char filename[MAX_FN_LEN+1]="0";
	int len;
	char tmpname[MAX_FN_LEN+1]="0";
	if(p1==NULL) 
		return -1;
	p2 = strstr(p1,"attachment; filename=");
	if(p2==NULL)
	{
		p2 = strstr(p1,"filename*=UTF-8''");
		if(!p2)
		{
			p2 = strstr(p1,"attachment; filename");
			if(p2 == NULL)
				return -1;
			p1 = p2;
			p1 += 20;
			p2=strstr(p1,"\"UTF-8''");
			if(p2)
			{
				p1=p2+8;
				p2 = strstr(p1,"\"\r\n");
			}
			else
				p2=strstr(p1,"\r\n");
		}
		else
		{
			p1=p2+17;
			p2 = strstr(p1,"\r\n");
		}
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
	memcpy(tmpname,p1,len);
	tmpname[len]=0;
	
	regmatch_t pm[4];
	char * tmpsub=tmpname;
	int ret = reg(tmpsub,"=\\?(\\S+)\\?(q|Q|b|B)\\?(.+)\\?=",pm,4);
	if(!ret)
	{
		char charset[15]={0};
		memcpy(charset,tmpsub+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
		char * tmpsub2 = (char *)malloc(len+1);
		if(!tmpsub2) return -1;
		char ch=*(tmpsub+pm[2].rm_so);
		if(ch=='q'||ch=='Q')
			equal_convert(tmpsub+pm[3].rm_so,pm[3].rm_eo-pm[3].rm_so,tmpsub2);
		else if(ch=='b'||ch=='B')
			base64Decode(tmpsub+pm[3].rm_so,pm[3].rm_eo-pm[3].rm_so,tmpsub2);
		//printf(tmpsub2);
		code_convert(charset,"utf8",tmpsub2,strlen(tmpsub2),tmpsub,100);
		free(tmpsub2);
		tmpsub2 = NULL;
	}
	htmldecode_full(tmpname,tmpname);
	char str[MAX_PATH_LEN+1];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	//printf("attch_path : %s\n", str);
	
	
	int fd;
	fd = open(str, O_RDWR | O_CREAT, file_mode);
	
	write(fd, mail_info->body, mail_info->bodyLen);
	close(fd);
	
	char str_file[MAX_PATH_LEN+1];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu",tv.tv_sec, tv.tv_usec);

// 	UpdateAttach(str_file, mail_info->mail_id);
	if(mail_info->mail_id[0] != '\0')
 		UpdateAttachNew(str_file, tmpname, mail_info->mail_id);
}

int analyse_qq_attach_rcvmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
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
		if (strstr(data, "Referer: http://m127.mail.qq.com/cgi-bin/readmail?folderid=1&t=readmail&mailid="))
		{
			char *p1, *p2;
			int len;
			p1 = data;
			if (p1==NULL)
				return -1;
			p2 = strstr(p1, "&mailid=");
			if (p2==NULL)
				return -1;
			p1 = p2 + 8;
			p2 = strstr(p1,"&mode=");
			if (p2==NULL)
				return -1;
			len = p2 - p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(tmp_id, p1, len);
			tmp_id[len] = 0;
			htmldecode_full(tmp_id,mail_info->mail_id);
			//printf("mail_info->mail_id333 : %s\n", mail_info->mail_id);
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
		if(mail_info->mail_id[0] == '\0' )
		{
			char *p1, *p2;
			int len;
			p1 = strstr(data ,"mailid=");
			if(p1 != NULL)
			{
				p1 += 7;
				p2 = strstr(p1 , "&");
				if (p2==NULL)
					return -1;
				len = p2 - p1;
				if (len < 0 || len > MAX_ID_LEN)
					return -1;
				memcpy(tmp_id, p1, len);
				tmp_id[len] = 0;
				htmldecode_full(tmp_id,mail_info->mail_id);
				//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
				
			}
		}
		
	}
	else if(mail_info->mail_id[0])
	{
		int f = http_recive_mail(mail_info,data,data_len);
		if (f == 1)
		{
			//printf("attach recive down --------\n");
			char * s;
			int slen;
			if(strstr(mail_info->header,"Content-Encoding: gzip\r\n"))
			{
				inflate_read(mail_info->body,mail_info->bodyLen,&s,&slen,1);
				//int f=inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				//if(f!=Z_OK){ printf("gzip decode error");return -1;}
				free(mail_info->body);
				mail_info->body=s;
				mail_info->bodyLen=slen;
			}
			write_qq_attach_down(mail_info);
			return -1;
		}
        else if (f < 0)
            return -1;
		
		/*if(mail_info->mail_id[0] == '\0')
			return -1;
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n", 15))
		{
// 			printf("****** 200 OK ******\n");

			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length <= 0)
				return -1;
			mail_info->recive_length += 1000;
// 			printf("mail_info->recive_length :%d\n",mail_info->recive_length);
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			
			if(mail_info->recive_data == NULL)
				return -1;
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq;
		}
		if (mail_info->recive_data != NULL)
		{
			off_seq = seq - mail_info->http_seq;
			range = off_seq + data_len;
			if (range > mail_info->recive_length)
				return -1;
			memcpy(mail_info->recive_data + off_seq, data, data_len);
			mail_info->ok_length +=   data_len;
// 			printf("mail_info->ok_length : %d\n",mail_info->ok_length);
		}
		if (mail_info->recive_data != NULL && (ptcp->fin == 1 ||
			(mail_info->recive_length-1000 <= mail_info->ok_length-(strstr(mail_info->recive_data,"\r\n\r\n")+4-mail_info->recive_data))))
		{
			printf("******qq down_load attach over111 ****** \n\n");
			
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			printf("mail_info->ok_length : %d  attach_len : %d\n",mail_info->ok_length , attach_len);
			if (attach_len <= 0) 
				return -1;
			write_qq_attach_down(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}
		/*else
		if (ptcp->fin == 1 ||(ptcp->psh == 1 && strstr(data, "HTTP/1.1 200 OK")))
		{
			printf("****** down_load attach over222 ****** \n%s\n", data);
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			if (attach_len <= 0)
				return -1;
			write_qq_attach_down(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}
		else
		if (ptcp->fin == 1 ||(ptcp->psh == 1 && strncmp(data, "HTTP/1.1 206 Partial Content", 28)))
		{
			//printf("****** down_load attach over333 ****** \n%s\n", data);
			mail_info->is_complished = 1;
			attach_len = get_http_length_2(mail_info->recive_data, &n);
			if (attach_len <= 0)
				return -1;
			write_qq_attach_down(mail_info, attach_len, n);
			del_mail_node(mail_info);
		}*/
	}
	return 0;
}
void write_qq_psword(Mail_info *mail_info)
{//printf("\ngo in qq_pswordss\n");
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
		return ;
	}
	htmldecode_full(mail_info->passwd,mail_info->passwd);
        //printf("usernamess = %s and password = %s",mail_info->username,mail_info->passwd);
	write_xml(mail_info);

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

int analyse_qq_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
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
		if(strstr(mail_info->mail_data,"&pwd="))
		{
			write_qq_psword(mail_info);
			return -1;
		}
	}
	else if(!strncmp(data,http_ok_head,9))
	{
		//printf("Data recive successfully!");
		write_qq_psword(mail_info);
		return -1;
	}
	
	return 0;
}

int analyse_qq(PacketInfo * packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
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
			result = analyse_qq_psword(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x11:
			//printf("\nanalyse_qq_mail\ndata11 = %s\n",data);
			result = analyse_qq_mail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x12:
			//printf("\nanalyse_qq_mail\ndata12 = %s\n",data);
			result = analyse_qq_mail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x21:
            result = analyse_qq_rcvmail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x29:
            result = analyse_qq_attach_rcvmail(mail_info, data, data_len, ptcp, is_to_s);
			break;
			//printf("\nanalyse_qq_attach_rcvmail\n");
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
            result = analyse_qq_attach_2(attach_info, data, data_len, ptcp, is_to_s);
    	}
        
		if(result == -1)
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
    }
}

