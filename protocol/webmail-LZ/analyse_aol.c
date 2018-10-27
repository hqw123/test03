
#include "common.h"

extern int clear_tag(char *src);
char ID_str[41];
unsigned int data_length=0;
unsigned int attachdata_length=0;

void htmldecode_fulll(char *src, char *dest)
{
	int strlength=strlen(src);
	if(strlength<3)
	{
		strcpy(dest,src);
		return ;
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
		if(src[i] =='=')
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
					dest[j] = '=';
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
}




char *clear_yh(char *source)
{
    if (source == NULL)
        return NULL;
		
    char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
    int result;
    if (result != -1)
        result = cns_str_ereplace(&str, "\"", "");
    if (result != -1)
        result = cns_str_ereplace(&str, "\\\\n", "\n");
    return str;
}

char *clear_b(char *p, int len)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = (char *)malloc(len);
	memset(tmp, 0, len);
	pstart = p;
	while(strstr(pstart, "<"))
	{
		pstart = strstr(pstart, "<");
		if (pstart == NULL)
			break;
		pstart += 1;
		pend = strstr(pstart, ">");
		if (pend == NULL)
			break;
		memcpy(tmp+strlen(tmp), pstart, pend-pstart);
		strcat(tmp, ",");
		pstart = pend;
	}
	return tmp;	
}


void write_attach_down_4(Mail_info *mail_info,unsigned int length, int is_chunk)
{
	//printf("write_attach_down_4()\nmail_info->mail_data: %s\n", mail_info->mail_data);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int len;
	char *p1 = mail_info->mail_data;
	char *p2;
	char filename[MAX_FN_LEN]={0};
	char tmpname[MAX_FN_LEN]={0};
	char tmp[MAX_FN_LEN]={0};
	char *pzip_judge = NULL;
	char *p3 = mail_info->recive_data;
	char *p4 = NULL;
	if (p3==NULL)
	{
		 return;
	}
	pzip_judge = memfind(p1,"Content-Encoding: gzip\r\n", mail_info->mail_length);
	p1 = strstr(p1, "tachment; filename=\"");
	if (p1 == NULL)
		return;
	p1 += 20;
	p2 = strstr(p1, "\"\r\n");
	if (p2 == NULL)
		return;
	len = p2-p1;
	if(len>MAX_FN_LEN) len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	//printf("tmpname: %s\n", tmpname);
	if (strstr(tmpname, "?utf-8?Q?"))
	{
		p1 = tmpname;
		while (strstr(p1, "?utf-8?Q?"))
		{
			p1 = strstr(p1, "?utf-8?Q?");
			if (p1 == NULL)
				break;
			p1 += 9;
			p2 = strstr(p1, "?=");
			if (p2 == NULL)
				break;
			memcpy(tmp + strlen(tmp), p1, p2 - p1);
			p1 = p2;
		}
		memset(tmpname, 0, sizeof(tmpname));
		strcpy(tmpname, tmp);
		//printf("tmpname: %s\n", tmpname);
		htmldecode_fulll(tmpname, filename);
	}
	else
		htmldecode_full(tmpname,filename);
	
	p4 = strstr(p3, "\r\n\r\n");
	if(p4==NULL) return ;
	p4 +=4;
	
	char str_dir[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(str_dir, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec,filename);
	//printf("str_dir: %s\n", str_dir);
	
	int fd;
	
	fd = open(str_dir, O_RDWR | O_CREAT, file_mode);
	if(!is_chunk)
	{
		if(pzip_judge)
		{
			decomp_gzip_2(p4,length,&mail_info->recive_data);
			if(mail_info->recive_data==NULL) return;
			p4=mail_info->recive_data;
			length=strlen(p4);
		}
		write(fd, p4, length);
		close(fd);
	}
	else
	{
		p4=strstr(p4,"\r\n");
		if(p4==NULL) return;
		p4 += 2;
		if (pzip_judge)
		{
			decomp_gzip_2(p4,length,&mail_info->recive_data);
			if(mail_info->recive_data==NULL) return;
			p4=mail_info->recive_data;
			length=strlen(p4);
		}
		write(fd,p4,length);
		close(fd);
	}
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec, filename);
	//printf("str_file: %s\n", str_file);
	strcpy(filename, clear_yh(filename));
	//printf("filename: %s\n", filename);
	
	UpdateAttachNew(str_file,filename, mail_info->mail_id);
}



char *strnstr(char *src, size_t srcLen, char *substr, size_t substrLen)
{
	size_t i, len;
	char *p = src;
	char *p1 = NULL;
	char *p2 = NULL;

	if (src == NULL || substr == NULL)
		return NULL;
        if (srcLen < substrLen) 
		return NULL;
	len = srcLen - substrLen + 1;
	for (i = 0; i < len; i++) 
	{
		if (*p != *substr) {
			p++;
			continue;
		}

		p1 = substr;
		p2 = p;
		int j = 0;
		while (j < substrLen) 
		{
			j++;
			if (*(++p2) != *(++p1))
				break;
		}
		if (j == substrLen) {
			return p;
		}
		p++;
	}
	return NULL;
}



void writefileaol(Mail_info *mail_info)
{
	char patternfrom[]="requests=%5B%7B%22From%22%3A%22(.+?)%22%2C%22To";
	char patternto[]="%22%2C%22To%22%3A%22(.+?)%22%2C%22Cc";
	char patterncc[]="%2C%22%2C%22Cc%22%3A%22(.+?)%22%2C%22Bcc";
	char patternbcc[]="%22%2C%22Bcc%22%3A%22(.+?)%22%2C%22Subject";
	char patternsubject[]="%22%2C%22Subject%22%3A%22(.+?)%22%2C%22RichBody";
	char patternsubject_2[]="%22%2C%22Subject%22%3A%22(.+?)%22%2C%22PlainBody";
	char patterncontent[] ="%22%2C%22PlainBody%22%3A%22(.+?)%22%2C%22RichEdit";

	memset(mail_info->from,0,MAX_FROM_LEN+1);
	regcompile_1(mail_info->mail_data, patternfrom, mail_info->from, MAX_FROM_LEN);
	convert_contents(mail_info->from);
	memset(mail_info->to,0,MAX_TO_LEN+1);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to, MAX_TO_LEN);
	convert_contents(mail_info->to);
	memset(mail_info->cc,0,MAX_CC_LEN+1);
	int k=regcompile_1(mail_info->mail_data, patterncc, mail_info->cc, MAX_CC_LEN);
	if(k!=-1)
	{
		convert_contents(mail_info->cc);
	}
	memset(mail_info->bcc,0,MAX_BCC_LEN+1);
	k=regcompile_1(mail_info->mail_data, patternbcc,mail_info->bcc, MAX_BCC_LEN);
	if(k!=-1)
	{
		convert_contents(mail_info->bcc);
	}
	k=regcompile_1(mail_info->mail_data, patternsubject, mail_info->subject, MAX_SUBJ_LEN);
	if(k==-1)
	{
		regcompile_1(mail_info->mail_data, patternsubject_2, mail_info->subject, MAX_SUBJ_LEN);
	}
	htmldecode_full(mail_info->subject, mail_info->subject);
	strcpy(mail_info->subject, clear_yh(mail_info->subject));
	//printf("mail_info->subject: %s\n", mail_info->subject);
	regcompile_2(mail_info->mail_data, patterncontent, &mail_info->content);
	htmldecode_full(mail_info->content, mail_info->content);
	strcpy(mail_info->content, clear_yh(mail_info->content));
	//printf("mail->info->content: %s\n", mail_info->content);
	if (mail_info->content != NULL)
	{
		convert_contents(mail_info->content);
	}
        memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"aol",mail_info->from);
        write_to_file(mail_info);
}

int analyse_aol_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	char http_ok_head[18]="HTTP/1.1 200 OK\r\n";
	
	if(is_b_s)
	{
		if(!mail_info->is_complished)
		{
			if (mail_info->mail_length == 0) 
			{
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data==NULL)
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
	}
	else if(!strncmp(data,http_ok_head,15))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefileaol(mail_info);
		del_mail_node(mail_info);
	}

	return 0;
}

void analyse_aol_attach_content(PacketInfo *packetInfo, Attach_info *attach_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,char *destMAC)
{
	unsigned int seq=ntohl(tcp->seq);
	int result=0;
        int off_seq;
        int data_seq;
        int flag = 0;
        char *p;
	char writepath[MAX_PATH_LEN] = {0};
	int  i=0;
	//printf(" analyse_aol_attach_content is_b_s: %d\n", is_b_s);

	if(is_b_s)
	{

		if (strstr(data, "/aol-6/en-us/common/rpc/RPC.aspx?") && strstr(data, "&transport=iframe&") && strstr(data, "&a=SendMessage&"))
		{
			if (strstr(data, "Content-Length: "))
			{
				attach_info->recive_length = 0;
				attach_info->recive_length = get_http_length(data);
				//printf("if attach_info->recive_length: %d\n", attach_info->recive_length);
			}
		}
		else if(strstr(data,"------") && attach_info->recive_data == NULL)
		{
			char *p1;
			char *p2;
			p1 = NULL;
			p2 = NULL;
			
			if (strstr(data, "Content-Length: "))
			{
				attach_info->recive_length = 0;
				attach_info->recive_length = get_http_length(data);
				//printf("else if attach_info->recive_length: %d\n", attach_info->recive_length);
			}
			if (attach_info->recive_length <= 0)
				return ;
			attach_info->recive_length += 2000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			memset(attach_info->recive_data,0,attach_info->recive_length);
			p1 = strstr(data,"------");
			if(p1 == NULL)
				return;
			p2 = strstr(p1,"\r\n");
			if (p2 == NULL)
				return;
			memset(ID_str, 0, sizeof(ID_str));
			memcpy(ID_str, p1, (p2-p1));
			//printf("ID_str: %s\n", ID_str);

			p1 = strstr(data,"------");
			if(p1 == NULL)
				return;
                        attach_info->start_seq = seq+(p1-data);
			memcpy(attach_info->recive_data, p1, datalen-(p1-data));
		}
		else
		{
			if((attach_info->recive_data != NULL) && datalen)// 
			{
				off_seq = seq - attach_info->start_seq;
				//printf("off_seq: %d\n", off_seq);
				if (off_seq+ datalen <= attach_info->recive_length)
				{
					memcpy(attach_info->recive_data + off_seq, data, datalen);
					//printf("writedata seq = %ul\n", seq);
				}
			}
		}
        }
	if(!is_b_s)
	{
		if(!attach_info->is_get_ok)
		{
			char http_ok_head[21]="HTTP/1.1 ";
			if(!strncmp(data,http_ok_head,9))
			{
				attach_info->is_get_ok=1;
				
				attach_info->is_complished =1;
				Mail_info *mail_info = (Mail_info *)malloc(sizeof(Mail_info));
				if (mail_info == NULL)
					return;
				memset(mail_info, 0, sizeof(Mail_info));
				get_time(data, mail_info->sent_time);
				mail_info->source_ip = attach_info->source_ip;
				mail_info->dest_ip = attach_info->dest_ip;
				mail_info->source_port = attach_info->source_port;
				mail_info->dest_port = attach_info->dest_port;
				memcpy(mail_info->client_mac, destMAC, MAC_LEN);
				mail_info->is_complished = 1;
				mail_info->mail_type = attach_info->attach_type;
				mail_info->mail_length = 0;
				mail_info->mail_data = NULL;
				mail_info->is_writing = 0;
				mail_info->recive_length = 0;
				mail_info->recive_data = NULL;
				mail_info->connect_id[0]=0;
				mail_info->mail_id = (char *)malloc(MAX_ID_LEN);
				memset(mail_info->mail_id, 0, MAX_ID_LEN);
				mail_info->is_proce_mail = 0;
				mail_info->num_of_attach = 0;
				mail_info->start_seq = attach_info->start_seq;
				mail_info->prev = mail_tab.head;
				mail_info->next = mail_tab.head->next;
				mail_tab.head->next = mail_info;
				/*add by zhangzm*/
				mail_tab.count++;
				if (mail_info->next != NULL)
					mail_info->next->prev = mail_info;

				mail_info->mail_num= 312;
				strcpy(mail_info->url, "mail.aol.com");

				char from_str[90];
				strncpy(from_str, ID_str, 40);
				from_str[40]=0;
				//printf("attach_info->recive_length: %d\n", attach_info->recive_length);
				//printf("attach_info->recive_data: %s\n", attach_info->recive_data);

				char *pstart = NULL;
				char *pend = NULL;
				int length;
				pstart = strnstr(attach_info->recive_data, attach_info->recive_length,"[{\"From\"", 8);
				if (pstart == NULL)
					return;
				pstart += 10;
				pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"To\":", 7);
				if (pend == NULL)
					return;
				length = pend - pstart;
				memcpy(mail_info->from, pstart, length);

				//printf("1.mail_info->from: %s\n", mail_info->from);
				memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
				create_dir(mail_info->save_path,"aol",mail_info->from);
				char *pp = attach_info->recive_data;

				while(attach_info->recive_data != NULL)
				{
					char *p1=memfind(attach_info->recive_data,"; filename=\"", attach_info->recive_length - (attach_info->recive_data - pp));
					if(p1 != NULL)
					{
						//printf("this is if\n");
						p1+=12;
						char *p2=memfind(p1,"\"\r\n", attach_info->recive_length - (p1 - pp));
						if(p2 == NULL)
							return;
						int len = p2 - p1;
						if(len>0)
						{
							i++;
							memset(attach_info->attach_name, 0, sizeof(attach_info->attach_name));
							strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
							//printf("21. attach_info->attach_name: %s\n", attach_info->attach_name);
							attach_info->attach_name[p2-p1]=0;

							p1=memfind(p1,"\r\n\r\n", attach_info->recive_length - (p1 - pp));
							p1+=4;
							char str[43] = {0};
							strncat(str,ID_str,40);
							p2 = memfind(p1, str, attach_info->recive_length-(p1-attach_info->recive_data)-strlen(str));
							if(p2 == NULL)
								return ;
							p2 -= 2;
							struct timeval tv;
							struct timezone tz;
							gettimeofday(&tv,&tz);
							sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); 
							mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
							//printf("1. attach_info->path_of_here: %s\n", attach_info->path_of_here);
							int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
							if (fd ==-1)
								return ;
							write(fd,p1,p2-p1);
							close(fd);
							Attachment *attachment = (Attachment *)malloc((sizeof(Attachment))+1);
							memset(attachment,0,(sizeof(Attachment))+1);
							memset(attachment->loc_filename,0,MAX_FN_LEN+1);
							attachment->next =NULL;
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
						}
						attach_info->recive_data = memfind(p2,ID_str, attach_info->recive_length - (p2 - pp));
						//printf("p2: %s\n", p2);
						//printf("ID_str: %s\n", ID_str);
						//printf("attach_info->recive_data: %s\n", attach_info->recive_data);
						//printf("new i = %d\n", i);
					}
					else
					{
						mail_info->num_of_attach = i;
						pstart = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"To\":\"", 8);
						if (pstart == NULL)
						{
							return;
						}
						pstart += 8;
						pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"Cc\":\"", 7);
						if (pend == NULL)
						{
							return;
						}
						memset(mail_info->to, 0, MAX_TO_LEN);
						memcpy(mail_info->to, pstart, pend-pstart);
						//printf("mail_info->to: %s\n", mail_info->to);

						pstart = pend;
						pstart += 8;
						pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"Bcc\":\"", 9);
						if (pend == NULL)
						{
							return;
						}
						memset(mail_info->cc, 0, MAX_CC_LEN);
						memcpy(mail_info->cc, pstart, pend-pstart);
						//printf("mail_info->cc: %s\n", mail_info->cc);

						pstart = pend;
						pstart += 9;
						pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"Subject\":\"", 13);
						if (pend == NULL)
						{
							return;
						}
						memset(mail_info->bcc, 0, MAX_BCC_LEN);
						memcpy(mail_info->bcc, pstart, pend-pstart);
						//printf("mail_info->bcc: %s\n", mail_info->bcc);

						pstart = pend;
						pstart += 13;
						pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"RichBody\":\"", 14);
						if (pend == NULL)
						{
							pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"PlainBody\":\"", 15);
							if (pend == NULL)
								return;
						}
						memcpy(mail_info->subject, pstart, pend - pstart);
						strcpy(mail_info->subject, clear_yh(mail_info->subject));
						//printf("mail_info->subject: %s\n", mail_info->subject);
		
						pstart = strnstr(attach_info->recive_data, attach_info->recive_length, "\"PlainBody\":\"", 13);
						if (pstart == NULL)
						{
							return;
						}
						pstart += 13;
						pend = strnstr(attach_info->recive_data, attach_info->recive_length, "\",\"RichEdit", 11);
						if (pend == NULL)
						{
							return;
						}
						mail_info->content = (char *)malloc(pend - pstart +1);
						memset(mail_info->content, 0, pend - pstart +1);
						memcpy(mail_info->content, pstart, pend-pstart);
						strcpy(mail_info->content, clear_yh(mail_info->content));
						//printf("mail_info->content: %s\n", mail_info->content);
						write_to_file(mail_info);
						attach_info->recive_data = NULL;
					}
				}
			}
		}
	}
}


void write_aol_recive_up(Mail_info *mail_info)
{
	//printf("write_aol_recive_up()\n");
	int len;
	char *ungzip = NULL;
	decomp_gzip_2(mail_info->body,mail_info->bodyLen,&ungzip);
	if(ungzip==NULL)
		return;
	free(mail_info->body);
	mail_info->body = ungzip;
	//printf("mail_info->body: %s\n", mail_info->body);
	char *p2 = NULL;
	char *p1 = NULL;

	p1 = ungzip;
	p1=strstr(p1,"baseSubject\":\"");
	if(p1==NULL)
		return;
	p1+=14;
	p2=strstr(p1,"\",\"attachments");
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) 
		len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	clear_tag(mail_info->subject);
	//printf("mail_info->subject: %s\n", mail_info->subject);

	p1=strstr(p1,"displayTo\":\"");
	if(p1==NULL)
		return;
	p1+=12;
	p2=strstr(p1,"\",\"sentTime");
	len=p2-p1;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	clear_tag(mail_info->to);
	down_contents(mail_info->to);
	char *to = NULL;
	to = conv_to_xml_symbol(mail_info->to);
	strcpy(mail_info->to,to);
	free(to);
	to = clear_b(mail_info->to, sizeof(mail_info->to));
	strcpy(mail_info->to, to);
	free(to);
	to = NULL;
	//printf("mail_info->to: %s\n",mail_info->to);

	char sendtime[100];
        memset(sendtime,0,100);
	p1=strstr(p1,"sentTime\":\"");
	p1+=11;
	p2=strstr(p1," +0000\",");
	len=p2-p1;
	strncpy(sendtime,p1,len);
	sendtime[len]=0;
	get_send_time(sendtime,mail_info->sent_time);

	p1 = ungzip;
	p1=strstr(p1,"uid\":\"");
	if(p1==NULL)
		return;
	p1+=6;
	p2=strstr(p1,"\",\"hasAttachments");
	if(p2==NULL)
		return;
	len=p2 - p1;
	if (len < 0 || len > MAX_ID_LEN)
		return;
	memcpy(mail_info->mail_id, p1, len);
	mail_info->mail_id[len] = 0;
	//printf("mail_info->mail_id: %s\n", mail_info->mail_id);

	p1=ungzip;
	p1=strstr(p1,"displayFrom\":\"");
	if(p1==NULL)
		return;
	p1+=14;
	p2=strstr(p1,"\",\"subject");
	len=p2-p1;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_tag(mail_info->from);
	down_contents(mail_info->from);
	char patternfrom[]="<(.*)>";
	regcompile_1(mail_info->from, patternfrom, mail_info->from,100);
	//printf("mail_info->from: %s\n", mail_info->from);

	p1=strstr(p1,"body\":\"");
	if(p1==NULL)
		return;
	p1+=7;
	p2=strstr(p1,"\",\"inputFrom");
	len=p2-p1;
	mail_info->content=(char *)malloc(len+1);
	strncpy(mail_info->content,p1,len);
	mail_info->content[len]=0;

	char *tmp_p1 = NULL;
	tmp_p1 = clear_html_tag(mail_info->content);
	free(mail_info->content);
	mail_info->content = tmp_p1;
	tmp_p1 = NULL;
	
	clear_tag(mail_info->content);
	down_contents(mail_info->content);

	tmp_p1 = clear_html_symbol(mail_info->content);
	free(mail_info->content);
	mail_info->content = tmp_p1;
	tmp_p1 = NULL;
	//printf("mail_info->content: %s\n", mail_info->content);
	
	p1 = strstr(p1, "displayCc\":\"");
	if (p1 == NULL)
		return;
	p1 += 12;
	p2 = strstr(p1, "\",\"folder\"");
	if (p2 == NULL)
		return;
	memset(mail_info->cc, 0, sizeof(mail_info->cc));
	memcpy(mail_info->cc, p1, p2-p1);

	tmp_p1 = clear_b(mail_info->cc, sizeof(mail_info->cc));
	strcpy(mail_info->cc, tmp_p1);
	free(tmp_p1);
	tmp_p1 = NULL;
	//printf("mail_info->cc: %s\n", mail_info->cc);
	memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"aol",mail_info->from);
	//printf("mail_info->save_path: %s\n", mail_info->save_path);
	write_to_file(mail_info);
}


void write_aol_recive_up2(Mail_info *mail_info)
{
	//printf("write_aol_recive_up()\n");
	int len;
	char *ungzip = NULL;
	ungzip = mail_info->body;
	char *p2;
	char *p1=strstr(ungzip,"displayCc\":\"");
	if (p1 == NULL)
	{
		return;
	}
	//printf("p1: %s\n", p1);
	p1+=12;
	p2=strstr(p1,"\",\"folder");
	if (p2 == NULL)
	{
		return;
	}
	//printf("p2: %s\n", p2);
	len = p2 - p1;
	if(len>0)
	{
		strncpy(mail_info->cc,p1,len);
		mail_info->cc[len]=0;
		clear_tag(mail_info->cc);
		down_contents(mail_info->cc);
	}

	char *tmp_p1 = NULL;
	tmp_p1 = clear_b(mail_info->cc, sizeof(mail_info->cc));
	strcpy(mail_info->cc, tmp_p1);
	free(tmp_p1);
	tmp_p1 = NULL;
	//printf("mail_info->cc: %s\n", mail_info->cc);

	p1 = ungzip;
	p1=strstr(p1,"baseSubject\":\"");
	if(p1==NULL)
		return;
	p1+=14;
	p2=strstr(p1,"\",\"attachments");
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) 
		len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	clear_tag(mail_info->subject);
	//printf("mail_info->subject: %s\n", mail_info->subject);

	p1=strstr(p1,"displayTo\":\"");
	if(p1==NULL)
		return;
	p1+=12;
	p2=strstr(p1,"\",\"sentTime");
	len=p2-p1;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	clear_tag(mail_info->to);
	down_contents(mail_info->to);
	char *to = NULL;
	to = conv_to_xml_symbol(mail_info->to);
	strcpy(mail_info->to, to);
	free(to);
	to = clear_b(mail_info->to, sizeof(mail_info->to));
	strcpy(mail_info->to, to);
	free(to);
	to = NULL;
	//printf("mail_info->to: %s\n",mail_info->to);

	char sendtime[100];
        memset(sendtime,0,100);
	p1=strstr(p1,"sentTime\":\"");
	p1+=11;
	p2=strstr(p1," +0000\",");
	len=p2-p1;
	strncpy(sendtime,p1,len);
	sendtime[len]=0;
	get_send_time(sendtime,mail_info->sent_time);

	p1 = ungzip;
	p1=strstr(p1,"displayBcc\":\"");
	p1+=13;
	p2=strstr(p1,"\",\"receivedTime");
	len = p2-p1;
	if(len>0)
	{
		strncpy(mail_info->bcc,p1,len);
		mail_info->bcc[len]=0;
		clear_tag(mail_info->bcc);
		down_contents(mail_info->bcc);
	}

	p1=strstr(p1,"uid\":\"");
	if(p1==NULL)
		return;
	p1+=6;
	p2=strstr(p1,"\",\"hasAttachments");
	if(p2==NULL)
		return;
	len=p2 - p1;
	if (len < 0 || len > MAX_ID_LEN)
		return;
	memcpy(mail_info->mail_id, p1, len);
	mail_info->mail_id[len] = 0;
	//printf("mail_info->mail_id: %s\n", mail_info->mail_id);

	if(p1==NULL)
		p1=ungzip;
	p1=strstr(p1,"displayFrom\":\"");
	if(p1==NULL)
		return;
	p1+=14;
	p2=strstr(p1,"\",\"subject");
	len=p2-p1;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_tag(mail_info->from);
	down_contents(mail_info->from);
	char patternfrom[]="<(.*)>";
	regcompile_1(mail_info->from, patternfrom, mail_info->from,100);
	//printf("mail_info->from: %s\n", mail_info->from);

	p1=strstr(p1,"body\":\"");
	if(p1==NULL)
		return;
	p1+=7;
	p2=strstr(p1,"\",\"inputFrom");
	len=p2-p1;
	mail_info->content=(char *)malloc(len+1);
	strncpy(mail_info->content,p1,len);
	mail_info->content[len]=0;

	tmp_p1 = clear_html_tag(mail_info->content);
	free(mail_info->content);
	mail_info->content = tmp_p1;
	tmp_p1 = NULL;

	clear_tag(mail_info->content);
	down_contents(mail_info->content);

	tmp_p1 = clear_html_symbol(mail_info->content);
	free(mail_info->content);
	mail_info->content = tmp_p1;
	tmp_p1 = NULL;

	memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"aol",mail_info->from);
	//printf("mail_info->save_path: %s\n", mail_info->save_path);
	write_to_file(mail_info);
}

int analyse_aol_recive(PacketInfo *packetInfo, Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int len;
	int range;
	char *p=NULL;
	if(is_b_s)
	{
	    if(strstr(data, "/aol-6/en-us/common/rpc/RPC.aspx?") && strstr(data, "&transport=xmlhttp&") && strstr(data, "&a=GetMessage&"))
	    {
			data_length = 0;
            mail_info->is_writing = 0;
		}
	}
	else
    {
		int resultt = http_recive_mail(mail_info, data, datalen);
		//printf("mail_info->header: %s\n", mail_info->header);
		if(resultt == 1)
		{
			if (strstr(mail_info->header, "Content-Encoding: gzip"))
			{
				write_aol_recive_up(mail_info);
			}
			else
			{
				write_aol_recive_up2(mail_info);
			}
			//del_mail_node(mail_info);
			return -1;
		}
        else if (resultt < 0)
            return -1;
    }
	
	return 0;
}
int analyse_aol_attach_recive(PacketInfo *packetInfo, Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	
	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN+1];
		int result;

		if (strstr(data, "/aol-6/en-us/mail/get-attachment.aspx?") && strstr(data, "&folder=Inbox&"))
		{
			char *p1, *p2;
			int len_id;
			attachdata_length = 0;
			p1=strstr(data,"?uid=");
			if(p1==NULL)
				return -1;
			p1+=5;
			p2=strstr(p1,"&folder=");
			if(p2==NULL)
				return -1;
			len_id=p2 - p1;
			if (len_id < 0 || len_id > MAX_ID_LEN)
				return -1;
			memset(mail_info->mail_id, 0, sizeof(mail_info->mail_id));
			memcpy(mail_info->mail_id, p1, len_id);
			mail_info->mail_id[len_id] = 0;
			//printf("attach: mail_info->mail_id: %s\n", mail_info->mail_id);
			mail_info->is_writing = 0;
			mail_info->mail_length = 0;
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			if (strstr(data, "Content-Length:"))
			{
				mail_info->recive_length=get_http_length(data);
				if(mail_info->recive_length<=0)
					return -1;
				mail_info->recive_length += 1000;
				//printf(" if mail_info->recive_length: %d\n", mail_info->recive_length);
			}
			char *p1 = strstr(data,"HTTP/1.1 200 OK");
			char *p2 = strstr(data,"\r\n\r\n");
			if(p2!=NULL)
			{
				p2+=4;
				mail_info->mail_length=p2-p1;
				//printf("mail_info->mail_length: %d\n", mail_info->mail_length);
				mail_info->mail_data=(char *)malloc(mail_info->mail_length);
				memcpy(mail_info->mail_data,p1,mail_info->mail_length);
				if (mail_info->recive_length <1000)
					return -1;
				mail_info->recive_data = (char *)malloc(mail_info->recive_length);
				if(mail_info->recive_data == NULL)
					return -1;
				memset(mail_info->recive_data,0,mail_info->recive_length);
				mail_info->http_seq = seq;
				mail_info->is_writing = 1;
			}
			else
			{
				//printf("datalen: %d\n", datalen);
				mail_info->mail_data=(char *)malloc(datalen-(p1-data));
				memcpy(mail_info->mail_data,p1,datalen-(p1-data));
				mail_info->mail_length=datalen-(p1-data);
				attachdata_length += datalen-(p1-data);
			}
		}
		else if(strncmp(data,"HTTP/1.1 200 OK\r\n",15) && mail_info->recive_data ==NULL)
		{
			if (strstr(data, "Content-Length:"))
			{
				mail_info->recive_length=get_http_length(data);
				if(mail_info->recive_length<=0)
					return -1;
				mail_info->recive_length += 1000;
				//printf(" else if mail_info->recive_length: %d\n", mail_info->recive_length);
			}
			char *p2 = strstr(data,"\r\n\r\n");
			if(p2!=NULL)
			{
				p2+=4;
				int len = p2-data;
				mail_info->mail_data=(char *)realloc(mail_info->mail_data,mail_info->mail_length+len);
				memcpy(mail_info->mail_data+mail_info->mail_length,data,len);
				mail_info->mail_length += len;
				if (mail_info->recive_length <1000)
					return -1;
				mail_info->recive_data = (char *)malloc(mail_info->recive_length);
				if(mail_info->recive_data == NULL)
					return -1;
				memset(mail_info->recive_data,0,mail_info->recive_length);
				mail_info->http_seq = seq;
				mail_info->is_writing = 1;
			}
			else
			{
				mail_info->mail_data=(char *)realloc(mail_info->mail_data,mail_info->mail_length+datalen);
				memcpy(mail_info->mail_data+mail_info->mail_length,data,datalen);
				attachdata_length += datalen;
				mail_info->mail_length += datalen;
			}
		}
		
		if (mail_info->recive_data !=NULL)
		{
			off_seq = seq - mail_info->http_seq;
			if(off_seq < 0)
				return -1;
			range = off_seq + datalen;
			if (range >= mail_info->recive_length)
				return -1;
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			attachdata_length += datalen;
			//printf("attachdata_length: %d\n", attachdata_length);
			//printf("mail_info->recive_length: %d\n", mail_info->recive_length);
			//printf("mail_info->mail_length: %d\n", mail_info->mail_length);
		}
		
		if (((attachdata_length-mail_info->mail_length == mail_info->recive_length-1000)) && mail_info->is_writing)
		{
			//printf("values equre!\n");
			//printf("recive end\n");
			mail_info->is_complished = 1;
			attach_len=get_http_length_2(mail_info->mail_data,&n);
			if (attach_len <= 0)
				return -1;
			write_attach_down_4(mail_info,attach_len,n);
			//del_mail_node(mail_info);
			return -1;//lzb
		}
	}
	return 0;
}

void analyse_aol(PacketInfo * packetInfo, void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a,char *destMAC)
{
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned int type;
	int result = 0;

	if(!m_or_a)
	{
		mail_info=(Mail_info *)tmp;
		type=mail_info->mail_type;
		type = type & 0X00FF;

		switch(type)
		{
			case 0x11:
				result = analyse_aol_content(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x31:
			{
                result = analyse_aol_recive(packetInfo, mail_info, data, datalen, tcp, is_b_s);
				/*result=analyse_aol_recive(mail_info,data,datalen,tcp,is_b_s);*/
				break;
			}
			case 0x32:
			{
                result = analyse_aol_attach_recive(packetInfo, mail_info, data, datalen, tcp, is_b_s);
				/*result=analyse_aol_attach_recive(mail_info,data,datalen,tcp,is_b_s);*/
				break;
			}
			default:
				break;
		}

		if(result == -1)
		{
			delete_mail_info(mail_info);
		}
	}
	else
	{
		attach_info=(Attach_info *)tmp;
		type=attach_info->attach_type;
		type = type & 0x00FF;

		switch(type) 
		{
			case 0x61:
			{
                analyse_aol_attach_content(packetInfo,attach_info, data, datalen, tcp, is_b_s, destMAC);
				//	analyse_aol_attach_content(attach_info,data,datalen,tcp,is_b_s,destMAC);
				break;
			}
            
			default :
				break;
		}
	}
}
