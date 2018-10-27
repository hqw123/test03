
#include "common.h"

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
	char * buff=(char *)malloc(strlen(buf)+1);
	strcpy(buff,buf);
	buff[strlen(buf)]='\0';
	fputs(buff,fp);
	fclose(fp);
	free(buff);
	buff = NULL;
}
#endif

void get_21cn_subject(char *mail_data, char *mail_subject)
{
	char *p1 = NULL; 
	char *p2 = NULL;
	int len;
	p1 = strstr(mail_data,"subject");
	if(p1 == NULL) 
    {
        LOG_INFO("\nno subject\n");
	    return;
	}
	p1+=12;
	p2=strstr(p1,"\r\n");
    if(!p2) return;
	len=p2-p1;
    if(len>=MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
    if(len<=0) return;
	memcpy(mail_subject,p1,len);
	mail_subject[len]=0;
}

void get_21cn_from(char *data,char *from)
{
   char *p1,*p2;
   int flag;
   p1=strstr(data,"ACCOUNT=");
   if(!p1) return ;
   p1+=8;
   p2=p1;
   while(*p2!=';')
   {
	   p2++;
	   flag=p2-p1;
	   if(flag==50) return;
   }
   strncpy(from,p1,flag);
   from[flag]=0;
}

void writefile21cn(Mail_info *mail_info)
{
    char patternto[]="name=\"to\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";     
    char patterncontent[]="name=\"content\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"priority\"";
	char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
	char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subject\"";
    char patterncontent_1[]="name=\"content\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"underWrite\"";
	char patternkey[] = "name=\"fileKey\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"to\"";
	char patternkey2[] = "name=\"fileKey\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"sender\"";
//	regcompile_1(mail_info->mail_data,patternfrom,mail_info->from);
	get_21cn_from(mail_info->mail_data, mail_info->from);
	regcompile_1(mail_info->mail_data,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	memset(mail_info->mail_id,0,MAX_ID_LEN);
	regcompile_1(mail_info->mail_data,patternkey,mail_info->mail_id,MAX_ID_LEN);
    
	if(strstr(mail_info->mail_id,"----"))
		regcompile_1(mail_info->mail_data,patternkey2,mail_info->mail_id,MAX_ID_LEN);
//	regcompile_1(mail_info->mail_data,patternsubject,mail_info->subject);
	
	get_21cn_subject(mail_info->mail_data, mail_info->subject);
	///////
  /*	char *subject_tmp=NULL;
	int len;
	subject_tmp=conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	len=strlen(subject_tmp);
	if(len>MAX_SUBJ_LEN) subject_tmp[MAX_SUBJ_LEN]=0;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);
	subject_tmp = NULL;*/
	////////
	regcompile_2(mail_info->mail_data,patterncontent,&mail_info->content);
	if (mail_info->content == NULL)
		regcompile_2(mail_info->mail_data,patterncontent_1,&mail_info->content);
	if (mail_info->content != NULL) {
		char *tmp_str = NULL;
		
		tmp_str = clear_html_tag(mail_info->content);  
		free(mail_info->content);
		mail_info->content = tmp_str;
	}
	
    //char *p1=mail_info->mail_data;
	char *p1=NULL;
	char *p2=NULL;
    int  fd,atta_fd;
	struct stat st;
	char *mapped;
	char filename[MAX_FN_LEN];
	int len=0;
	//Attach_info *attach_info=NULL;
	char ID[MAX_ID_LEN]={0};
	//Attachment *attachment;
	//int flag=0;
	//int i=0;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	create_dir(mail_info->save_path,"21cn",mail_info->from);

	Attachment *attachment;
        Attach_info *attach_tmp;
        Attach_info *attach_info;
        char writepath[MAX_PATH_LEN] = {0};
        attach_info=attach_tab.head->next;
        int  i=0;
        int flag=0;
	memset(ID,0,MAX_ID_LEN);
        regcompile_1(mail_info->mail_data, patternkey, ID,MAX_ID_LEN);
	if(strstr(ID,"----"))
		regcompile_1(mail_info->mail_data,patternkey2,ID,MAX_ID_LEN);
	while(attach_info!=NULL)
        {
		if(!strncmp(attach_info->ID_str, ID, strlen(ID)))
		{
	                i++;
		        attachment = (Attachment *)malloc((sizeof(Attachment))+1);
			if (attachment == NULL)
				break;
                        //memset(attachment,0,(sizeof(Attachment))+1);
                        memset(attachment->loc_filename,0,MAX_FN_LEN+1);
			//sprintf(attachment->loc_filename,"attach%d_%s",i,attach_info->attach_name);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->attach_name);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			if(!flag)
		        {//printf("11111111\n");
				attachment->next =NULL;
				mail_info->attach = attachment;
				flag++;
			}
			else
			{//printf("22222222\n");
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
	write_to_file(mail_info);
}

int analyse_21cn_content(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	if (is_b_s)
	{
		char *p1 = NULL, *p2 = NULL;
		int f = http_recive_mail(mail_info, data, datalen);
		if (1 == f)
		{
			p1 = strstr(mail_info->body, "from=");
			if (p1)
			{
				p1 += strlen("from=");
                    
				for(p2 = p1; *p2!='&'; p2++);
                char* tmp_from = (char*)malloc(p2-p1+1);
				if (!tmp_from)
				    return -1;
					
                memset(tmp_from, 0, p2-p1+1);
                memcpy(tmp_from, p1, p2-p1);
				url_decode(tmp_from, p2-p1, mail_info->from, MAX_FROM_LEN);
                free(tmp_from);
			}

			p1 = strstr(mail_info->body, "to=");
			if (p1)
			{
				p1 += strlen("to=");
				
				for(p2 = p1; *p2!='&'; p2++);
				char* tmp_to = (char*)malloc(p2-p1+1);
				if (!tmp_to)
				    return -1;
					
                memset(tmp_to, 0, p2-p1+1);
                memcpy(tmp_to, p1, p2-p1);
				url_decode(tmp_to, p2-p1, mail_info->to, MAX_TO_LEN);
                free(tmp_to);
			}

			p1 = strstr(mail_info->body, "cc=");
			if(p1)
			{
				p1 += strlen("cc=");
				
				for(p2 = p1; *p2!='&'; p2++);
				char* tmp_cc = (char*)malloc(p2-p1+1);
				if (!tmp_cc)
				    return -1;
					
                memset(tmp_cc, 0, p2-p1+1);
                memcpy(tmp_cc, p1, p2-p1);
				url_decode(tmp_cc, p2-p1, mail_info->cc, MAX_CC_LEN);
                free(tmp_cc);
			}

			p1 = strstr(mail_info->body, "subject=");
			if (p1)
			{
				p1 += strlen("subject=");
				
				for(p2 = p1; *p2!='&'; p2++);
                char* tmp_subject = (char*)malloc(p2-p1+1);
				if (!tmp_subject)
				    return -1;
					
                memset(tmp_subject, 0, p2-p1+1);
				memcpy(tmp_subject, p1, p2-p1);
                url_decode(tmp_subject, p2-p1, mail_info->subject, MAX_SUBJ_LEN);
                free(tmp_subject);
			}

			p1 = strstr(mail_info->body, "content=");
			if (p1)
			{
				p1 += strlen("content=");

				for(p2 = p1; *p2!='&'; p2++);
				char* tmp = (char*)malloc(p2-p1+1);
                if (!tmp)
                    return -1;
					
				memset(tmp, 0, p2-p1+1);
				memcpy(tmp, p1, p2-p1);
				
				mail_info->content = (char*)malloc((p2-p1)*2);
                if(!mail_info->content)
                    return -1;
                
                memset(mail_info->content, 0, (p2-p1)*2);
                url_decode(tmp, p2-p1, mail_info->content, (p2-p1)*2);
                free(tmp);

                tmp = conv_to_xml_symbol(mail_info->content);
        		
        		free(mail_info->content);
        		mail_info->content = clear_html_tag(tmp);
        		free(tmp);
                
				create_dir(mail_info->save_path, "21cn", mail_info->from);
				write_to_file(mail_info);
			}
			
			return -1;
		}
        else if (f < 0)
            return -1;
	}

	return 0;
}

void write_21cn_psword(Mail_info *mail_info)
{
	char *p1,*p2;
	char *tmp = NULL, *tmp1 = NULL;
//	char mail_info->username[MAX_UN_LEN],mail_info->passwd[MAX_PW_LEN];
	int  len;
	int  range;

	p1 = mail_info->mail_data;//printf("\n%s\n",mail_info->mail_data);
	p1 = strstr(p1,"&UserName=");
	if(!p1)
		return ;
	p1+=10;

	p2=strstr(p1,"&");
	if(!p2)
		return ;
	range = p2-p1;
	if(range>=MAX_UN_LEN && range <=0) return;
    strncpy(mail_info->username,p1,range);
	mail_info->username[range]=0;
	tmp = mail_info->username;

	while (*tmp != '\0') {   //firefox
		if (*tmp == '%' && *(tmp + 1) == '4' && *(tmp + 2) == 0) {
			tmp1 = tmp + 3;
			*tmp = '@';
			tmp++;
			while (*tmp1 != '\0') {
				*tmp = *tmp1;
				tmp++;
				tmp1++;
			}
			*tmp1 = '\0';
			break;
		}
		tmp++;
	}

	len = strlen(mail_info->username);
	while(len&&mail_info->username[len]!='@')
	{
		len--;
	}
	if(!len){
	strcat(mail_info->username, "@21cn.com");
	}
	p1=strstr(p1,"&passwd=");
	if(!p1) return;
	p1+=8;
	p2=strstr(p1,"&");
	if(!p2) return;
    range=p2-p1;
	if(range>=MAX_PW_LEN && range <=0) return;
    strncpy(mail_info->passwd,p1,range);
	mail_info->passwd[range]=0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);
	
	write_xml(mail_info);

	FILE *fp;
	char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	//chdir(mail_data_path);
	fp=fopen(passpath,"a+");
	if(fp==NULL) return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}

int analyse_21cn_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
    char *p1 = NULL, *p2 = NULL;
    char tmp_name[MAX_UN_LEN + 1] = {0};
    char tmp_password[MAX_UN_LEN + 1] = {0};
    size_t len = 0;

    if (is_b_s && (1 == http_recive_mail(mail_info, data, datalen))) 
    {
        p1 = strstr(data, "userName=");
        if (p1 == NULL) 
        {
            return -1;
        }
        p1 += strlen("userName=");
        p2 = strchr(p1, '&');
        len = p2 - p1;
        if (p2 == NULL || len > MAX_UN_LEN) 
        {
    		return -1;
        }
        memcpy(tmp_name, p1, len);
        tmp_name[len] = 0;
        htmldecode_full(tmp_name, mail_info->username);
        len = strlen(mail_info->username);
        while(len&&mail_info->username[len]!='@')
        {
            len--;
        }
        if(!len)
        {
            strcat(mail_info->username, "@21cn.com");
        }
        p1 = strstr(p2, "password=");
        if (p1 == NULL)
            return -1;
        p1 += strlen("password=");
        p2 = strchr(p1, '&');
        if (p2 == NULL)
        {
            return -1;
    	}

        len = p2 - p1;
        memcpy(tmp_password, p1, len > MAX_UN_LEN ? MAX_UN_LEN : len);
       	url_decode(tmp_password, len, mail_info->passwd, MAX_PW_LEN);
    	
        store_account_db(mail_info);
        return -1;
    } 

    return 0;
}

void write_21cn_recive(Mail_info *mail_info)
{
	char *p1=NULL,*p2=NULL,*p3=NULL,*p4=NULL;
	int len;
	
	//printf("mail_info->recive_data = %s\n", mail_info->recive_data);

	p1=strstr(mail_info->recive_data,"<div class=\"XinTitle\"");
	if (p1==NULL) 
		return;
	p1=strstr(p1,";\">");
	if (p1==NULL) 
		return;
	p1+=3;
	p2=strstr(p1,"</div>");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) 
		len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	//printf("\nmail_info->subject : %s\n", mail_info->subject);

        p1=strstr(p2,"formAddrTem = \'");
        if(p1 != NULL) 
		{
        	p1+=15;
        	p2=strstr(p1,"\';\r\n");
        	if(p2==NULL) 
				return;
        	len=p2-p1;
        	if(len>MAX_FROM_LEN) 
				len=MAX_FROM_LEN;
        	strncpy(mail_info->from,p1,len);
        	mail_info->from[len]=0;

			//printf("mail_info->from : %s\n", mail_info->from);
		}

        p1=strstr(p2,"toAddrTem = \'");
        if(p1!=NULL) 
		{
        	p1+=13;
        	p2=strstr(p1,"\';\r\n");
        	if(p2==NULL) 
				return;
        	len=p2-p1;
        	if(len>MAX_TO_LEN) 
				len=MAX_TO_LEN;
        	strncpy(mail_info->to,p1,len);
        	mail_info->to[len]=0;
			
			//printf("mail_info->to : %s\n", mail_info->to);
		}

        p1=strstr(p2,"ccAddrTem = \'");
        if(p1!=NULL) 
		{
        	p1+=13;
        	p2=strstr(p1,"\';\r\n");
        	if(p2==NULL) 
				return;
        	len=p2-p1;
        	if(len>MAX_CC_LEN) 
				len=MAX_CC_LEN;
        	strncpy(mail_info->cc,p1,len);
        	mail_info->cc[len]=0;

			//printf("mail_info->cc : %s\n", mail_info->cc);
		}

        p1=strstr(p2,"<li>");
        if(p1!=NULL) 
		{
        	p1+=16;
        	p2=strstr(p1,"</li>\r\n");
        	if(p2==NULL) 
				return;
        	//p1=p2-19;
        	len=p2-p1;
        	if(len>MAX_TIME_LEN) 
				len=MAX_TIME_LEN;
        	strncpy(mail_info->sent_time,p1,len);
        	mail_info->sent_time[len]=0;

			//printf("mail_info->sent_time : %s\n", mail_info->sent_time);
		}

        p1=strstr(p2,"<div id=\"mailContent\"");
        if(p1!=NULL) 
		{
			//printf("111\n");
			p1 += 21;
			p1=strstr(p1,"\"> \r\n");
			if(p1==NULL) 
					return;
				//printf("222\n");
			p1=p1+4;
			p2=strstr(p1,"</div>\r\n");
			if(p2==NULL) 
					return;
				//printf("333\n");
			len=p2-p1;
			mail_info->mail_data=(char*)malloc(len+1);
			if(mail_info->mail_data!=NULL)
			{
				memset(mail_info->mail_data,0,len+1);
				memcpy(mail_info->mail_data,p1,len);
				mail_info->content=clear_html_tag(mail_info->mail_data);
			}
		}
        create_dir(mail_info->save_path,"21cn",mail_info->from);
        write_to_file(mail_info);
}

int analyse_21cn_recive(Mail_info *mail_info, char *data,unsigned int datalen,struct tcphdr *tcp, int is_b_s)
{  //need to changed for another form
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int len;
	int result;
	char *p=NULL;
	static int flag = -1;
	static int flagg = -1;
	char *dest = NULL;
	
	//printf("%s\n", data);
	
	if(is_b_s)
	{
	   	if(!strncmp(data, "GET /webmail/readMail.do?",25))
	   	{
	     		char *p1, *p2;
	     		int len_id;
	     		if (data == NULL) 
					return -1;
				p1 = strstr(data, "messageid=");
	     		if(p1 == NULL) 
					return -1;
	     		p1 += 10;
	     		p2 = strstr(p1,"HTTP/1.");
	     		if (p2 == NULL) 
					return -1;
	     		p2 -= 3;
	     		if (*p2 !='@')
				{
					p2 -= 1;
					if (*p2 !='@')
						return -1;
				}
	     		len_id = p2 - p1;
				len_id = (len_id > MAX_ID_LEN ? MAX_ID_LEN : len_id);
	     		memcpy(mail_info->mail_id, p1, len_id);
	     		mail_info->mail_id[len_id] = '\0';
				//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
	   	}
	}
	else
	{
		if(!strncmp(data,"HTTP/1.",7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{
			if(strstr(data, "Content-Encoding: gzip\r\n"))
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
				result = write_to_okdata(mail_info, data, datalen, tcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				//printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, datalen, tcp);
				mail_info->is_ok_chunked = 1;
			}
			if (result == -1)
			{
				//printf("write_to_okdata ... Error!\n");
				return -1;
			}
		}
		if(!memcmp(data + datalen - 5, "0\r\n\r\n", 5) || strstr(data + datalen - 20, "</html>"))
		{
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					//printf("22222\n");
					Chunked(mail_info);//printf("\nmail_info->recive_length2222 = %d, mail_info->recive_data2222 = %s\n",mail_info->recive_length,mail_info->recive_data);
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
					LOG_WARN("webmail:analyse_21cn_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
                
				free(mail_info->recive_data);
				mail_info->recive_data = dest;
				dest = NULL;
			}

			write_21cn_recive(mail_info);
			del_mail_node(mail_info);
		}
	}

	return 0;
}

int WriteAttachFile21cn(Mail_info *mail_info) 
{
   //according to the http information head, this function added
   get_21cn_from(mail_info->mail_data,mail_info->from);
   char *p1=mail_info->mail_data;
   char *p2;
   int fd;
   
   char filename[MAX_FN_LEN]="0";
   int len=0;
   mode_t file_mode=S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
   create_dir(mail_info->save_path,"21cn",mail_info->from);
   
   p1=strstr(p1,"filename=\"");
   if (p1==NULL) return (-1);
   p1+=10;
   p2=strstr(p1,"\"\r\n");
   if (p2==NULL) return (-1);
   len=p2-p1;
   if (len>MAX_PATH_LEN) return (-1);
   #if 0
   int i;
   for(i=0; i<len;i++)
       filename[i]=*(p1+i);
   filename[len]=0;
   #endif
   strncpy(filename,p1,len);
   char str[MAX_PATH_LEN];
   sprintf(str,"%s/attach_%s",mail_info->save_path,filename);
   fd=open(str,O_RDWR|O_CREAT,file_mode);
   p2+=3;
   p1=strstr(p2,"\r\n\r\n");
   if (p1==NULL) return (-1);
   p1+=4;
   
   unsigned int n=mail_info->mail_length-(p1-mail_info->mail_data);
   p2=memfind(p1,"Content-Disposition",n);
   #if 0
   p2=strstr(p1,"Content-Disposition");//not accurate
   if (p2==NULL)
   {
      return;
   }
   #endif
   write(fd,p1,p2-p1);
   close(fd);
   trim_attach(str,45);//use???
     
}

int analyse_21cn_attach_head(Attach_info *attach_info, char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	struct timeval tv;
	struct timezone tz;
	char *p1=NULL;
	char *p2=NULL;
	int off_seq;
	int result;
	int range;
	
		
	off_seq = seq - attach_info->start_seq;
	if(off_seq < 0) return -1;
	range = off_seq + datalen;
	if(range > attach_info->ok_len)
	{
		del_attach_node(attach_info);
		delete_attach(attach_info);
		return -1;
	}
	
	memcpy(attach_info->ok_data + off_seq, data, datalen);
	
	p1 = strstr(attach_info->ok_data,"name=\"Filename\"\r\n\r\n");
	if(p1 == NULL) return 0;
	p1 += 19;
	p2 = strstr(p1,"\r\n----");
	if(p2 == NULL) return 0;
	int len=0;
	len = p2 - p1;
	if (len>MAX_PATH_LEN) len=MAX_PATH_LEN;
	memcpy(attach_info->attach_name,p1,len);
	attach_info->attach_name[len]=0;
	p1 = strstr(p2,"name=\"key\"");
	if(p1 == NULL) return 0;
	p1+=14;
	p2 = strstr(p1,"\r\n----");
	if (p2 == NULL) return 0;
	len = p2 - p1;
	if (len > MAX_ID_LEN) len = MAX_ID_LEN;
	strncpy(attach_info->ID_str,p1,len);
	LOG_INFO("attach_info->ID_str = %s\n", attach_info->ID_str);
	p1 = strstr(p2,"; filename=\"");
	if (p1 == NULL) return 0;
	p1 = strstr(p1,"\r\n\r\n");
	if (p1 == NULL) return 0;
	p1 += 4;
	attach_info->start_seq = p1 - attach_info->ok_data + attach_info->start_seq;
	gettimeofday(&tv,&tz);
	sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	fd = open(attach_info->path_of_here,O_RDWR | O_CREAT, file_mode);
	write(fd,p1,off_seq + datalen - (p1-attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1;
	return 0;
		 
}

int analyse_21cn_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned  int seq=ntohl(ptcp->seq);
	int result=0;
    int off_seq;
    int data_seq;
    int flag = 0;
    char *p;
	if(is_to_s)
	{ 	
		if (!strncmp(data, "POST /webmail/upload.do", 23))
		{ 
			char *p1;
			p1 = NULL;
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
			//mail_info->attach_len = mail_info->recive_length;
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
			if(ptcp->fin)
			{
				attach_info->is_get_ok=1;
				
				attach_info->is_complished =1;
                                char *p1=strstr(attach_info->recive_data,"Filename\"\r\n\r\n");
				if(p1 == NULL)
				{
					return -1;
				}
				p1+=13;
				char *p2=strstr(p1,"\r\n");
				if(p2 == NULL)
				{
					return -1;
				}
				
				strncpy(attach_info->attach_name, p1, p2-p1);//the name of attach file
	            attach_info->attach_name[p2-p1] = 0;
				p1 = strstr(p1, "key\"\r\n\r\n");
				p1 += 8;
				p2 = strstr(p1, "\r\n");
				strncpy(attach_info->ID_str, p1, p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1] = 0;

                p1=strstr(p1,"application/octet-stream\r\n\r\n");
                p1+=28;
                p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
                if(p2 == NULL)
                {
                    return -1;
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
					return -1; 
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
				char* p1 = strstr(attach_info->recive_data,"name=\"Filename\"\r\n\r\n");
				if(p1 == NULL)
				{
					return -1;
				}
				p1 += 19;
				char* p2 = strstr(p1,"\r\n----");
				if(p2 == NULL) 
				{
					return -1;
				}
				int len=0;
				len = p2 - p1;
				if (len>MAX_PATH_LEN) len=MAX_PATH_LEN;
				memcpy(attach_info->attach_name,p1,len);
				attach_info->attach_name[len]=0;
				p1 = strstr(p2,"name=\"key\"");
				if(p1 == NULL)
				{
					return -1;
				}
				p1+=14;
				p2 = strstr(p1,"\r\n----");
				if (p2 == NULL)
				{
					return -1;
				}
				len = p2 - p1;
				if (len > MAX_ID_LEN) len = MAX_ID_LEN;
				strncpy(attach_info->ID_str,p1,len);
		
				p1=strstr(p1,"application/octet-stream\r\n\r\n");
				if(p1 == NULL)
				{
					return -1;
				}
				p1+=28;  
                p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
                if(p2 == NULL)
                {
                	return -1;
                }
				struct timeval tv;//creat temp attach file
				struct timezone tz;
				gettimeofday(&tv,&tz);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); //3
				mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
				int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
				if (fd ==-1)
				{
					LOG_ERROR("open\n");
					return -1; 
				}
                write(fd,p1,p2-p1);
				close(fd);
				attach_info->is_complished=1;
			}
		}
	}	
	return 0;
}
/*{
	printf("analyse_21cn_attach\n");
	unsigned int seq = ntohl(ptcp->seq);
	int result;
	if (is_to_s)
	{
		if (attach_info->is_writing)
		{
			int off_seq = seq - attach_info->start_seq;
			if (off_seq < 0)
			{
				data_len += off_seq;
				if (data_len < 1)
					return;
				data -= off_seq;
				off_seq = 0;
			}
			int fd = open(attach_info->path_of_here, O_RDWR);
			lseek(fd, off_seq, SEEK_SET);
			write(fd,data,data_len);
			close(fd);
		}
		else
		{
			analyse_21cn_attach_head(attach_info,data,data_len,seq);
		}
	}
	else
	{
		if(!attach_info->is_get_ok)
		{
			char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";
			
			if(!strncmp(data,http_ok_head,17))
			{
				trim_attach(attach_info->path_of_here,46);
			    attach_info->ok_data = NULL;
				attach_info->is_complished = 1;
			}
		}
			
	}
}*/
#if 0
int analyse_21cn_attach(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//this function is used to analyse the attachfile of the mail
  //not test
   unsigned int seq=ntohl(tcp->seq);
   int off_seq=seq-mail_info->start_seq;
   int range;
   char http_ok_head[18]="HTTP/1.1 200 OK\r\n";
   
   if (is_b_s)
   {
     if (!mail_info->is_complished)
        {
          if (mail_info->mail_length==0)
             {
               mail_info->mail_length=5000;
               mail_info->mail_data=(char *)malloc(5000);
               if (mail_info->mail_data==NULL)
                  {
                      return -1;
                   }
                memset(mail_info->mail_data,0,5000);//clean memory
                mail_info->start_seq=seq;
             }
           if (mail_info->mail_length==5000)
              {
                int len;
                char *tmp;
                len=get_http_length(data);
                if (len>0)
                   {
                     mail_info->mail_length+=len;
                     tmp=(char *)malloc(mail_info->mail_length);
                     if (tmp==NULL)
                      {
                        return -1;
                      }
                      memset(tmp,0,mail_info->mail_length);
                      memcpy(tmp,mail_info->mail_data,5000);
                      free(mail_info->mail_data);
                      mail_info->mail_data=tmp;
                   }
               }
             off_seq=seq-mail_info->start_seq;
      range=off_seq+datalen;
            if (range>mail_info->mail_length)
             {
              return -1;
              }
          memcpy(mail_info->mail_data+off_seq,data,datalen);
         }
   }
   else if (!strncmp(data,http_ok_head,15))
        {
            mail_info->is_complished=1;
            get_time(data,mail_info->sent_time);
            WriteAttachFile21cn(mail_info);
            del_mail_node(mail_info);
         }

}
#endif

int analyse_21cn_attach_recive(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
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
     
		if (!strncmp(data,"GET /webmail/getAttachment.do?",30))
		{
			char *p1, *p2;
			int len;
			p1=data;
			if (p1==NULL) return -1;
			p1=strstr(p1,"messageid=");
			if(p1==NULL) return -1;
			p1 +=10;
			p2 = strstr(p1,"&msid=");
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
			range = off_seq + datalen;
			if (range>mail_info->recive_length)
			{
				mail_info->recive_data = (char *)realloc(mail_info->recive_data,range+1);
				if(mail_info->recive_data == NULL)
					return 0;
				mail_info->recive_length=range;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
		}
		if (tcp->fin == 1 || (datalen>0&&!memcmp(mail_info->recive_data+range-7,"\r\n0\r\n\r\n",7)))
		{
			mail_info->is_complished = 1;
			attach_len = mail_info->recive_length - 1000;
			write_attach_down_2(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}

	return 0;
}

int analyse_21cn_down_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	static  int dataLen = 0;
	static int isChunked = -1;

	if (attach_info->is_writing == 1)
	{
		attach_info->ok_len += data_len;
		if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
		{
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
			//memcpy(attach_info->recive_data+(attach_info->ok_len-data_len-dataLen), data, data_len);
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
			{
				return -1;
			}
			lseek(fd, 0, SEEK_END);
			write(fd, data, data_len);
			close(fd);
		}

		/*int fd = open(attach_info->path_of_here, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
		lseek(fd, 0, SEEK_END);
		write(fd, data, data_len);
		close(fd);
		if(ptcp->fin == 1 || !memcmp(data+data_len-4,"\r\n\r\n",4))
		{//printf("\n2\n");
			//UpdateAttach(attach_info->attach_name, attach_info->ID_str);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}*/
	}
	else
	{
		if(!strncmp(data, "HTTP/1.0 200 OK\r\n", 17) || !strncmp(data, "HTTP/1.1 200 OK\r\n", 17))
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
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
			char temp_name[MAX_PATH_LEN];
			memset(temp_name, MAX_PATH_LEN, 0);
			strcpy(temp_name, attach_info->attach_name);
			temp_name[len] = '\0';
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);

			//printf("attach_info->path_of_here : %s\n", attach_info->path_of_here);

			front = strstr(data, "Date:");
			if(front == NULL)
			{
				return -1;
			}
			front += 5;
			front = strstr(front, "\r\n\r\n");
			if(front == NULL)
			{
				return -1;
			}
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
				}
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

			attach_info->is_writing = 1;
		}
		else
		{
			int len;
			char *front, *back;
			front = strstr(data, "GET /webmail/getAttachment.do?messageid=");
			if(front == NULL)
				return 0;
			front += 40;
			back = strstr(front, "&msid=");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(attach_info->ID_str, front, len);
			attach_info->ID_str[len] = '\0';
			//printf("attach_info->ID_str : %s\n", attach_info->ID_str);
			//htmldecode_full(attach_info->ID_str, attach_info->ID_str);

			//printf("attach_info->ID_str : %s\n", attach_info->ID_str);
		}
	}
	
	return 1;
}

int analyse_21cn_recive_mail(Mail_info *mail_info, char *data, int data_len, int is_to_s)
{
    if (!is_to_s)
    {
        char *p1 = NULL, *p2 = NULL, *p3 = NULL;
        int f = http_recive_mail(mail_info, data, data_len);
        if(f == 1)
        {
            char *p_content = NULL, *p_title = NULL , *p_dest = NULL;
            char *body = NULL;
            int gzip_flag = 0;
            if (strstr(mail_info->header, "Content-Encoding: gzip"))
            {
                gzip_flag = 1;
                int result = decomp_gzip(mail_info->body, mail_info->bodyLen-2, &p_dest);
                if (result == -1 || p_dest == NULL)
                {
                    return -1;
                }
            }
            
            if (1 == gzip_flag)
            {
                body = p_dest;
            }
            else
            {
                body = mail_info->body;
            }
            
            if (body)
            {
                p_content = strstr(body, "id=\"mail-content\"");
                p_title = strstr(body, "\"subject\":");
            }
            
            if (p_title)
            {
                if ((p1 = strstr(body, "to\":[")) != NULL)
                {   
                    p2 = strstr(p1,"],");
                    while((p1 = strstr(p1,"\"address\":\"")) != NULL && p1 < p2)
                    {
                        p3 = strstr(p1, "\",");
                        p1 += strlen("\"address\":\"");
                        strncat(mail_info->to, p1, p3-p1);
                        strcat(mail_info->to,";");
                    }
                    clear_html_tag_2(mail_info->to);
                }
                
                if ((p1 = strstr(body, "cc\":[")) != NULL)
                {   
                    p2 = strstr(p1,"],");
                    while((p1 = strstr(p1,"\"address\":\"")) != NULL && p1 < p2)
                    {
                        p3 = strstr(p1, "\",");
                        p1 += strlen("\"address\":\"");
                        strncat(mail_info->cc, p1, p3-p1);
                        strcat(mail_info->cc,";");
                    }
                    clear_html_tag_2(mail_info->cc);
                }
        
                if ((p1 = strstr(body, "bcc\":[{\"address\":\"")) != NULL)
                {
                    p1 += 18;
                    p2 = strstr(p1,"\"");
                    memcpy(mail_info->bcc, p1, p2-p1>MAX_CC_LEN?MAX_CC_LEN:p2-p1);
                    clear_html_tag_2(mail_info->bcc);
                }
            
                if ((p1 = strstr(body, "\"sentDate\":")) != NULL)
                {          
                    char dest1[MAX_TIME_LEN + 1] = {0};
                    time_t timeval;

                    p1 += 11;
                    p2 = strstr(p1,",");
                    memcpy(dest1, p1, 10);

                    struct tm *tm_ptr;
                    timeval = strtol(dest1, NULL, 0);
                    tm_ptr = localtime(&timeval);
                    snprintf(mail_info->sent_time, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);    
                }
        
                if ((p1 = strstr(body, "from\":[{\"address\":\"")) != NULL)
                {       
                    p1 += 19;           
                    p2 = strstr(p1,"\"");
                    memcpy(mail_info->from, p1, p2-p1>MAX_FROM_LEN?MAX_FROM_LEN:p2-p1);
                    clear_html_tag_2(mail_info->from);
                }
           
                if ((p1 = strstr(body,"\"subject\":")) != NULL)
                {       
                    p1 += 11;
                    p2 = strstr(p1,"\"");
                    memcpy(mail_info->subject, p1, p2-p1>MAX_SUBJ_LEN?MAX_SUBJ_LEN:p2-p1);
                    clear_html_tag_2(mail_info->subject);
                }
            }
            else if(p_content)
            {
                char* tmp = NULL;
                p1 = strstr(p_content, "<body>");
                if(!p1)
                return -1;
                p1 += strlen("<body>");
                p2 = strstr(p1, "</body>");
                
                tmp = (char*)malloc(p2-p1 + 1);
                if (NULL == tmp)
                return -1;
                
                memset(tmp, 0, p2-p1 + 1);
                memcpy(tmp, p1, p2-p1);
               
                mail_info->content = clear_html_tag(tmp); 
                free(tmp);
                clear_tag(mail_info->content);
                create_dir(mail_info->save_path, "21cn", mail_info->from);
                write_to_file(mail_info);
                if(1 == gzip_flag)
                {
                    free(p_dest);
                }
                    
                return -1;
            }
            else if(!p_content && strlen(mail_info->subject) > 0)
            {
                return -1;
            }
               
            free(mail_info->body);
            mail_info->body = NULL;
            mail_info->bodyLen = 0;
            free(mail_info->header);
            mail_info->header = NULL;
            mail_info->headerLen = 0;
            mail_info->status = 0;
            mail_info->bodyTotal = 0;
            if (1 == gzip_flag)
            {
                free(p_dest);
            }
        }
        else if (f < 0)
            return -1;
    }
    
    return 0;
}


void analyse_21cn(void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
{   
	Mail_info *mail_info;
	unsigned int lowtype;
	int result = 0;
	if(!mora)
	{
	/*
		mail_info = (Mail_info *)tmp;
		analyse_21cn_content(mail_info ,data ,datalen,tcp,is_b_s);
	*/
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype &0X00FF;
		switch(lowtype)
		{
			case 0x09:
				//analyse_21cn_attach(mail_info,data,datalen,tcp,is_b_s);//yu added ***
				break;
                
			case 0x11:
				result = analyse_21cn_content(mail_info, data, datalen, tcp, is_b_s); //send mail
				break;
                
			case 0x01:
				result = analyse_21cn_psword(mail_info, data, datalen, tcp, is_b_s);
				break;
                
			case 0x31:
				result = analyse_21cn_recive(mail_info, data, datalen, tcp, is_b_s);
				break;
                
			case 0x32:
			    result = analyse_21cn_attach_recive(mail_info, data, datalen, tcp, is_b_s);
			    break;

			case 0x41:
				result = analyse_21cn_recive_mail(mail_info, data, datalen, is_b_s);
				break;
                
			default:
				break;
		}

		if (result == -1) 
		{
			delete_mail_info(mail_info);
		}
	} 
	else
	{
		Attach_info *attach_info = (Attach_info *)tmp;
		lowtype = attach_info->attach_type & 0x00FF;
		switch(lowtype)
		{
			case 0x61:
				analyse_21cn_attach(attach_info, data, datalen, tcp, is_b_s);
				break;
			case 0x64:
				result = analyse_21cn_down_attach(attach_info, data, datalen, tcp, is_b_s);
				if(result == -1)
				{
					del_attach_node(attach_info);
					delete_attach(attach_info);
				}
				break;
			default:
				break;
		}
	}	
		
}
