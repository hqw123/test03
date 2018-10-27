#include "common.h"

extern int clear_tag(char *src);
void writefileeyou(Mail_info *mail_info)
{
   //char patternto[]="name=\"rcpt\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";
   //char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
   //char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subject\"";
   //char patternsubject[]="name=\"subject\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"upload\"";
   //char patterncontent[] = "name=\"mess\"\r\n\r\n(.*)\r\n..*\r\n.*name=\"text";
   //printf("%s\n", mail_info->mail_data);
   if(strstr(mail_info->mail_data,"action_type=draft.auto&content_type=html&"))
         return;
   char patternfrom[]="&from=(.*)&rec1=";
   char patternto[]="&rec1=(.*)&rec1g=&";
   char patterncc[]="&rec2=(.*)&rec2g=&";
   char patternbcc[]="&rec3=(.*)&rec3g=&";
   char patternsubject[]="&subject=(.*)&content_text=";
   char patterncontent[] = "&content_text=(.*)&priority=";
   char patternRid[] = "&rid=(.*)&iid=";
   //regcompile(filedata,patternfrom, mail_info->to);
   memset(mail_info->from,0,MAX_FROM_LEN+1);
  
  // get_from(mail_info->from, mail_info->source_ip);

   int k=regcompile_1(mail_info->mail_data, patternfrom, mail_info->from,MAX_TO_LEN);
   if(k==-1)
       return;
   convert_contents(mail_info->from);
   char pattern[]="\" <(.*)>";
   regcompile_1(mail_info->from, pattern, mail_info->from,100);
   memset(mail_info->to,0,MAX_TO_LEN+1);
   regcompile_1(mail_info->mail_data, patternto, mail_info->to,MAX_TO_LEN);
   convert_contents(mail_info->to);
   regcompile_1(mail_info->to, pattern, mail_info->to,100);
   memset(mail_info->cc,0,MAX_CC_LEN);
   //printf("\nmail_info->to =%s",mail_info->to);
   k=regcompile_1(mail_info->mail_data, patterncc, mail_info->cc,MAX_CC_LEN);
   if(k!=-1)
   {
        convert_contents(mail_info->cc);
   }
   //printf("\nmail_info->cc =%s",mail_info->cc);
   
   memset(mail_info->bcc,0,MAX_BCC_LEN);
   k=regcompile_1(mail_info->mail_data, patternbcc,mail_info->bcc,MAX_BCC_LEN);
   if(k!=-1)
   {
      convert_contents(mail_info->bcc);
   }
   //printf("\nmail_info->bcc =%s",mail_info->bcc);
   regcompile_1(mail_info->mail_data, patternsubject, mail_info->subject,MAX_SUBJ_LEN);
   if(k!=-1)
   {
	htmldecode_full(mail_info->subject, mail_info->subject);
   }
   
    //////////////
   /*char *subject_tmp=NULL;
	int len0;
	subject_tmp=conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	len0=strlen(subject_tmp);
	if(len0>MAX_SUBJ_LEN) subject_tmp[MAX_SUBJ_LEN]=0;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
   ///////////////////
    //printf("%s\n", mail_info->mail_data);
   
        char *p1=mail_info->mail_data;
        char *p2=NULL;
	/////////
	char  *tmp1=NULL ,*tmp2=NULL;
	int len;
	char ID[MAX_ID_LEN];
	memset(ID,0,MAX_ID_LEN);
        regcompile_1(mail_info->mail_data, patternRid, ID,MAX_SUBJ_LEN);
	/////////////
	int  fd;
	char filename[MAX_FN_LEN] = {0};
        memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"eyou",mail_info->from);
        Attachment *attachment;
        Attach_info *attach_tmp;
        Attach_info *attach_info;
        char writepath[MAX_PATH_LEN] = {0};
        attach_info=attach_tab.head->next;
        int  i=0;
        int flag=0;
        //printf("\nID = %s",ID);
	while(attach_info!=NULL)
        {
                //printf("\nattach_info->ID_str = %s",attach_info->ID_str);
		if(!strcmp(attach_info->ID_str,ID))
		{
                        //printf("\nhello");
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
//	chdir(mail_info->save_path);
       /* p1=strstr(p1,"filename=\"");
	p2 = p1;
	if(p1)
	{
		p1+=10;
		if(*p1 != '\"') 
		{
			p2=strstr(p1,"\"\r\n");
			if(!p2) 
				return;
			Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
			attachment->next = NULL;
			mail_info->attach = attachment;
			memcpy(attachment->path_of_sender,p1,p2-p1);
			attachment->path_of_sender[p2 - p1] = 0;
			get_file_name(attachment->path_of_sender,filename);
			sprintf(attachment->loc_filename,"%s",filename);
			p1=strstr(p1,"\r\n\r\n");
			if(!p1) return;
			p1+=4;
			unsigned int n = mail_info ->mail_length-(p1-mail_info->mail_data);
			p2 = memfind(p1,"Content-Disposition",n);
			if(!p2) return ;          
			char str[MAX_PATH_LEN];
			sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ;
			fd = open (str,O_RDWR|O_CREAT,file_mode);
			if(fd ==-1) return;
			write(fd,p1,p2-p1);
			close(fd);
			mail_info->num_of_attach = 1;
			trim_attach(str, 45);
		}
		else
		{
		   char i=0;
		   int  flag=0;
		   Attach_info *attach_tmp;
		   Attachment *attachment;
                   Attach_info *attach_info;
		   char writepath[MAX_PATH_LEN];
                   tmp1=strstr(mail_info->mail_data,"EYLGN=");
		   if(tmp1)
		   {
			  tmp1+=6;
			  tmp2=strstr(tmp1,";");
			  if(tmp2!=NULL)
			  {
				len=tmp2-tmp1;
				if(len<MAX_ID_LEN)
				{
					strncpy(ID,tmp1,len);
					ID[len]=0;
					//printf("ID = %s\n", ID);
				}
			  }
		   }
		   if(ID[0]!='\0')
		   {
			   attach_info=attach_tab.head->next;
			   while(attach_info!=NULL)
			   {
				   if(!strcmp(attach_info->ID_str,ID))
				   {
					   i++;
					   get_file_name(attach_info->path_of_sender,filename);
					   attachment = (Attachment *)malloc(sizeof(Attachment));
					   attachment->next =NULL;
					   sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
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
		   }
		}
	}*/
	regcompile_2(mail_info->mail_data, patterncontent, &mail_info->content);
	if (mail_info->content != NULL) 
	{
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
		htmldecode_full(mail_info->content, mail_info->content);
	}
	
	//printf("mail_info->from : %s\n", mail_info->from);
	//printf("mail_info->to : %s\n", mail_info->to);
	//printf("mail_info->cc : %s\n", mail_info->cc);
	//printf("mail_info->bcc : %s\n", mail_info->bcc);
	//printf("mail_info->subject : %s\n", mail_info->subject);
	//printf("mail_info->content : %s\n", mail_info->content);
        if(mail_info->mail_id)
        {
	    	free(mail_info->mail_id);
            mail_info->mail_id = NULL;
        }
        write_to_file(mail_info);
//	chdir("..");
//	chdir("..");
//	chdir("..");
}



int analyse_eyou_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	char http_ok_head[18]="HTTP/1.1 200 OK\r\n";
	
	//printf("%s\n", data);
	
	if(is_b_s)
	{
		//printf("1111111111\n");
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
		//printf("2222222222222\n");
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefileeyou(mail_info);
		del_mail_node(mail_info);
	}

	return 0;
}
int  analyse_eyou_attach_head(Attach_info *attach_info, char *data,unsigned int datalen,unsigned int seq)
{
	char file_name_pattern[]="; filename=\"(.*)\"\r\nContent-Type: ";
	struct timeval tv;
	struct timezone tz;
	char  *p=NULL;
	char *tmp1=NULL,*tmp2 =NULL;
	int off_seq;
	int  len;
	int range;

	off_seq = seq -attach_info->start_seq;
	range=off_seq+datalen;
	if(range>attach_info->ok_len)
	{
	    return -1;
	}
        memcpy(attach_info->ok_data+off_seq,data,datalen);

	p = strstr(attach_info->ok_data,"filename=\"");
	if(p==NULL)
		return -2;
        p=strstr(p,"\r\n\r\n");
	if(p==NULL) 
		return -2;
	p+=4;
	///////////////////////
	tmp1=strstr(attach_info->ok_data,"EYLGN=");
	if(tmp1!=NULL)
	{
		tmp1 +=6;
		tmp2=strstr(tmp1,";");
		if(tmp2)
		{
                     len=tmp2-tmp1;
		       if(len<MAX_ID_LEN)
		       {
			     strncpy(attach_info->ID_str,tmp1,len);
			     attach_info->ID_str[len]=0;
		        }
		 }
	}
	//////////////////////
	attach_info->start_seq = p - attach_info->ok_data+attach_info->start_seq;//1
	regcompile_2(attach_info->ok_data,file_name_pattern,&attach_info->path_of_sender);//2
	gettimeofday(&tv,&tz);
	sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec); //3
        mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
        int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
	if (fd ==-1)
	{
            return -1;
	}
	write(fd,p,off_seq+datalen-(p-attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data =NULL;
	attach_info->is_writing =1;
	return  0;

}
void analyse_eyou_attach(Attach_info *attach_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
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
		if (!strncmp(data, "POST /user/?q=compose.upload.do",31))
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
			
			attach_info->recive_length += 1000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL) 
				return ;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			
			p1 = strstr(data,"\r\n\r\n");
			if(p1 == NULL)
			return;
			p1+=4;
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
				p1=strstr(p1,"rid\"\r\n\r\n");
				p1+=8;
				p2=strstr(p1,"\r\n");
				strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1]=0;

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
					return;
				p1+=13;
				char *p2=strstr(p1,"\r\n");
				if(p2 == NULL)
					return;
				
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
		                attach_info->attach_name[p2-p1]=0;
				p1=strstr(p1,"rid\"\r\n\r\n");
				p1+=8;
				p2=strstr(p1,"\r\n");
                                
				strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1]=0;
		
				p1=strstr(p1,"application/octet-stream\r\n\r\n");
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
					return ; 
				}
                                write(fd,p1,p2-p1);
				close(fd);
			}
		}
	}
}

void write_eyou_psword(Mail_info *mail_info)
{
        //printf("go in eyou_pswordss");
	char patternusername[]="user=(.*)&domain_name=";

	char patternpassword[]="password=(.*)&login_ssl=";
        memset(mail_info->username,0,MAX_UN_LEN+1);
        regcompile_1(mail_info->mail_data, patternusername, mail_info->username,MAX_UN_LEN); 
        convert_contents(mail_info->username);
        char *p=strstr(mail_info->username,"@eyou.com");
        if(p == NULL)
        {
            int lengths = strlen(mail_info->username);
            strncpy(mail_info->username+lengths,"@eyou.com",9);
            mail_info->username[lengths+9]=0;
        }
        
	regcompile_1(mail_info->mail_data, patternpassword, mail_info->passwd,MAX_PW_LEN);
	htmldecode_full(mail_info->passwd,mail_info->passwd);
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
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

int analyse_eyou_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
        //printf("go in login state");
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
        //printf("Data recive successfully!");
		write_eyou_psword(mail_info);
		return -1;
	}

	return 0;
}

void write_eyou_recive_up(Mail_info *mail_info)
{
    int len = 0;
    char *ungzip = NULL;
    
    decomp_gzip_1(mail_info->mail_data,mail_info->recive_length-2,&ungzip);
    if(ungzip == NULL) 
        return;
    free(mail_info->mail_data);
    mail_info->mail_data = ungzip;
    char *p2 = NULL;
    char *p1 = strstr(ungzip,"\",\"_cc\":\"");
    
    if(p1)
    {
        p1+=9;
        p2=strstr(p1,"\",\"");
        strncpy(mail_info->cc,p1,p2-p1);
        mail_info->cc[p2-p1]=0;
        clear_tag(mail_info->cc);
        down_contents(mail_info->cc);
        //printf("\nmail_info->cc = %s\n",mail_info->cc);
    }
    
    if(p1==NULL)
        p1=ungzip;
   
    p1=strstr(p1,"\"from_digest\":\"");
    if(p1==NULL)
    {
        //free(ungzip);
        return;
    }
    
    p1+=15;
    p2=strstr(p1,"\",\"from_display");
    len=p2-p1;
	if(len>MAX_FROM_LEN) 
        len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
       // strncpy(mail_info->from+len,"@eyou.com",9);
	mail_info->from[len]=0;
    clear_tag(mail_info->from);
    down_contents(mail_info->from);
    char pattern[]="\" <(.*)>";
    regcompile_1(mail_info->from, pattern, mail_info->from,100);
    p1=strstr(p1,"\"to_digest\":\"");
    if(p1==NULL)
    {
        //free(ungzip);
        return;
    }
    
    p1+=13;
    p2=strstr(p1,"\",\"to_display");
    len = p2-p1;
    
	if(len>MAX_FROM_LEN) 
                len=MAX_FROM_LEN;
	strncpy(mail_info->to,p1,len);
      //  strncpy(mail_info->to+len,"@eyou.com",9);
	mail_info->to[len]=0;
    clear_tag(mail_info->to);
    down_contents(mail_info->to);

    p1=strstr(p1,"\"subject_digest\":\"");
    if(p1==NULL)
    {
        //free(ungzip);
    return;
    }
    p1+=18;
    p2=strstr(p1,"\",\"");
    len=p2-p1;

    if(len>MAX_SUBJ_LEN) 
        len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
    mail_info->subject[len]=0;
    clear_tag(mail_info->subject);
    
   //tmldecode_full(mail_info->subject,mail_info->subject);
    //ar subject[MAX_SUBJ_LEN + 1];
   // code_convert("unicode", "utf-8", mail_info->subject, len ,subject, MAX_SUBJ_LEN + 1);
   //rintf("\nsubject = %s",unicode_convert(mail_info->subject)); 
   //rintf("\nlength = %d",strlen(unicode_convert(mail_info->subject)));
   // int length=strlen(unicode_convert(mail_info->subject));
  //strncpy(mail_info->subject,unicode_convert(mail_info->subject),strlen(unicode_convert(mail_info->subject)));
  //mail_info->subject[length]=0;
    p1=strstr(p1,"\"content_digest\":\"");
    if(p1==NULL)
    {
        //free(ungzip);
        return;
    }
    
    p1+=18;
    p2=strstr(p1,"\",\"");
    len=p2-p1;
    mail_info->content=(char *)malloc(len+1);
    memset(mail_info->content,0,len);
	strncpy(mail_info->content,p1,len);
    mail_info->content[len]=0;

	char *tmp_p1 = NULL;
	tmp_p1 = clear_html_tag(mail_info->content);
	free(mail_info->content);
    mail_info->content = tmp_p1;
        
    clear_tag(mail_info->content);
    down_contents(mail_info->content);
    char sendtime[100];
    memset(sendtime,0,100);
    p1=ungzip; 
    p1=strstr(p1,"\",\"_time\":");
    p1+=10;
    p2=strstr(p1,"},");
    len=p2-p1;
    strncpy(sendtime,p1,len);
    sendtime[len]=0;
    memset(mail_info->sent_time,0,MAX_TIME_LEN + 1);
    convert_time_to_string(atoi(sendtime),mail_info->sent_time);
    //code_convert("UNICODE", "UTF-8", mail_info->content, len ,subject, MAX_SUBJ_LEN + 1);
    //printf("\nsubject = %s",subject);
    // free(ungzip);
    memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"eyou",mail_info->from);
	write_to_file(mail_info);
	/*char *ungzip=NULL;
	
	char *p1=NULL, *p2=NULL, *p3=NULL;
        char *p4=NULL;
	
	decomp_gzip_2(mail_info->mail_data,mail_info->recive_length-22,&ungzip);
	//printf("ungzip=%s\n",ungzip);
	
	p1=strstr(ungzip,"\"sender\">");
	if(p1==NULL)
        {
		free(ungzip);
		return;
	}
        p4=p1;
        *p4='\0';
        p4-=1000;

	p1+=9;
	p2=strstr(p1,"</span>");
	if(p2==NULL)
        {
		free(ungzip);
		return;
	}
	

	clear_from(mail_info->from);
	//printf("from=%s\n",mail_info->from);

	p3=strstr(p1,"\"mailcontent\"");
	if(p3==NULL)
        {
		free(ungzip);
		return ;
	}
	*p3='\0';

	p1=strstr(p2,"\"receiver\">");
	if(p2==NULL)
        {
		free(ungzip);
		return;
	}
	p1+=11;
	p2=strstr(p1,"</td>");
	if(p2==NULL)
        {
		free(ungzip);
		return;
	}
	len=p2-p1;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	//printf("to=%s\n",mail_info->to);
    
	p3=strstr(p2,"\"d_cc\">");
	if(p3)
        {
		p3+=7;
		p1=strstr(p3,"</td>");
		if(p1)
                {
			len=p1-p3;
			if(len>MAX_CC_LEN) len=MAX_CC_LEN;
			strncpy(mail_info->cc,p3,len);
			mail_info->cc[len]=0;
		}
	}
	//printf("cc=%s\n",mail_info->cc);

	p1=strstr(p2,"\"subject\">");
	if(p1==NULL) 
        {
		free(ungzip);
		return;
	}
	p1+=10;
	p2=strstr(p1,"</td>");
	if(p2==NULL)
        {
		free(ungzip);
		return;
	}
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	//printf("subject=%s\n",mail_info->subject);

        p3=strstr(p4,"infobar");
        if(p3)
        {
           p3+=23;
           p4=strstr(p3,"</div>");
           if(p4)
           {
              len=p4-p3;
              if(len>MAX_TIME_LEN)  len=MAX_TIME_LEN;
              strncpy(mail_info->sent_time,p3,len);
              mail_info->sent_time[len]=0;
           }
        }
    
	free(ungzip);*/

}

void write_eyou_recive_down(Mail_info *mail_info)
{
	char *p1=NULL, *p2=NULL;
	char *ungzip = NULL;
	decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&ungzip);
	//printf("ungzip=%s\n",ungzip);
	if(ungzip==NULL) 
        return ;
	mail_info->content=clear_html_tag(ungzip);
	free(ungzip);
	ungzip = NULL;
	create_dir(mail_info->save_path,"eyou",mail_info->from);
	write_to_file(mail_info);

}
int analyse_eyou_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{//printf("analyse_eyou_recive\n");
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int len;
	int range;
	char *p=NULL;
        //printf("\nis_b_s = %d",is_b_s);
	if(is_b_s)
	{
	    if(!strncmp(data, "GET /user/?q=compose", 20))
	    {
            char id[MAX_ID_LEN]={0};
			char patterniid[]="q=compose&iid=(.*)&action=readmail";
            regcompile_1(data, patterniid, id,MAX_ID_LEN);
	      	char *p1, *p2;
	      	int len_id;
	      	p1=strstr(data,"&zid=");
	      	if(p1==NULL) 
            {
                //printf("\n234");
			    return -1;
            }
	      	p1+=5;
	      	p2=strstr(p1," HTTP/1.1");
	      	if(p2==NULL) 
            { 
			    //printf("\n334");
			    return -1;
            }
	      	len_id=p2 - p1;
	      	if (len_id < 0 || len_id > MAX_ID_LEN)
            {
                //printf("\n344");
			    return -1;
            }
	      	memcpy(mail_info->mail_id, p1, len_id);
            memcpy(mail_info->mail_id+len_id, id, strlen(id));
	      	mail_info->mail_id[len_id+strlen(id)] = 0;
            mail_info->is_writing = 0;
	   }
	}
    else
    {
        if(datalen > 0)
        {
			char Data[16];
            strncpy(Data,data,15);
            Data[15]=0;
        }

        if(!strncmp(data,"HTTP/1.",7) && !mail_info->is_writing)
		{
            /*if(mail_info->mail_data != NULL)
            {
                if(mail_info->start_seq >= seq+datalen)
                    return;
                free(mail_info->mail_data);
                mail_info->mail_data = NULL;
            }*/
			mail_info->mail_length=get_http_length(data);
            //   printf("\nmail_info->mail_length = %d\n",mail_info->mail_length);
			if(mail_info->mail_length<=0)
			{
				return -1;
			}
			//mail_info->mail_length+=20;
			mail_info->mail_data=(char *)malloc(mail_info->mail_length+20);
			if(mail_info->mail_data==NULL)
			{
				return -1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL) return -1;
			p+=4;
			len=datalen-(p-data);
			mail_info->start_seq=seq+datalen;
                        mail_info->source_seq=seq+(p-data);
			if(len>mail_info->mail_length)
			{
				return -1;
			}
            //mail_info->http_seq=len;
			memset(mail_info->mail_data,0,mail_info->mail_length+1);
			memcpy(mail_info->mail_data,p,len);
            mail_info->recive_length = mail_info->mail_length;
            mail_info->is_writing = 1;
			/*if(!memcmp(data+datalen-5,"0\r\n\r\n",5))
			{
				mail_info->is_proce_mail=1;
				write_eyou_recive_up(mail_info);
			}*/
        }
        else
        {
                      
            /*  if(mail_info->start_seq > seq)
            {
                if(mail_info->start_seq>=seq+datalen) 
                     return;
                else
                {
                     printf("chong chuan!");
                     off_seq=seq+datalen-mail_info->start_seq;
                     mail_info->http_seq=mail_info->http_seq+off_seq;
                     memcpy(mail_info->mail_data,data+mail_info->start_seq-seq,off_seq);
                     mail_info->start_seq=seq+datalen; 
                }
            }
            
            if(mail_info->start_seq == seq)
            {
                mail_info->start_seq=seq+datalen;
                mail_info->http_seq+=datalen;
                memcpy(mail_info->mail_data,data,datalen);
                // printf("\nmail_info->http_seq = %d\n",mail_info->http_seq);
            }
            else
            {*/
                if(mail_info->mail_data == NULL)
                    return -1;
                //printf("\nthe sequence isn't right!");
                if( seq > mail_info->source_seq + mail_info->mail_length)
                {
                    return -1;
                }
                else
                {
					if( seq + datalen > mail_info->source_seq + mail_info->mail_length)
					{
						memcpy(mail_info->mail_data+seq-mail_info->source_seq,data,mail_info->source_seq + mail_info->mail_length - seq);
					}
					if( seq + datalen <= mail_info->source_seq + mail_info->mail_length)
						memcpy(mail_info->mail_data+seq-mail_info->source_seq,data,datalen);
                }
                      
         } 
		 
         if(mail_info->mail_data == NULL)
               return -1;
		 
         if(tcp->fin || strlen(mail_info->mail_data) == mail_info->mail_length || !memcmp(data + datalen -2, "\0\0", 2))//接受结束
         {
              write_eyou_recive_up(mail_info);
              // write_eyou_recive_down(mail_info);
		      del_mail_node(mail_info);
         }
	}

	return 0;
 /*	if(!is_b_s && mail_info->is_proce_mail==0)
	{
		if(!strncmp(data,"HTTP/1.",7))
		{
			mail_info->mail_length=get_http_length(data);
			if(mail_info->mail_length<=0)
			{
				return -1;
			}
			mail_info->mail_length+=20;
			mail_info->mail_data=(char *)malloc(mail_info->mail_length);
			if(mail_info->mail_data==NULL)
			{
				return -1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL) return -1;
			p+=4;
			p=strstr(p,"\r\n");
			if(p==NULL) return -1;
			p+=2;
			len=datalen-(p-data);
			mail_info->start_seq=seq+(p-data);
			if(len>mail_info->mail_length)
			{
				return -1;
			}
			memset(mail_info->mail_data,0,mail_info->mail_length);
			memcpy(mail_info->mail_data,p,len);
			if(!memcmp(data+datalen-5,"0\r\n\r\n",5))
			{
				mail_info->is_proce_mail=1;
				write_eyou_recive_up(mail_info);
			}
		}
		else 
		if(mail_info->mail_data!=NULL)
		{
			off_seq=seq-mail_info->start_seq;
			range=off_seq+datalen;
			if(range>mail_info->mail_length)
			{
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-5,"0\r\n\r\n",5))
                        {
				mail_info->is_proce_mail=1;
				write_eyou_recive_up(mail_info);
			}
		}		
	}
	else 
	if(!is_b_s&&mail_info->is_proce_mail==1)
	{
                   if(!strncmp(data,"HTTP/1.",7))
		   {
			   mail_info->recive_length=get_http_length(data);
			   if(mail_info->recive_length<=0)
			   {
				   return -1;
			   }
			   mail_info->recive_length+=20;
			   mail_info->recive_data=(char *)malloc(mail_info->recive_length);
			   if(mail_info->recive_data==NULL)
			   {
				   return -1;
			   }
			   p=strstr(data,"\r\n\r\n");
			   if(p==NULL)
			   {
				   return -1;
			   }
			   p+=4;
			   p=strstr(p,"\r\n");
			   if(p==NULL)
			   {
				   return -1;
			   }
			   p+=2;
			   len=datalen-(p-data);
			   mail_info->http_seq=seq+(p-data);
			   if(len>mail_info->recive_length)
			   {
				   return -1;
			   }
			   memset(mail_info->recive_data,0,mail_info->recive_length);
			   memcpy(mail_info->recive_data,p,len);
			   if(!memcmp(data+datalen-5,"0\r\n\r\n",5))
			   {
				   write_eyou_recive_down(mail_info);
				   del_mail_node(mail_info);
			   }
		   } 
		   else 
		   if(mail_info->recive_data!=NULL)
		   {
				off_seq=seq-mail_info->http_seq;
				range=off_seq+datalen;
				if(range>mail_info->recive_length)
				{
					return -1;
				}
				
				memcpy(mail_info->recive_data+off_seq,data,datalen);
				
				if(!memcmp(data+datalen-5,"0\r\n\r\n",5))
				{
					write_eyou_recive_down(mail_info);
					del_mail_node(mail_info);
				}
		   }
	}*/
}

int analyse_eyou_attach_recive(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{//printf("\nanalyse_eyou_attach_recive...\n");
	unsigned int seq=ntohl(tcp->seq);   
	unsigned int ack_seq = ntohl(tcp->ack);
	int off_seq;
	int range;
	unsigned int attach_len;
	int n;
	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN + 1];
		int result;
		if (!strncmp(data, "GET /public/?q=compose.output", 29))
		{
			mail_info->ack_seq = ack_seq;
			char id[MAX_ID_LEN]={0};
			char patterniid[]="q=compose.output&action=mail.attach&mid=(.*)&part=";
			regcompile_1(data, patterniid, id,MAX_ID_LEN);
			//   printf("\n data = %s",data);
			char *p1, *p2;
			int len_id;
			p1=strstr(data,"&zid=");
			if(p1==NULL) 
				return -1;
			p1+=5;
			p2=strstr(p1," HTTP/1.1");
			if(p2==NULL) 
				return -1;
			len_id = p2 - p1;
			if (len_id < 0 || (len_id + strlen(id)) > MAX_ID_LEN)
				return -1;
			memcpy(mail_info->mail_id, p1, len_id);
			memcpy(mail_info->mail_id+len_id, id, strlen(id));
			mail_info->mail_id[len_id+strlen(id)] = 0;
			mail_info->is_writing = 0;
			/*if(mail_info->recive_data != NULL)
			{
				printf("\nack_seq-mail_info->ack_seq = %d",ack_seq-mail_info->ack_seq);
				if(ack_seq-mail_info->ack_seq == mail_info->attach_len)
				{
					printf("\n recive is completed!");
					mail_info->is_complished = 1;
					write_attach_down_1(mail_info, mail_info->attach_len, n);
					del_mail_node(mail_info);
				}
			}*/
		}
	}
	else
	{
		/*  if(!datalen) 
		return;
		char Data[16] = {0};
		strncpy(Data,data,15);
		Data[15]=0;
		printf("\nData = %s",Data);*/
		if (!strncmp(data, "HTTP/1.1 200 OK",15)&& !mail_info->is_writing)
		{
			char *p1;
			p1 = NULL;
			mail_info->recive_length = 0;
			//mail_info->recive_length = get_http_length(data);
			
			char *p = strstr(data, "\r\ncontent-length: ");
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
			mail_info->is_chunked= judge_chunk(data);
			mail_info->attach_len = mail_info->recive_length;

			// printf("\nmail_info->recive_length = %d",mail_info->recive_length);
			if (mail_info->recive_length <= 0) 
				return -1;

			mail_info->recive_length += 1000;
			unsigned int seq=ntohl(tcp->seq);
			unsigned int ack_seq = ntohl(tcp->ack);
			int off_seq;
			int range;
			unsigned int attach_len;
			int n;
			if (is_b_s)
			{
				char tmp_id[MAX_ID_LEN + 1];
				int result;
				if (!strncmp(data, "GET /public/?q=compose.output", 29))
				{
					mail_info->ack_seq = ack_seq;
					char id[MAX_ID_LEN]={0};
					char patterniid[]="q=compose.output&action=mail.attach&mid=(.*)&part=";
					regcompile_1(data, patterniid, id,MAX_ID_LEN);
					//   printf("\n data = %s",data);
					char *p1, *p2;
					int len_id;
					p1=strstr(data,"&zid=");
					if(p1==NULL) 
						return -1;
					p1+=5;
					p2=strstr(p1," HTTP/1.1");
					if(p2==NULL) 
						return -1;
					len_id = p2 - p1;
					if (len_id < 0 || (len_id + strlen(id)) > MAX_ID_LEN)
						return -1;
					memcpy(mail_info->mail_id, p1, len_id);
					memcpy(mail_info->mail_id+len_id, id, strlen(id));
					mail_info->mail_id[len_id+strlen(id)] = 0;
					mail_info->is_writing = 0;
					/*if(mail_info->recive_data != NULL)
					{
						printf("\nack_seq-mail_info->ack_seq = %d",ack_seq-mail_info->ack_seq);
						if(ack_seq-mail_info->ack_seq == mail_info->attach_len)
						{
							printf("\n recive is completed!");
							mail_info->is_complished = 1;
							write_attach_down_1(mail_info, mail_info->attach_len, n);
							del_mail_node(mail_info);
						}
					}*/
				}
			}
			else
			{
				/*  if(!datalen) 
					return;
				char Data[16] = {0};
				strncpy(Data,data,15);
				Data[15]=0;
				printf("\nData = %s",Data);*/
				if (!strncmp(data, "HTTP/1.1 200 OK",15)&& !mail_info->is_writing)
				{
					char *p1;
					p1 = NULL;
					mail_info->recive_length = 0;
					//mail_info->recive_length = get_http_length(data);
					
					char *p = strstr(data, "\r\ncontent-length: ");
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
					mail_info->is_chunked= judge_chunk(data);
					mail_info->attach_len = mail_info->recive_length;

					// printf("\nmail_info->recive_length = %d",mail_info->recive_length);
					if (mail_info->recive_length <= 0) 
						return -1;

					mail_info->recive_length += 1000;
					mail_info->recive_data = (char *)malloc(mail_info->recive_length);
					if(mail_info->recive_data == NULL) 
						return -1;
					unsigned int seq=ntohl(tcp->seq);   
					unsigned int ack_seq = ntohl(tcp->ack);
					int off_seq;
					int range;
					unsigned int attach_len;
					int n;
					if (is_b_s)
					{
						char tmp_id[MAX_ID_LEN + 1];
						int result;
						if (!strncmp(data, "GET /public/?q=compose.output", 29))
						{ 

							mail_info->ack_seq = ack_seq;
							char id[MAX_ID_LEN]={0};
							char patterniid[]="q=compose.output&action=mail.attach&mid=(.*)&part=";
							regcompile_1(data, patterniid, id,MAX_ID_LEN);
						//   printf("\n data = %s",data);
							char *p1, *p2;
							int len_id;
							p1=strstr(data,"&zid=");
							if(p1==NULL) 
								return -1;
							p1+=5;
							p2=strstr(p1," HTTP/1.1");
							if(p2==NULL) 
								return -1;
							len_id=p2 - p1;
							if (len_id < 0 || (len_id + strlen(id)) > MAX_ID_LEN)
								return -1;
							memcpy(mail_info->mail_id, p1, len_id);
							memcpy(mail_info->mail_id+len_id, id, strlen(id));
							mail_info->mail_id[len_id+strlen(id)] = 0;
							mail_info->is_writing = 0;
							/*if(mail_info->recive_data != NULL)
							{
								printf("\nack_seq-mail_info->ack_seq = %d",ack_seq-mail_info->ack_seq);
								if(ack_seq-mail_info->ack_seq == mail_info->attach_len)
								{
									printf("\n recive is completed!");
									mail_info->is_complished = 1;
									write_attach_down_1(mail_info, mail_info->attach_len, n);
									del_mail_node(mail_info);
								}
							}*/
						}
					}
					else
					{
						/*  if(!datalen) 
						return;
						char Data[16] = {0};
						strncpy(Data,data,15);
						Data[15]=0;
						printf("\nData = %s",Data);*/
						if (!strncmp(data, "HTTP/1.1 200 OK",15)&& !mail_info->is_writing)
						{
							char *p1;
							p1 = NULL;
							mail_info->recive_length = 0;
							//mail_info->recive_length = get_http_length(data);

							char *p = strstr(data, "\r\ncontent-length: ");
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
							mail_info->is_chunked= judge_chunk(data);
							mail_info->attach_len = mail_info->recive_length;

							// printf("\nmail_info->recive_length = %d",mail_info->recive_length);
							if (mail_info->recive_length <= 0) 
								return -1;
						
							mail_info->recive_length += 1000;
							mail_info->recive_data = (char *)malloc(mail_info->recive_length);
							if(mail_info->recive_data == NULL)
								return -1;
							memset(mail_info->recive_data,0,mail_info->recive_length);
							mail_info->http_seq = seq; 

							p1 = strstr(data,"\r\n\r\n");
							if(p1 == NULL)
								return -1;
							p1+=4;
							mail_info->attach_len = mail_info->attach_len+p1-data; 
							mail_info->source_seq=seq+(p1-data);
							memcpy(mail_info->recive_data, data, datalen);
							mail_info->is_writing = 1;
						}
						else 
						{
							if((mail_info->recive_data != NULL) && datalen)
							{
								off_seq = seq - mail_info->http_seq;
								if (off_seq > mail_info->attach_len) 
								{
									mail_info->recive_data = (char *)realloc(mail_info->recive_data,mail_info->recive_length+((off_seq-mail_info->attach_len)/5000+2)*5000);
									if(mail_info->recive_data == NULL)
										return 0;
									mail_info->attach_len+=((off_seq-mail_info->attach_len)/5000+2)*5000;
									memcpy(mail_info->recive_data + off_seq, data, datalen); 
									return 0;
								}
								range = off_seq + datalen;
								if (range > mail_info->attach_len)
								{
									memcpy(mail_info->recive_data + off_seq, data, mail_info->attach_len-off_seq); 
								}
								else
								{
									memcpy(mail_info->recive_data + off_seq, data, datalen);
								}
             						}
          					}
						/*if (!memcmp(data+datalen-5,"0\r\n\r\n",5))
						{
							mail_info->is_complished = 1;
							write_attach_down_1(mail_info, attach_len, n);
							del_mail_node(mail_info);
						}*/
						if(mail_info->recive_data != NULL)
						{
							if(tcp->fin)
							{
								mail_info->is_complished = 1;
								if(!mail_info->is_have_contentlength)
								{
									mail_info->recive_length = seq-mail_info->source_seq+1000+datalen;
								}                
								write_attach_down_2(mail_info, mail_info->attach_len, mail_info->is_chunked);
								del_mail_node(mail_info);
							}
						} 
					}
					memset(mail_info->recive_data,0,mail_info->recive_length);
					mail_info->http_seq = seq; 
					p1 = strstr(data,"\r\n\r\n");
					if(p1 == NULL)
						return -1;
					p1+=4;
					mail_info->attach_len = mail_info->attach_len+p1-data; 
					mail_info->source_seq=seq+(p1-data);
					memcpy(mail_info->recive_data, data, datalen);
					mail_info->is_writing = 1;
				}
				else 
				{
					if((mail_info->recive_data != NULL) && datalen)
					{ 
						off_seq = seq - mail_info->http_seq;
						if (off_seq > mail_info->attach_len) 
						{
							mail_info->recive_data = (char *)realloc(mail_info->recive_data,mail_info->recive_length+((off_seq-mail_info->attach_len)/5000+2)*5000);
							if(mail_info->recive_data == NULL)
								return 0;
							mail_info->attach_len+=((off_seq-mail_info->attach_len)/5000+2)*5000;
							memcpy(mail_info->recive_data + off_seq, data, datalen); 
							return 0;
						}
						range = off_seq + datalen;
						if (range > mail_info->attach_len)
						{
							memcpy(mail_info->recive_data + off_seq, data, mail_info->attach_len-off_seq); 
						}
						else
						{
							memcpy(mail_info->recive_data + off_seq, data, datalen);
						}
					}
				}
				/*if (!memcmp(data+datalen-5,"0\r\n\r\n",5))
				{
				mail_info->is_complished = 1;
				write_attach_down_1(mail_info, attach_len, n);
				del_mail_node(mail_info);
				}*/
				if(mail_info->recive_data != NULL)
				{
					if(tcp->fin)
					{
						mail_info->is_complished = 1;
						if(!mail_info->is_have_contentlength)
						{
							mail_info->recive_length = seq-mail_info->source_seq+1000+datalen;
						}                
						write_attach_down_2(mail_info, mail_info->attach_len, mail_info->is_chunked);
						del_mail_node(mail_info);
					}
				} 
			}
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL)
				return -1;
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq; 
			
			p1 = strstr(data,"\r\n\r\n");
			if(p1 == NULL)
				return -1;
			p1+=4;
			mail_info->attach_len = mail_info->attach_len+p1-data; 
			mail_info->source_seq=seq+(p1-data);
			memcpy(mail_info->recive_data, data, datalen);
			mail_info->is_writing = 1;
		}
		else 
		{
			if((mail_info->recive_data != NULL) && datalen)
			{
				off_seq = seq - mail_info->http_seq;
				if (off_seq > mail_info->attach_len) 
				{
					mail_info->recive_data = (char *)realloc(mail_info->recive_data,mail_info->recive_length+((off_seq-mail_info->attach_len)/5000+2)*5000);
					if(mail_info->recive_data == NULL)
						return 0;
					mail_info->attach_len+=((off_seq-mail_info->attach_len)/5000+2)*5000;
					memcpy(mail_info->recive_data + off_seq, data, datalen); 
					return 0;
				}
				range = off_seq + datalen;
				if (range > mail_info->attach_len)
				{
					memcpy(mail_info->recive_data + off_seq, data, mail_info->attach_len-off_seq); 
				}
				else
				{
					memcpy(mail_info->recive_data + off_seq, data, datalen);
				}
             		}
          	}
		/*if (!memcmp(data+datalen-5,"0\r\n\r\n",5))
		{
		mail_info->is_complished = 1;
		write_attach_down_1(mail_info, attach_len, n);
		del_mail_node(mail_info);
		}*/
		if(mail_info->recive_data != NULL)
		{
			if(tcp->fin)
			{
				mail_info->is_complished = 1;
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
	
void analyse_eyou(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int mora)
{
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned int lowtype;
	int result = 0;
	if(!mora)
	{
		mail_info=(Mail_info *)tmp;
		lowtype=mail_info->mail_type;
		lowtype = lowtype & 0X00FF;
		switch(lowtype)
		{
			case 0x11:
				//printf("\n1\n");
				result = analyse_eyou_content(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x01:
				//printf("\n2\n");
				result = analyse_eyou_psword(mail_info,data,datalen,tcp,is_b_s);
				break;
            case 0x31:
				result = analyse_eyou_recive(mail_info,data,datalen,tcp,is_b_s);
				break;
	        case 0x32:
			//printf("\n4\n"); 
			    result = analyse_eyou_attach_recive(mail_info,data,datalen,tcp,is_b_s);
				break;
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
		lowtype=attach_info->attach_type;
		lowtype = lowtype & 0x00FF;
		switch(lowtype) 
		{
			case 0x61:
				analyse_eyou_attach(attach_info,data,datalen,tcp,is_b_s);
				break;
			default :
				break;
		}
	}
}	
