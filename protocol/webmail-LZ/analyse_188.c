#include "common.h"


extern char *conv_163_to_utf8(char *src); 

int write_188_passwd(Mail_info *mail_info)
{
	char username[MAX_UN_LEN], passwd[MAX_PW_LEN];
	char writepath[MAX_PATH_LEN];
	char *p1 = NULL, *p2= NULL;
	int len;

	p1 = strstr(mail_info->mail_data, "&user=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&pass=");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_UN_LEN - 1)
		return -1;
	memcpy(username, p1, len);
	username[len] = 0;
	if (strstr(username, "@188.com") == NULL) {
		if (len + 8 > MAX_UN_LEN - 1)
			return -1;
		strcat(username, "@188.com");
	}

	p1 = p2 + 6;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_PW_LEN - 1)
		return -1;
	memcpy(passwd, p1, len);
	passwd[len] = 0;
	htmldecode_full(passwd,passwd);

	FILE *fp;
	sprintf(writepath, "%s/pass.txt", mail_data_path);
	fp=fopen(writepath, "a+");
	if(fp==NULL) 
		return -1;
	fprintf(fp,"\nusername=%s\npassword=%s\n",username,passwd);
	fclose(fp);
	return 0;
}

int analyse_188_passwd(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			if (!strncmp(data, "<?xml version=\"1.0\"?><object><string name=\"action\">sa", 53) || !strncmp(data, "<?xml version=\"1.0\"?><object/>", 32)) 
			{
				return -1;
			}
			if (mail_info->mail_length == 0) 
			{
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if (mail_info->mail_data == NULL) 
				{
					return -1;
				}
				memset(mail_info->mail_data, 0, 5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000) 
			{
				int len;
				char *tmp = NULL;

				len = get_http_length(data);
				if (len > 0) {
					mail_info->mail_length += len;
					tmp = (char *)malloc((size_t)mail_info->mail_length);
					if (tmp == NULL) 
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
			memcpy(mail_info->mail_data+off_seq,data,data_len);
		}
//	} else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15)){
	} 
	else if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		write_188_passwd(mail_info);
		
		del_mail_node(mail_info);
	}

	return 0;
}

void writefile188(Mail_info *mail_info)
{
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL;
	char *tmp_str;
	int len;
	int result;
	char attach_tag[200];
	char filepath[MAX_PATH_LEN];
	char filename[MAX_FN_LEN];
	char writepath[MAX_PATH_LEN];
	char ID[MAX_ID_LEN];
	Attachment *attachment;
	mode_t file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
	int fd;
	int n, i = 0;
	int flag = 0;

//	printf("####%s#####\n", mail_info->mail_data);
	p1 = strstr(mail_info->mail_data, "<string name=\"id\"");
/*	
	if (p1 == NULL)
		return ;
	p1 += 18;
	p2 = strstr(p1, "</string");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_ID_LEN - 1)
		return ;
	memcpy(ID, p1, len);
	ID[len] = 0;
	p2 += 8;
*/
	if (p1 != NULL) {
		p1 += 18;
		p2 = strstr(p1, "</string");
		len = p2 - p1;
		if (p2 == NULL || len > MAX_ID_LEN - 1)
			return ;
		memcpy(ID, p1, len);
		ID[len] = 0;
		p2 += 8;
	}

//	p1 = strstr(p2, "<string name=\"account\">");
	p1 = strstr(mail_info->mail_data, "<string name=\"account\">");
	if (p1 == NULL)
		return ;
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL)
		return ;
	p3 = memfind(p1, "&lt;", len);
	if (p3 != NULL) {
		p1 = p3 + 4;
		p2 = strstr(p1, "&gt;");
		if (p2 == NULL)
			return ;
		len = p2 - p1;
	}
	if (len > MAX_FROM_LEN - 1)
		return ;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	p2 += 8;

	p1 = strstr(p2, "<array name=\"to\"><string>");
	if (p1 == NULL)
		return ;
	p1 += 25;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_TO_LEN - 1)
		return ;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	p2 += 8;

	p1 = strstr(p2, "<array name=\"cc\"><string>");
	if (p1 != NULL) {
		p1 += 25;
		p2 = strstr(p1, "</string>");
		len = p2 - p1;
		if (p2 != NULL && len < MAX_CC_LEN) {
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
			p2 += 8;
		}
	} else {
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "<array name=\"bcc\"><string>");
	if (p1 != NULL) {
		p1 += 26;
		p2 = strstr(p1, "</string>");
		len = p2 - p1;
		if (p2 != NULL && len < MAX_BCC_LEN) {
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
			p2 += 8;
		}
	} else {
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "<string name=\"subject\">");
	if (p1 == NULL)
		return ;
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_SUBJ_LEN - 1)
		return ;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	p2 += 8;

	p1 = strstr(p2, "<string name=\"content\">");
	if (p1 == NULL)
		return ;
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL)
		return ;
	mail_info->content = (char *)malloc((size_t)len + 1);
	if (mail_info->content == NULL)
		return ;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += 8;

	create_dir(mail_info->save_path, "188" ,mail_info->from);
		
	if (strstr(p2, "<object name=\"attachments\">") != NULL) {
		int fd, atta_fd;
		struct stat st;
		char *mapped;
		char *p1, *p2;
		char filename[MAX_FN_LEN];
		char writepath[MAX_PATH_LEN];
		Attachment *attachment;
		int flag = 0;
		int i = 0;

		mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		attach_info = find_attach(ID);
		if (attach_info == NULL)
			return ;
		fd = open(attach_info->path_of_here, O_RDWR);
		if (fstat(fd, &st) < 0) {
			LOG_ERROR("error.\n");
			return ;
		}
		//printf("OKOKOKOKOKOKOKOKOKOKOKOKOK\n");

		mapped = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
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
			i++;
			tmp_str = conv_163_to_utf8(attachment->path_of_sender);
			if (tmp_str == NULL)
				return ;
			get_file_name(tmp_str, filename);
			sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
			free(tmp_str);
			tmp_str = NULL;
			char str[MAX_PATH_LEN];
			p1 = strstr(p2, "\r\n\r\n");
			p1 += 4;
			unsigned int n = st.st_size - (p1 - mapped);
			p2 = memfind(p1, "Content-Disposition: form-data; name", n);
			sprintf(str, "%s/%s", mail_info->save_path, attachment->loc_filename);
			atta_fd = open(str, O_RDWR | O_CREAT, file_mode);
			write(atta_fd, p1, p2 - p1);
			close(atta_fd);
			trim_attach(str, 45);
//			trim_attach(str, 42);
			p1 = p2;
		}
		munmap(mapped, st.st_size);
		close(fd);
		mail_info->num_of_attach = i;
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);
	} else {
		char filename[MAX_FN_LEN];
		int i = 0;
		int flag = 0;
		Attach_info *attach_tmp;
		Attachment *attachment;
		Attach_info *attach_info = attach_tab.head->next;

		while (attach_info != NULL) {
			if (!strcmp(attach_info->ID_str, ID)) {
				i++;
				get_file_name(attach_info->path_of_sender, filename);
				attachment = (Attachment *)malloc(sizeof(Attachment));
				attachment->next = NULL;
				sprintf(attachment->loc_filename, "atta%d_%s", i, filename);
				if (!flag) {
					mail_info->attach = attachment;
					flag++;
				} else {
					attachment->next = mail_info->attach->next;
					mail_info->attach->next = attachment;
				}
				sprintf(writepath, "%s/%s", mail_info->save_path, attachment->loc_filename);
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

	if (mail_info->content != NULL) 
	{	
		tmp_str = conv_to_xml_symbol(mail_info->content);
		free(mail_info->content);
		mail_info->content = clear_html_tag(tmp_str);
		free(tmp_str);
		tmp_str = NULL;
	}
	write_to_file(mail_info);
}
void write_188_recive_up(Mail_info *mail_info)
{
	char *p1=NULL,*p2=NULL,*p3=NULL;
	int len;
	
	p1=strstr(mail_info->recive_data,"'from':['");
	if(p1==NULL)  return ;
	p1+=9;
	p2=strstr(p1,"'],");
	if(p2==NULL)  return;
    len=p2-p1;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_from(mail_info->from);

	p1=strstr(p2,"'to':[");
	if(p1==NULL) return;
	p1+=6;
	p2=strstr(p1,"],");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	
	p3=p2;
	p1=strstr(p3,"'cc':[");
	if(p1!=NULL){
		p1+=6;
	    p3=strstr(p1,"],");
		if(p3){
			len=p3-p1;
			if(len>MAX_CC_LEN) len=MAX_CC_LEN;
			strncpy(mail_info->cc,p1,len);
			mail_info->cc[len]=0;
			p2=p3;
		}
	}
	p1=strstr(p2,"'subject':");
	if(p1==NULL) return;
    p1+=10;
	p2=strstr(p1,"'sentDate':");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	
	p2+=11;
	p1=strstr(p2,"'priority':");
	if(p1==NULL) return;
	len=p1-p2;
	if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
	strncpy(mail_info->sent_time,p2,len);
	mail_info->sent_time[len]=0;
	//create_dir(mail_info->save_path,"188",mail_info->from);
	//write_to_file(mail_info);
	int i;
	char *pend=NULL, *pstart=NULL;
	pend = mail_info->sent_time;
	for (i = 0; i < 5; i++) {
		pstart = strstr(pend, ",");
		if (pstart == NULL)
			break;
		switch (i) {
		case 0:
			*pstart = '-';
			break;
		case 1:
			*pstart = '-';
			{
				char *p = pstart - 1;
				(*p)++;
				if (*p > '9') {
					*p-=10;
                    memmove(p, p+1, MAX_TIME_LEN - (p - mail_info->sent_time + 1) - 1); 
                    *p = 1;
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


}
int analyse_188_recive_up(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *ptcp,int is_b_s)
{
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq;
	int len;
	int range;
	char *p1=NULL,*p2=NULL,*p=NULL;
	if(is_b_s && mail_info->connect_id[0]=='\0'){
		p1=strstr(data,"<string name=\"id\">");
		if(p1==NULL) return -2;
		p1+=18;
		p2=strstr(p1,"</string>");
		if(p2==NULL) return -1;
		len=p2-p1;
		if(len>MAX_ID_LEN) return -1;
		strncpy(mail_info->connect_id,p1,len);
		mail_info->connect_id[len]=0;
    }else if(!is_b_s){
		if(!strncmp(data,"HTTP/1.",7)){
            mail_info->recive_length=get_http_length(data);
			if(mail_info->recive_length<=0){
				return -1;
			}
			mail_info->recive_length+=20;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){
				return -1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL){
				return -1;
			}
			p+=4;
			len=datalen-(p-data);
			mail_info->http_seq = seq+p-data;
			if(len<0||mail_info->recive_length<len){
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			memcpy(mail_info->recive_data,p,len);
			if(strstr(data+datalen-5,"}}")){
				mail_info->is_complished =1;
				write_188_recive_up(mail_info);
			}
		}else if(mail_info->recive_data!=NULL){
			off_seq = seq-mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(strstr(data+datalen-5,"}}")){
				mail_info->is_complished = 1;
				write_188_recive_up(mail_info);
			}
		}
	}
}
int write_188_recive_down(Mail_info *mail_info)
{
	//char  *tmp_str=NULL;
	int len;
	Mail_info *mail_org=NULL;
	if(mail_info->connect_id[0]=='\0') return -1;
	mail_org=find_mail_head(mail_info->connect_id,mail_info);
	if(mail_org==NULL) return -1;
	mail_info->content=clear_html_tag(mail_info->recive_data);
	len=mail_info->recive_length*3/2+1;
	mail_org->content=(char *)malloc(len);
	if(mail_org->content!=NULL){
		memset(mail_org->content,0,len);
		code_convert("gb18030","utf-8",mail_info->content,strlen(mail_info->content),mail_org->content,len);
	}

	create_dir(mail_org->save_path,"188",mail_org->from);
	write_to_file(mail_org);
	delete_mail_info(mail_org);
	
	return 0;
}
int analyse_188_recive_down(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *ptcp ,int is_b_s)
{
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq;
	int len;
	int range;
	char *p1=NULL,*p2=NULL;
	char *p=NULL;
	if(is_b_s && mail_info->connect_id[0]=='\0'){
		p1=strstr(data,"&mid=");
		if(p1==NULL) return -2;
		p1+=5;
		p2=strstr(p1,"&filterLinks");
		if(p2==NULL) return -1;
		len=p2-p1;
		if(len>MAX_ID_LEN) return -1;
		strncpy(mail_info->connect_id,p1,len);
		mail_info->connect_id[len]='\0';
	 }else if(!is_b_s){
		 if(!strncmp(data,"HTTP/1.",7)){
			 mail_info->recive_length=get_http_length(data);
			 if(mail_info->recive_length<=0){
				 return -1;
			 }
			 mail_info->recive_length+=20;
			 mail_info->recive_data=(char *)malloc(mail_info->recive_length);
			 if(mail_info->recive_data==NULL){
				 return -1;
			 }
			 p=strstr(data,"\r\n\r\n");
			 if(p==NULL){
				 return -1;
			 }
			 p+=4;
			 len=datalen-(p-data);
			 mail_info->http_seq = seq+p-data;
			 if(len>mail_info->recive_length){
				 return -1;
			 }
			 memset(mail_info->recive_data,0,mail_info->mail_length);
			 memcpy(mail_info->recive_data,p,len);
			 if(strstr(data+datalen-6,"\r\n\r\n")){
				 write_188_recive_down(mail_info);
				 del_mail_node(mail_info);
			 }
		 }else if(mail_info->recive_data !=NULL){
			 off_seq=seq-mail_info->http_seq;
			 range=off_seq+datalen;
			 if(range>mail_info->recive_length){
				 return -1;
			 }
			 memcpy(mail_info->recive_data+off_seq,data,datalen);
			 if(strstr(data+datalen-6,"\r\n\r\n")){
				 write_188_recive_down(mail_info);
				 del_mail_node(mail_info);
			 }
		 }
	}
}
int analyse_188(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned short type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
			case 0x01:
				result = analyse_188_passwd(mail_info, data, data_len, ptcp, is_to_s);  //login form hao123
				break;
    		case 0x31:
		    	result = analyse_188_recive_up(mail_info,data,data_len,ptcp,is_to_s);
				break;
			case 0x41:
				result = analyse_188_recive_down(mail_info,data,data_len,ptcp,is_to_s);
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
	}

	return 0;
}
	
