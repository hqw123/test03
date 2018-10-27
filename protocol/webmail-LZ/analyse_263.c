#include "common.h"

int get_263_boundary(char *src,char *boundary)
{
	char *p1=NULL;
	char *p2=NULL;
	int  boun_len;
	p1=strstr(src,"; boundary=");
	if(p1==NULL) return -1;
	p1 += 11;
	p2 = strstr(p1,"\r\n");
	if(!p2) return -1;
	boun_len=p2-p1;
	if(boun_len>=MAX_BOUN_LEN &&boun_len <=0)  return -1;
	memcpy(boundary,p1,boun_len);
	boundary[boun_len]=0;
	return boun_len;
}


void writefile263(Mail_info *mail_info)
{
    Attach_info *attach_info;
	char  boundary[MAX_BOUN_LEN];
	char  *p1=NULL, *p2=NULL;
	int  len;
	int  boun_len;
	int  result;
   //	char attach_tag[200];
	char filepath[MAX_PATH_LEN];
	char filename[MAX_FN_LEN];
	Attachment *attachment;
    mode_t file_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	int  fd;
	int  n, i=0;
	int  flag =0;
	boun_len = get_263_boundary(mail_info->mail_data,boundary);
	if(boun_len == -1){
		return;
	}
	p1=strstr(mail_info->mail_data,"name=\"usr\"\r\n\r\n");
    if(p1 == NULL) return;
	p1+=14;
	p2 = strstr(p1,boundary);
    if(!p2) return;
	p2-=4;
	len = p2-p1;
	if(len>=MAX_FROM_LEN&&len<=0) return ;
	memset(mail_info->from,0,MAX_FROM_LEN);
	memcpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	strcat(mail_info->from,"@263.net");
	p2+=boun_len;

	p1 =strstr(p2,"name=\"to\"\r\n\r\n");
    if(p1 ==NULL) return;
	p1+=13;
    p2 = strstr(p1,boundary);
	if(p2 ==NULL) return ;
	p2-=4;
	len = p2-p1;
	if(len>=MAX_TO_LEN&&len<=0) return ;
	memcpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	p2+=boun_len;

	////---------------cc-----------------//
	p1=strstr(p2,"name=\"cc\"\r\n\r\n");
	if(p1==NULL) return;
	p1+=13;
	p2 = strstr(p1,boundary);
	if(p2 ==NULL) return;
	p2-=4;
	len =p2 -p1;
	memset(mail_info->cc,0,MAX_CC_LEN);
	if(len>=MAX_CC_LEN&&len<0) return;
    if(len!=0){
		memcpy(mail_info->cc,p1,len);
		mail_info->cc[len]=0;
	}
	p2+=boun_len;
	// ---------------bcc-----------------//
	p1=strstr(p2,"name=\"bcc\"\r\n\r\n");
	if(p2==NULL) return;
	p1+=13;
	p2=strstr(p1,boundary);
	if(p2==NULL) return;
	p2-=4;
	len=p2-p1;
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	if(len>=MAX_BCC_LEN &&len<0) return;
	if(len!=0){
		memcpy(mail_info->bcc,p1,len);
		mail_info->bcc[len]=0;
	}
	p2+=boun_len;
	//////////////////////

	p1 =strstr(p2,"name=\"subject\"\r\n\r\n");
    if(p1 ==NULL) return;
	p1+=18;
	p2 = strstr(p1,boundary);
	if(p2 ==NULL) return;
	p2-=4;
	len =p2-p1;
	if(len>=MAX_SUBJ_LEN&&len<=0) return;
	memset(mail_info->subject,0,MAX_SUBJ_LEN);
	memcpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	p2+=boun_len;
	///////////
	/*char *subject_tmp=NULL;
	subject_tmp=conv_xml_symbol(mail_info->subject);
	if(subject_tmp ==NULL) return;
    len=strlen(subject_tmp);
    if(len>MAX_SUBJ_LEN) subject_tmp[MAX_SUBJ_LEN]=0;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	//////////
	p1=p2;

	create_dir(mail_info->save_path,"263",mail_info->from);
	//chdir(mail_info->save_path);

	while(1){
		p2=strstr(p1,"; filename=\"");
		if(p2==NULL) break;
		p1=p2;
		p1+=12;
		if(*p1=='\"')  continue;
		p2=strstr(p1,"\"\r\n");
		if(!p2) break;
		i++;
		Attachment *attachment=(Attachment *)malloc(sizeof(Attachment));
		attachment->next=NULL;
		if(!flag){
			mail_info->attach=attachment;
			flag=1;
		}else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next=attachment;
		}
		memcpy(attachment->path_of_sender,p1,p2-p1);
		attachment->path_of_sender[p2-p1]=0;
		get_file_name(attachment->path_of_sender,filename);
		sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
		p1=strstr(p1,"\r\n\r\n");
		if(!p1) break;
		p1+=4;
		unsigned int n=mail_info->mail_length-(p1-mail_info->mail_data);
		p2 = memfind(p1,"Content-Disposition",n);
		if(p2==NULL)  return;
		char str[MAX_PATH_LEN];
		sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
		fd = open(str,O_RDWR|O_CREAT,file_mode);
		write(fd,p1,p2-p1);
		close(fd);
		trim_attach(str,45);
		p1=p2;
	}
	mail_info->num_of_attach = i;
	//regcompile_2(p1,patterncontent,&mail_info->content);
	if(p1==NULL) return;
	p2= strstr(p1,"name=\"text\"\r\n\r\n");
	if(p2==NULL) return;
	p2+=15;
	p1 = strstr(p2,boundary);
	if(p1==NULL)  return;
	p1 -=4;
	len =p1-p2;
	mail_info->content = (char *)malloc(len+1);
	memcpy(mail_info->content,p2,len);
	mail_info->content[len]=0;   
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	write_to_file(mail_info);
}


int analyse_263_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int range;
	char http_ok_head[18]= "HTTP/1.0 200 OK\r\n";
    if(is_b_s){
		if(!mail_info->is_complished){
			if(mail_info->mail_length ==0){
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data == NULL)
				{
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length==5000){
				int len;
				char *tmp; 
				len = get_http_length(data);
				if(len>0) {
					mail_info->mail_length +=len;
					tmp = (char *)malloc((size_t)mail_info->mail_length);
					if(tmp==NULL)
					{
						return -1;
					}
					memset(tmp ,0, mail_info->mail_length);
					memcpy(tmp,mail_info->mail_data,5000);
					free(mail_info->mail_data);
					mail_info->mail_data = tmp;
				}
			}
			off_seq = seq -mail_info->start_seq;
			range=off_seq+datalen;
			if(range>mail_info->mail_length)
			{
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
		}
	} else if(!strncmp(data,http_ok_head,15)){
		get_time(data,mail_info->sent_time);
		mail_info->is_complished =1;
		writefile263(mail_info);
		del_mail_node(mail_info);
	}

	return 0;
}

void write_263_psword(Mail_info *mail_info)
{
	char *p1, *p2;
//	char username[MAX_UN_LEN],passwd[MAX_PW_LEN];
	int  range;
	p1 = mail_info->mail_data;
    p1 = strstr(p1,"\r\n\r\nusr=");
	if(p1){  //mail.263.net
		p1 += 8 ;
		p2 = strstr(p1,"&");
		if(!p2) return;
		range = p2- p1;
		if (range>=MAX_UN_LEN-8 && range <=0)  return;
		strncpy(mail_info->username,p1,range);
		mail_info->username[range]=0;
		strcat(mail_info->username,"@263.net");
		p1=p2;
		p1=strstr(p1,"&pass=");
		if(!p1) return;
		p1+=6;
		p2 = strstr(p1,"&");
		if(!p2) return ;
		range = p2 - p1;
		if( range >=MAX_PW_LEN && range <=0) return ;
		strncpy(mail_info->passwd,p1,range);
		mail_info->passwd[range]=0;
	}else if(p1 =strstr(mail_info->mail_data,"\r\n\r\nfunc=")){
	    p1 = strstr(p1,"&usr=");
		if(!p1) return;
		p1 += 5;
		p2 = strstr(p1,"&sel_domain");
		if(p2){ //www263net
			range = p2 - p1;
			if(range>=MAX_UN_LEN-8 && range <=0 ) return;
			strncpy(mail_info->username,p1,range);
			mail_info->username[range]=0;
			strcat(mail_info->username,"@263.net");
			p1 = p2;
			p1 = strstr(p1,"&pass=");
			if(!p1) return;
			p1 +=6;
			p2 = strstr(p1,"&");
			if(!p2) return;
			range = p2 -p1;
			if(range >= MAX_PW_LEN && range <=0) return;
			strncpy(mail_info->passwd,p1,range);
			mail_info->passwd[range]=0;
		}else{  //www263com
			p2 = strstr(p1,"&domain=");
			if(!p2) return;
			range = p2 -p1;
			if(range>=MAX_UN_LEN-8 && range <=0) return;
			strncpy(mail_info->username,p1,p2-p1);
			mail_info->username[p2-p1]=0;
            strcat(mail_info->username,"@263.net");
			p1=p2;
			p1 = strstr(p1,"&pass=");
			p1+=6;
			strcpy(mail_info->passwd,p1);
        }
	}
	htmldecode_full(mail_info->passwd,mail_info->passwd);
	write_xml(mail_info);

	FILE *fp;
    char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	//chdir(mail_data_path);
	fp= fopen(passpath,"a+");
	if(fp == NULL) return;
	fprintf(fp,"\nusrname=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);
}

int analyse_263_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_to_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = seq - mail_info->start_seq;
	int range;
	char http_ok_head[11]= "HTTP/1.0 ";
	if(is_to_s){
		if(!mail_info->is_complished){
			if(mail_info->mail_length == 0){
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data==NULL)
				{
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000){
				int len;
				char *tmp;
				len = get_http_length(data);
				if(len > 0) {
					mail_info->mail_length += len;
					tmp = (char *)malloc((size_t)mail_info->mail_length);
					if(tmp == NULL)
					{
						return -1;
					}
					memset(tmp,0,mail_info->mail_length);
					memcpy(tmp,mail_info->mail_data,5000);
					free(mail_info->mail_data);
					mail_info->mail_data =tmp;
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
	} else if (!strncmp(data,http_ok_head,9)){
		mail_info->is_complished = 1;
		write_263_psword(mail_info);
		return -1;
	}

	return 0;
}
int write_263recive_file(Mail_info *mail_info)
{
	char *data_1 = NULL;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL;
	int len = 0;
    int result = -1;
    
	result = decomp_gzip_1(mail_info->mail_data,mail_info->mail_length-3,&data_1);
	//printf("data_1=%s\n",data_1);
	if (result == -1 || data_1 == NULL) 
        return -1;
    
	p1=strstr(data_1," mid=\"");
	if(p1==NULL) {
		free(data_1);
		return -1;
	}
	p1+=6;
	p2=strstr(p1,"\" ");
	if(p2==NULL){
		free(data_1);
		return -1;
	}
	len=p2-p1;
	if(len>MAX_ID_LEN) {
		free(data_1);
		return -1;
	}
	strncpy(mail_info->connect_id,p1,len);
	mail_info->connect_id[len]=0;

	p1=strstr(p2,"from=");
	if(p1==NULL) {
		free(data_1);
		return  -1;
	}
	p1+=6;
	p2=strstr(p1," to=");
	if(p2==NULL) {
		free(data_1);
		return -1;
	}
	len = p2-p1-1;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_from(mail_info->from);

	p1=p2;
	p1+=4;
    p2=strstr(p1," subject=");
    if(p2==NULL){
        free(data_1);
        return -1;
    }
	p3=strstr(p1," cc=");
	if(p3&&p3<p2){
		p3+=5;
		 len=p2-p3;
		 if(len>MAX_CC_LEN) len=MAX_CC_LEN;
		 strncpy(mail_info->cc,p3,len);
		 mail_info->cc[len]=0;
	
	}
    if(p3){
        len=p3-p1-5;
    }else{
        len = p2 -p1;
    }
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;

	
	p1=strstr(p2," charset=");
	if(p1==NULL){
		free(data_1);
		return -1;
	}
	p2+=9;
	len=p1-p2;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p2,len);
	mail_info->subject[len]=0;

	p1=strstr(p2,"fromtime=\"");
	if(p1==NULL){
		free(data_1);
		return -1;
	}
	p1+=10;
	p2=strstr(p1,"\" ");
	if(p2==NULL) {
		free(data_1);
		return -1;
	}
	len=p2-p1;
	if(len>MAX_TIME_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->sent_time,p1,len);
	mail_info->sent_time[len]=0;
    
    free(data_1);

	//create_dir(mail_info->save_path,"263",mail_info->from);
	//write_to_file(mail_info);
}
int analyse_263_recive_up(Mail_info *mail_info, char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
    unsigned int seq = ntohl(tcp->seq);
    int off_seq = seq - mail_info->start_seq;
    int range = 0;
    int len = 0;
    char *p = NULL;
    if (!is_b_s)
    {
        if (!strncmp(data, "HTTP/1.", 7))
        {
            len = get_http_length(data);
            if(len <= 0)
            {
                return -1;
            }
            
            mail_info->mail_length = len + 1;
            mail_info->mail_data = (char *)malloc(mail_info->mail_length);
            if(mail_info->mail_data == NULL)
            {
                return -1;
            }
            
            memset(mail_info->mail_data, 0, mail_info->mail_length);
            p = strstr(data,"\r\n\r\n");
            if(p == NULL)
            {
                return -1;
            }
            
            p += 4;
            mail_info->start_seq = seq+p-data;
            len = datalen - (p - data);
            if(len < 0 || mail_info->mail_length < len)
            {
                return -1;
            }
            
            memcpy(mail_info->mail_data,p,len);
            if(!memcmp(data + datalen - 2, "\0\0", 2))
            {
                mail_info->is_complished =1;
                write_263recive_file(mail_info);
            }			
        }
        else if (mail_info->mail_data != NULL)
        {
            off_seq = seq -mail_info->start_seq;
            range = off_seq + datalen;
            if (range > mail_info->mail_length)
            {
                return -1;
            }
            
            memcpy(mail_info->mail_data + off_seq, data, datalen);
            if(!memcmp(data + datalen - 2, "\0\0", 2))
            {
                mail_info->is_complished = 1;
                write_263recive_file(mail_info);
            }
        }		 
    }
    
	return 0;
}
int write_263recive_file_down(Mail_info *mail_info)
{
	Mail_info *mail_org=NULL;
	char *ungzip = NULL;
	char *p1 = NULL, *p2 = NULL;
	int len = 0;
	int flag = 0;
    
	if(mail_info->is_proce_mail == 1)
    {
		decomp_gzip_1(mail_info->recive_data,mail_info->mail_length-3, &mail_info->mail_data);
	    if(mail_info->mail_data == NULL)
            return -1;
		ungzip = mail_info->mail_data;
	}
    else
    {
		ungzip = mail_info->recive_data;
	}
	//printf("ungzip=%s\n",ungzip);
	if(ungzip==NULL) return -1;

	len=strlen(ungzip);
	if(len<=0)  return -1;
    if(strstr(ungzip+len-30,"</noframes>")) return -1;
    mail_info->connect_id[35]=0;
	if(mail_info->connect_id[0]=='\0') return -1;
	mail_org=find_mail_head(mail_info->connect_id,mail_info);
	if(mail_org==NULL) return -1;
    mail_org->recive_data =(char *)malloc(len+1);
	if(mail_org->recive_data !=NULL) {
		memset(mail_org->recive_data,0,len+1);
		memcpy(mail_org->recive_data,ungzip,len);
		if(p1=strstr(mail_org->recive_data,"charset"))
		{
			p1+=8;
			if(!strncmp(p1,"utf-8",5)||!strncmp(p1,"UTF-8",5))
				flag=0;
            else
                flag=1;

		}
		mail_info->content=clear_html_tag(mail_org->recive_data);
		if(flag==0){
           mail_org->content=mail_info->content;
           mail_info->content=NULL;
		}else{
			len=strlen(mail_info->content);
			if(len>0){
		    	len=len*3/2+1;
		    	mail_org->content=(char *)malloc(len);
		    	if(mail_org->content !=NULL)
		    	code_convert("gb18030","utf-8",mail_info->content,strlen(mail_info->content),mail_org->content,len);
			}
		}
	}
	create_dir(mail_org->save_path,"263",mail_org->from);
	write_to_file(mail_org);
	delete_mail_info(mail_org);
	
	return 0;
}
int analyse_263_recive_down(Mail_info *mail_info, char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = 0;
	int range;
	int len;
	char *p1=NULL,*p2=NULL ;
	char *p=NULL;
	if(is_b_s && mail_info->connect_id[0]=='\0'){
		p1=strstr(data,"&mid=");
		if(p1==NULL)
			return -1;
	    p1+=5;
		p2=strstr(data," HTTP/1.1");
		if(p2==NULL)
			return -1;
	    len=p2-p1;
		if(len>MAX_ID_LEN)
			return -1;
		strncpy(mail_info->connect_id,p1,len);
		mail_info->connect_id[len]=0;
       //printf("%s\n",mail_info->connect_id);
	}else if(!is_b_s){
		if(!strncmp(data,"HTTP/1.0 ",9)){
			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length <=0){
				return -1;
			}
			mail_info->recive_length +=1;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){
				return -1;
			}
			p=strstr(data,"Content-Encoding: gzip");
			if(p==NULL){
				mail_info->is_proce_mail = 0;
			}else{
				mail_info->is_proce_mail = 1;
			}
			p=strstr(data,"\r\n\r\n");
			if(p==NULL){
				return -1;
			}
			p+=4;
			len = datalen-(p-data);
			mail_info->http_seq = seq+p-data;
			if(len<0 ||mail_info->recive_length <len) {
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			memcpy(mail_info->recive_data,p,len);
			if(!memcmp(data+datalen-2,"\0\0",2)||!memcmp(data+datalen-8,"</html>",7)){
				write_263recive_file_down(mail_info);
				del_mail_node(mail_info);
			}
		}else if(mail_info->recive_data !=NULL){
			off_seq = seq -mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-2,"\0\0",2)||!memcmp(data+datalen-8,"</html>",7)){
				write_263recive_file_down(mail_info);
				del_mail_node(mail_info);
			}
		}
	}
	return 0; 
}
void analyse_263(void *tmp,char *data, unsigned int datalen,struct tcphdr *tcp, int is_b_s,int mora)
{
	Mail_info *mail_info;
	unsigned int lowtype;
	int result = 0;
	if(!mora)
	{
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype&0x00ff;
		switch(lowtype)
		{
			case 0x01:
				result = analyse_263_content(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x02:
				result = analyse_263_psword(mail_info,data,datalen,tcp,is_b_s);
				break;
		    case 0x31:
				result = analyse_263_recive_up(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x32:
				result = analyse_263_recive_down(mail_info,data,datalen,tcp,is_b_s);
				break;
			default:
				break;
		}

		if (result == -1)
		{
			delete_mail_info(mail_info);
		}
	}
}
