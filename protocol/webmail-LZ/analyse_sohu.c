
#include <regex.h>

#include "common.h"
#include "PacketParser.h"

#define MAX_MAIL_ATTACH_SOHU 10
static Mail_info *mail_info_sohu_attach[MAX_MAIL_ATTACH_SOHU+1];//store the attach information
int sohu_attach_number = 0;
int writefile_sohu_add(Mail_info *mail_info);//lihan add

#if 0
int clear_sohu_tag(char *str)
{
	char *head=NULL,*end=NULL;
	char A,B,C,D;
	char x,y,z;
	char u1=0x0e;
	char u2=0x80;
	if(str==NULL) return;
	head=str;
	end=head;
	while(*head!='\0'){
		if(*head=='\\'&&*(head+1)=='u'){
		        if(*(head+2)=='0' && *(head+3)=='0')
		            {
		              head+=6;
		              continue;
		            }
			A=chartoint(*(head+2));
			B=chartoint(*(head+3));
			C=chartoint(*(head+4));
			D=chartoint(*(head+5));
			x=(u1<<4)|A;
			y=u2 | (B<<2) |(C>>2);
			z=u2 | ((C&0x03)<<4) |D;
			*(end++)=x;
			*(end++)=y;
			*(end++)=z;
			head+=6;
			continue;
		}else{
			if(end<head) *end=*head;
			end++;
			head++;
		}
	}
	*end='\0';

}

#endif

void sjs(char * data)
{
	int num = 0;
	char * i,* j, str[256], res[64][256];
	i = strstr(data, "n=\"");
	while(i)
	{
		i += 3;
		j = strstr(i, "\"");
		int len = j - i;
		if (*(i - 5) == 'd')
		{
			memset(str, 0, 256);
			strncat(str, i, len);
			str[len] = '\0';
		}
		else
		if (*(i - 5) == 'c')
		{
			memset(res[num], 0, 256);
			strncat(res[num], i, len);
			res[num][len] = '\0';
			strcat(res[num], "@");
			strcat(res[num], str);
			num++;
		}
		i = strstr(i, "n=\"");
	}
}

char *sohu_conv_to_utf8(char *src)
{
	char *tmp_str = NULL;
	char *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	tmp_str = (char *)malloc(len + 1);
	if (NULL == tmp_str)
		return NULL;
	htmldecode_full(src, tmp_str);

	return tmp_str;
}

int sohu_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL, *tmp2 = NULL;
	size_t len;

	tmp1 = sohu_conv_to_utf8(str);
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
	tmp2 = NULL;
	
	return 0;
}

int get_sohu_from(char *data, char *mail_from)
{
	char *p1 = NULL, *p2 = NULL;
	size_t len;

	p1 = strstr(data, "SOHUID");
	if(p1 != NULL) {
		p1 += 11;
		p2 = p1;
		len = 0;
		while(*p2 != '|') {
			p2++;
			len++;
			if(len == MAX_FROM_LEN - 10 || *p2 == 0) 
				return -1;
		}
		memcpy(mail_from, p1, len);
		mail_from[len] = 0;
		strcat(mail_from, "@sohu.com");
	} else {
		p1 = strstr(data, "; VIPID=");
		if (p1 == NULL)
			return -1;
		p1 = strstr(p1, "|");
		if (p1 == NULL)
			return -1;
		p1++;
		p2 = strstr(p1, "|");
		if (p2 == NULL)
			return -1;
		len = p2 - p1;
		if (len > MAX_FROM_LEN)
			return -1;
		memcpy(mail_from, p1, len);
		mail_from[len] = 0;
	}
}

int writefile_sohu(Mail_info *mail_info)
{
	char *tmp = (char *)malloc(mail_info->mail_length * sizeof(char));
	char *p1 = NULL, *p2 = NULL;
	int result;
	size_t len;
	Attach_info *attach_info = NULL;
	char ID[MAX_ID_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char *tmp_str, *attach_data;
	int flag = 0;
	int i = 0;
   
	//get_sohu_from(mail_info->mail_data, mail_info->from);//有问题，建议直接从mail_info->mail_data寻找
	//lihan add from, "from":"12343592<12343592@163.com>"
	p1 = strstr(mail_info->mail_data, "from\":\"");
	if (p1 == NULL)
		return -1;

	p1 += 16;
	p2 = strstr(p1, ">");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->to[len] = 0;

	//"subject":"lihanzhuti呵呵","receipt":"","from":"12343592<12343592@163.com>"
	p1 = strstr(mail_info->mail_data, "subject\":\"");
	if (p1 == NULL)
		return -1;

	p1 += 10;
	p2 = strstr(p1, "\"");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	//{"to":["<ppag25938c86dc20@sohu.com>"]
	p1 = strstr(mail_info->mail_data, "to\":[\"<");
	if (p1 == NULL)
		return -1;

	p1 += 7;
	p2 = strstr(p1, ">");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	//"cc":["<2369501824@qq.com>"]
	if((p1 = strstr(mail_info->mail_data, "cc\":[\"<")) != NULL)
	{
	if (p1 != NULL) {
		p1 += 7;
		p2 = strstr(p1, ">");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} else {
			mail_info->cc[0] = 0;
		}
	    } else {
		mail_info->cc[0] = 0;
	   }
	}
	
	if((p1=strstr(mail_info->mail_data,"bcc\":[\"<"))!=NULL)
    {
	  if (p1 != NULL) 
	  {
		p1 += 8;
		p2 = strstr(p1, ">");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} else {
			mail_info->bcc[0] = 0;
		}
	} else {
		mail_info->bcc[0] = 0;
	}
  }
	
	//"content":"ihanzhengwen......呵呵2369501824"
	if((p1=strstr(mail_info->mail_data,"content\":"))!=NULL)
    {
		if (p1 == NULL)
			return -1;

		p1 += 10;
		p2 = strstr(p1, "\"");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		mail_info->content = (char *)malloc(len + 1);
		if (mail_info->content == NULL)
			return -1;
		memcpy(mail_info->content, p1, len);
		mail_info->content[len] = 0;
     }
	 
	create_dir(mail_info->save_path, "sohu", mail_info->from);
	while(1)
	{
		attach_info = find_attach_1(mail_info);
		if (attach_info == NULL)
		{
			break;
		}
        
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
			break;
        
		if(!flag)
		{
			mail_info->attach = attachment;
			attachment->next = NULL;
			flag = 1;
		}
		else
		{
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
        
		i++;
		get_file_name(attach_info->path_of_sender,filename);
		//sprintf(attachment->loc_filename, "attach%d_%s",i,filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		snprintf(writepath, MAX_PATH_LEN, "%s/%s",mail_info->save_path,attachment->loc_filename);
		link(attach_info->path_of_here,writepath);
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);	
	}
    
	mail_info->num_of_attach = i;
	result = sohu_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = sohu_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = sohu_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = sohu_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = sohu_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;
	write_to_file(mail_info);
	return 0;
}
		

int writefile_vip_sohu(Mail_info *mail_info)
{
	char *tmp = (char *)malloc(mail_info->mail_length * sizeof(char));
	char *p1 = NULL, *p2 = NULL;
	char ID[MAX_ID_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	Attach_info *attach_info;
	int flag = 0;
	int i = 0;
	char *tmp_str, *attach_data;
	int result;
	size_t len;

	get_sohu_from(mail_info->mail_data, mail_info->from);

	p1 = strstr(mail_info->mail_data, "&subject=");
	if (p1 == NULL)
		return -1;
	p1 += 9;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;

	p1 = strstr(p2, "&to=");
	if (p1 == NULL)
		return -1;
	p1 += 4;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	p1 = strstr(p2, "&cc=");
	if (p1 != NULL) {
		p1 += 4;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} else {
			mail_info->cc[0] = 0;
		}
	} else {
		mail_info->cc[0] = 0;
	}

	p1 = strstr(p2, "&bcc=");
	if (p1 != NULL) {
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 != NULL) {
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} else {
			mail_info->bcc[0] = 0;
		}
	} else {
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "&text=");
	if (p1 == NULL)
		return -1;
	p1 += 6;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL);
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;

	create_dir(mail_info->save_path, "sohu", mail_info->from);
	while(1)
	{
		attach_info = find_attach_1(mail_info);
		if (attach_info == NULL) 
            break;
        
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
            break;
        
		if(!flag)
		{
			mail_info->attach = attachment;
			attachment->next = NULL;
			flag = 1;
		}
		else
		{
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
        
		i++;
		get_file_name(attach_info->path_of_sender,filename);
		//sprintf(attachment->loc_filename, "attach%d_%s",i,filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		snprintf(writepath, MAX_PATH_LEN, "%s/%s",mail_info->save_path,attachment->loc_filename);
		link(attach_info->path_of_here,writepath);
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);	
	}
    
    mail_info->num_of_attach = i;
    
	result = sohu_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return i-1;
	result = sohu_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = sohu_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = sohu_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = sohu_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;
	write_to_file(mail_info);
	return 0;
}

int analyse_sohu_mail(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;
	char http_ok_head[18] = "HTTP/1.1 200 OK\r\n";
	int result;

	if (is_b_s)
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, tcp);
			return result;
		}
	}
	else if(!strncmp(data,http_ok_head, 15)) 
	{
	    char *p1 = mail_info->mail_data;
		char *host_p = NULL;
		char *p3 = NULL;

		if((p3=strstr(p1,"&stationery=&is_send=1"))!=NULL)//lihan add
	    {
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;

		host_p = strstr(mail_info->mail_data, "\r\nHost: ");
		if (host_p == NULL) {
			return -1;
		}
		if (memfind(host_p, "vip", 50) == NULL)
			writefile_sohu(mail_info);
		else
			writefile_vip_sohu(mail_info);
        
		del_mail_node(mail_info);
		return 0;
	 } 
	 else if ((p3=strstr(p1,"originId"))!=NULL)//lihan add   send(put) ...
	 {
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefile_sohu_add(mail_info);
		del_mail_node(mail_info);
		return 0;
	  }
	  else
		return -1;
	}	
	else 
	{
		return -1;
	}
}

int analyse_sohu_attach_head(Attach_info *attach_info, char *data, unsigned int datalen, unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "&filename=(.*)&verify_code=";
	char *p = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;

	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data,"filename=\"");
	if (p==NULL)
		return 0;
	p+=10;
	char * p2=strstr(p,"\"");
	int len=p2-p;
	attach_info->path_of_sender=(char*)malloc(len+1);
	memcpy(attach_info->path_of_sender,p,len);
	attach_info->path_of_sender[len]=0;
	p = strstr(p, "\r\n\r\n");
	if (p==NULL) {
		return 0;
	}

	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1
	/*result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);//2
	if (result == -1)
		return -1;*/
	gettimeofday(&tv, &tz);
    snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;

	write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; //4

	return 0;
}

int analyse_vip_sohu_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	char *p = NULL;
	char *p1 = NULL;
	char *p2 = NULL;
	struct timeval tv;
	struct timezone tz;
	Attach_info *attach_tmp = NULL;
	int off_seq;
	int result;
	size_t len;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int seek_pos;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data, "\r\n\r\n");
	if (p == NULL) {
		return 0;
	}
	p += 4;

	p1 = strstr(attach_info->ok_data, "resumeUpload?xid=");
	if (p == NULL)
		return -1;
	p1 += 17;
	p2 = strstr(p1, "&seek=");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_ID_LEN)
		return -1;
	memcpy(attach_info->ID_str, p1, len);
	p2 += 6;
	p1 = strstr(p2, " HTTP/1.1\r\n");
	if (p1 == NULL)
		return -1;
	*p1 = 0;
	seek_pos = atoi(p2);
	if (seek_pos < 0)
		return -1;
	if (seek_pos == 0) {
		attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1
		gettimeofday(&tv, &tz);
		snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
		fd = open(attach_info->path_of_here,O_RDWR | O_CREAT, file_mode);
		if (fd == -1)
			return -1;
		write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
		close(fd);
	} else {
		attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq - seek_pos;//1
		attach_tmp = attach_tab.head->next;
		while (attach_tmp != NULL) {
			if (attach_tmp != attach_info && !strcmp(attach_tmp->ID_str, attach_info->ID_str)) {
				del_attach_node(attach_tmp);
				break;
			} else {
				attach_tmp = attach_tmp->next;
			}
		}
		if (attach_tmp == NULL)
			return -1;
		strcpy(attach_info->path_of_here, attach_tmp->path_of_here);//3
		delete_attach(attach_tmp);
		lseek(fd, seek_pos, SEEK_SET);
		write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
		close(fd);
	}

	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing=1; //4

	return 0;
}

int analyse_sohu_attach(Attach_info *attach_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq =ntohl(tcp->seq);
	int result;

	if(is_b_s)
	{ //attach_body
		if (attach_info->is_writing)
		{
			result = write_to_attach(attach_info, data, datalen+47, seq);
		} 
		else
		{
			result = analyse_sohu_attach_head(attach_info,data,datalen,seq);
		}
		
		return result;
   } 
   else 
   if(!attach_info ->is_get_ok)
   {
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";

		if(!strncmp(data , http_ok_head ,17))
		{
			attach_info ->is_writing = 0;
			attach_info->is_get_ok = 1;
			//result = regcompile_1(data,"\"id\": \"(.*)\", \"filename\": ",attach_info->ID_str, MAX_ID_LEN);
			//if (result == -1) {
			//	return -1;
			//}
			trim_attach(attach_info->path_of_here, 47);
			attach_info->is_complished = 1;
			
			return 0;
		}
	}
	
	return -1;
}

///////////////////////////lihan add /////////
int writefile_sohu_add(Mail_info *mail_info)
{
	char *tmp = (char *)malloc(mail_info->mail_length * sizeof(char));
	char *p1 = NULL,*p2 = NULL;
	int result;
	size_t len;
	char ID[MAX_ID_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char *tmp_str, *attach_data;
	int flag = 0;
	int i = 0;

	p1 = strstr(mail_info->mail_data, "from\":\"");
	//"from":"<ppag25938c86dc20@sohu.com>"
	if (p1 == NULL)
		return -1;
	p1 += 8;
	p2 = strstr(p1, ">");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->to[len] = 0;
   
	//subject":"......:lihanzhuti......","
	p1 = strstr(mail_info->mail_data, "subject\":\"");
	if (p1 == NULL)
		return -1;
	p1 += 10;
	p2 = strstr(p1, "\"");
	if (p2 == NULL)
		return -1;
	len = p2 - p1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	//to":["12343592<
	p1 = strstr(mail_info->mail_data, "to\":[\"");
	if (p1 == NULL)
	{
		return -1;
	}
	p1 += 15;
	
	p2 = strstr(p1, ">");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	//cc":["<2369501824@qq.com>"]]
	if((p1 = strstr(mail_info->mail_data, "cc\":[\"<")) != NULL)
	{
		p1 += 7;
		p2 = strstr(p1, ">");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_CC_LEN)
				len = MAX_CC_LEN;
			memcpy(mail_info->cc, p1, len);
			mail_info->cc[len] = 0;
		} 
		else 
		{
			mail_info->cc[0] = 0;
		}
	}
	
	//bcc":["<lihan20002@sina.com>"]
	if((p1=strstr(mail_info->mail_data,"bcc\":")) != NULL)
    {
		p1 += 8;
		p2 = strstr(p1, ">");
		len = p2 - p1;
		if (p2 != NULL) 
		{
			if (len > MAX_BCC_LEN)
				len = MAX_BCC_LEN;
			memcpy(mail_info->bcc, p1, len);
			mail_info->bcc[len] = 0;
		} 
		else
		{
			mail_info->bcc[0] = 0;
		}
    }

	//"content":"<p><br/></p><p><br/></p><p><br/></p>lihanzhuti..v style=\"line-<br/> \n &nbsp;
	if((p1=strstr(mail_info->mail_data,"content\":"))!=NULL)
    {
		p1 += 10;
		p2 = strstr(p1, "&nbsp");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		mail_info->content = (char *)malloc(len + 1);
		if (mail_info->content == NULL)
			return -1;
		memcpy(mail_info->content, p1, len);
		mail_info->content[len] = 0;
    }
	create_dir(mail_info->save_path, "sohu", mail_info->from);
	
	///* add affixflag infomation    lihan 2017.3.22
	Attach_info *attach_tmp;
	Attachment *attachment;
	Attach_info *attach_info = attach_tab.head->next;
	     
	while (attach_info != NULL) 
	{
		if (!strcmp(attach_info->ID_str, mail_info->mail_id))
		{
			i++;
			get_file_name(attach_info->path_of_sender, filename);
			attachment = (Attachment *)malloc(sizeof(Attachment));
			
			if (attachment == NULL)
			{	
				return -1;
			}

			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			if (!flag ) 
			{
				attachment->next = NULL;
				mail_info->attach = attachment;
				flag++;
			} 
			else 
			{
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);
			
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
	
	mail_info->num_of_attach = i;//lihan add 2017.3.24*/
	write_to_file(mail_info);
	
	return 0;
}

int analyse_sohu_attach_2(Attach_info *attach_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq =ntohl(tcp->seq);
	int result;

	if(is_b_s)
	{
		if(attach_info->recive_length==0)
		{
			int len = get_http_length(data);
			if(len == 0) 
                return 0;
			
			char *p = strstr(data,"\r\n\r\n");
			if(!p) 
                return -1;
            
			p += 4;
	
			if((len + 1) > attach_info->ok_len)
			{
				char * t = (char*)realloc(attach_info->ok_data, len + 1);
				if(t == NULL)
				{
					return -1;
				}
				attach_info->ok_data = t;
			}
			
			attach_info->ok_data[len] = 0;
			attach_info->http_seq = seq + (p - data);
			attach_info->recive_length = len;
			memcpy(attach_info->ok_data, p, datalen-(p-data));
		}
		else
		{
			if(seq<attach_info->http_seq) return 0;
			//printf("hello\n");
			//printf(attach_info->ok_data);
			if(datalen+seq-attach_info->http_seq>attach_info->recive_length)
			{
				//printf("errorrrrr\n");
				return -1;
			}
			else
			{
			//printf("memcpy--\n");
				memcpy(attach_info->ok_data+(seq-attach_info->http_seq),data,datalen);
			//	printf(attach_info->ok_data);
			}
		}
		
		return 0;
   	} 
   	else 
   	{
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";

		if(!strncmp(data , http_ok_head ,17))
		{ 
		    memcpy(attach_info->ok_data, data, datalen);
			/*attach_info ->is_writing = 0;
			attach_info->is_get_ok = 1;
			//result = regcompile_1(data,"\"id\": \"(.*)\", \"filename\": ",attach_info->ID_str, MAX_ID_LEN);
			//if (result == -1) {
			//	return -1;
			//}
			trim_attach(attach_info->path_of_here, 47);*/
//			printf("sohu send attach down---\n");
			attach_info->is_complished = 1;
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
						
			char str_boundary[100];
			//front=attach_info->ok_data;
			front=data;
			back=strstr(front,"\r\n");
			memcpy(str_boundary,front,back-front);
			str_boundary[back-front]=0;
			
			memcpy(str_boundary,front,back-front);
			str_boundary[back-front]=0;
			
			front = strstr(back, "filename=");
			if(front == NULL)
			{
				return 0;
			}
			front += 10;
			back = strstr(front, "\"\r\n");
			
			if(back == NULL)
				return 0; 
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			attach_info->path_of_sender=(char*)malloc(len+1);
			attach_info->path_of_sender[len]=0;
			memcpy(attach_info->path_of_sender,front,len);

			char * last=memfind(back,str_boundary,attach_info->recive_length-(back-attach_info->ok_data));
			if(!last) return -1;
			
			last-=2;
			front=strstr(back,"\r\n\r\n");
			front+=4;
			
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",mail_temp_path, tv.tv_sec, tv.tv_usec);
			//char temp_name[MAX_PATH_LEN];
			//memset(temp_name, MAX_PATH_LEN, 0);
			//strcpy(temp_name, attach_info->attach_name);
			//temp_name[len] = '\0';

			fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
				return -1;
			write(fd, front, last-front);
			close(fd);
//			printf("downdowndown-------------\n");
			return 0;
		}
	}
	
	return 0;
}

int analyse_vip_sohu_attach(Attach_info *attach_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
   unsigned int seq =ntohl(tcp->seq);
   int result;

   if(is_b_s){ //attach_body
		if (attach_info->is_writing) {
			result = write_to_attach(attach_info, data, datalen, seq);
		} else {
			result = analyse_vip_sohu_attach_head(attach_info, data, datalen, seq);
		}
		return result;
   } else if(!attach_info ->is_get_ok) {
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";
		if(!strncmp(data , http_ok_head ,17)){ 
			attach_info ->is_writing = 0;
			attach_info->is_get_ok = 1;
			attach_info->is_complished = 1;
			return 0;
		}
	}
	return -1;
}

int analyse_sohu_delete(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;
	char http_ok_head[18] = "HTTP/1.1 200 OK\r\n";
	int result;

	if (is_b_s){
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, datalen, tcp);
			return result;
		}
	} else if(!strncmp(data, http_ok_head, 15)) {
		char ID[MAX_ID_LEN + 1];
		char *p1=mail_info->mail_data;

		mail_info->is_complished = 1;
		Attach_info  *attach_tmp = NULL;
		p1 = strstr(p1,"&_method=delete");
		if(p1 == NULL)
		  return -1;
		p1 -= 32;
		memcpy(ID, p1, 32);
		ID[32] = 0;
		attach_tmp = find_attach(ID);
		if(attach_tmp != NULL)
			delete_attach(attach_tmp);
		del_mail_node(mail_info);
		return 0;
	}
	return -1;
}

int analyse_vip_sohu_delete(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int off_seq;
	char *p1 = NULL, *p2 = NULL;
	char ID[MAX_ID_LEN + 1];
	Attach_info *attach_info;
	size_t len;

	if (is_b_s) {
		if (!mail_info->is_complished) {
			p1 = strstr(data, "?xid=");
			if (p1 == NULL) {
				return -1;
			}
			p1 += 5;
			p2 = strstr(p1, "&act=");
			if (p2 == NULL) {
				return -1;
			}
			if (strncmp(p2 + 5, "del", 3)) {
				return -1;
			}
			len = p2 - p1;
			if (len > MAX_ID_LEN)
				len = MAX_ID_LEN;
			memcpy(ID, p1, len);

			attach_info = find_attach(ID);
			if (attach_info == NULL) {
				return -1;
			}
			delete_attach(attach_info);

			del_mail_node(mail_info);
			return 0;
		}
	}
	return -1;
}

int analyse_sohu_passwd(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_to_s)
{
	char *p1 = NULL, *p2 = NULL;
	char tmp_name[MAX_UN_LEN + 1];
	size_t len;

	if (is_to_s) {
		p1 = strstr(data, "userid=");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 7;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 == NULL || len > MAX_UN_LEN) {
			return -1;
		}
		memcpy(tmp_name, p1, len);
		tmp_name[len] = 0;
		htmldecode_full(tmp_name, mail_info->username);

		p1 = strstr(p2, "&password=");
		if (p1 == NULL)
			return -1;
		p1 += 10;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 == NULL || len > MAX_PW_LEN) {
			return -1;
		}
		memcpy(mail_info->passwd, p1, len);
		mail_info->passwd[len] = 0;
		htmldecode_full(mail_info->passwd,mail_info->passwd);
		//LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
		write_xml(mail_info);
		
		FILE *fp = NULL;
		char writepath[MAX_PATH_LEN + 1];
		snprintf(writepath, MAX_PATH_LEN, "%s/pass.txt", mail_data_path);
		fp = fopen(writepath, "a+");
		if(fp == NULL)
			return -1;
		fprintf(fp,"\nusername=%s\npassword=%s\n", mail_info->username, mail_info->passwd);
		fclose(fp);

		del_mail_node(mail_info);
		return 0;
	} else {
		return -1;
	}
}

int analyse_sohu_vip_passwd(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_to_s)
{
	unsigned int seq = ntohl(tcp->seq);
	char *p1 = NULL, *p2 = NULL;
	size_t len, total_len;
	int off_seq;
	int result;

	if (is_to_s) {
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, datalen, tcp);
			return result;
		}
	} else if(!strncmp(data, "HTTP/1.1 302 Found",15)) {
	//	get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;

		p1 = strstr(mail_info->mail_data, "userid=");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 7;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 == NULL || len > MAX_UN_LEN) {
			return -1;
		}
		memcpy(mail_info->username, p1, len);
		mail_info->username[len] = 0;

		p1 = strstr(mail_info->mail_data, "&password=");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 10;
		p2 = strstr(p1, "&");  //???��?�没?? & 符�?��????��?��?��?尾�?
		if (p2 != NULL) {
			len = p2 - p1;
		} else {
			len = strlen(p1);
		}
		if (len > MAX_PW_LEN)
			return -1;
		memcpy(mail_info->passwd, p1, len);
		mail_info->passwd[len] = 0;
		htmldecode_full(mail_info->passwd,mail_info->passwd);

		write_xml(mail_info);

		FILE *fp = NULL;
		char writepath[MAX_PATH_LEN + 1];
		snprintf(writepath, MAX_PATH_LEN, "%s/pass.txt", mail_data_path);
		fp = fopen(writepath, "a+");
		if(fp == NULL)
			return -1;
		fprintf(fp,"\nusername=%s\npassword=%s\n", mail_info->username, mail_info->passwd);
		fclose(fp);

		del_mail_node(mail_info);
		return 0;
	} else {
		return -1;
	}
}

int analyse_sohu_passwd2(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_to_s)
{
	unsigned int seq = ntohl(tcp->seq);
	char *p1 = NULL, *p2 = NULL;
	size_t len, total_len;
	int off_seq;
	int result;

	if (is_to_s) {
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, datalen, tcp);
			return result;
		}
	} else if(!strncmp(data, "HTTP/1.1 302 Found",15)) {
	//	get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;

		p1 = strstr(mail_info->mail_data, "&username=");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 10;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 == NULL || len + 12 > MAX_UN_LEN) {
			return -1;
		}
		memcpy(mail_info->username, p1, len);
		mail_info->username[len] = 0;
		p1 = strstr(mail_info->mail_data, "&eru=");
		if (p1 == NULL) {
			return -1;
		}
		if (memfind(p1, "vip.sohu.com", 30) != NULL)
			strcat(mail_info->username, "@vip.sohu.com");
		else
			strcat(mail_info->username, "@sohu.com");

		p1 = strstr(mail_info->mail_data, "&passwd=");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 8;
		p2 = strstr(p1, "&");    //???��?�没?? & 符�?��????��?��?��?尾�?
		if (p2 != NULL)
			len = p2 - p1;
		else
			len = strlen(p1);
		if (len > MAX_PW_LEN) {
			return -1;
		}
		memcpy(mail_info->passwd, p1, len);
		mail_info->passwd[len] = 0;
		htmldecode_full(mail_info->passwd,mail_info->passwd);
		//LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
		write_xml(mail_info);

		FILE *fp = NULL;
		char writepath[MAX_PATH_LEN + 1];
		snprintf(writepath, MAX_PATH_LEN, "%s/pass.txt", mail_data_path);
		fp = fopen(writepath, "a+");
		if(fp == NULL)
			return -1;
		fprintf(fp,"\nusername=%s\npassword=%s\n", mail_info->username, mail_info->passwd);
		fclose(fp);

		del_mail_node(mail_info);
		return 0;
	} else {
		return -1;
	}
}
#if 0
int write_sohu_recive(Mail_info *mail_info)
{//this function is not right now!
	char *p1=NULL, *p2=NULL,*p3=NULL;
	int len;
	time_t timeint;
	struct tm *timestring=NULL;
	char tmp[50]={0};
	p1=strstr(mail_info->recive_data,"\"subject\": \"");
	if(p1==NULL) return;
	p1+=12;
	p2=strstr(p1,"\",");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	clear_tag(mail_info->subject);

	p1=strstr(p2,"\"date\": ");
	if(p1==NULL) return;
	p1+=8;
	p2=strstr(p1,", ");
	if(p2==NULL) return;
	len=p2-p1;
    if(len>MAX_TIME_LEN) return;
	strncpy(tmp,p1,len);
	tmp[len]=0;
	timeint=atoi(tmp);
	timestring=localtime(&timeint);
	strftime(mail_info->sent_time,MAX_TIME_LEN,"%Y-%m-%d %H:%M:%S",timestring);

	p1=strstr(p2,"\"sender\":");
	if(p1==NULL) return;
	p1+=9;
	p2=strstr(p1,"\"}, \"ccs\":");
	if(p2==NULL) return;
    p3=strstr(p1,"\"addr\": \"");
	if(p3!=NULL && p3<p2){
		p3+=9;
		len=p2-p3;
		if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
		strncpy(mail_info->from,p3,len);
		mail_info->from[len]=0;
		clear_from(mail_info->from);
	}
	//printf("111111111111111111111111111111111\n");
	p1=p2+10;
	p2=strstr(p1,"],");
	if(p2==NULL) return;
	*(p2++)='\0';
	while(p3=strstr(p1,"\"addr\": \"")){
		p3+=9;
		p1=strstr(p3,"\"}");
		if(p1){
			len=p1-p3;
			if(len>=50) len=48;
			strncpy(tmp,p3,len);
			tmp[len]=';';
			tmp[len+1]=0;
			len=strlen(mail_info->cc);
			if(MAX_CC_LEN-len>50)
			strcat(mail_info->cc,tmp);
		}
		p3=p1;
	}
//	printf("2222222222222222222222222222222222\n");
    p1=strstr(p2,"\"content\": ");
	if(p1==NULL) return;
	p1+=11;
	p2=strstr(p1,"\"bccs\":");
	if(p2==NULL) return;

    if(p3=strstr(p1,"<br><hr size=\\\"1\\\""))
	len=p3-p1;
    else
	len=p2-p1;

	mail_info->mail_data=(char *)malloc(len+1);
	if(mail_info->mail_data!=NULL){
		memset(mail_info->mail_data,0,len+1);
		memcpy(mail_info->mail_data,p1,len);
		clear_tag(mail_info->mail_data);
		mail_info->content=clear_html_tag(mail_info->mail_data);
	}
	
	p1=strstr(p2,"\"receiver\":");
	if(p1==NULL) return;
	p2=strstr(p1,"],");
	if(p2==NULL) return;
	while((p3=strstr(p1,"\"addr\": \"")) && p3<p2){
		p3+=9;
		p1=strstr(p3,"\"}");
		if(p1){
			len=p1-p3;
			if(len>=50) len=48;
			strncpy(tmp,p3,len);
			tmp[len]=';';
			tmp[len+1]=0;
			len=strlen(mail_info->to);
			if(MAX_TO_LEN-len>50)
			strcat(mail_info->to,tmp);
		}
		if(p1==p2) break;
		p3=p1;
	}
//	printf("sSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");

   create_dir(mail_info->save_path,"sohu",mail_info->from);
   write_to_file(mail_info);
}
 #endif

void write_sohu_recive_file(Mail_info *mail_info)
{
	char *p1=NULL, *p2=NULL, *p3=NULL;
	char tmp[50]={0};
	time_t timeint;
	int len;
	/*decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
	if(mail_info->mail_data==NULL) 
		return;*/
    
	//printf("%s\n", mail_info->mail_data);
    
	//here to add mid and sub_string.
	p1 = strstr(mail_info->mail_data,"\"mid\": \"");
	if (p1==NULL) 
		return;
	p1+=8;
	p2=strstr(p1,"\", \"content\"");
	if (p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_ID_LEN) len=MAX_ID_LEN;
	strncpy(mail_info->mail_id,p1,len);
	mail_info->mail_id[len]=0;
	
	/*memcpy(mail_info->mail_id, mail_info->mail_id + len - 64, 64);
	mail_info->mail_id[64] = '\0';*/
	
	//printf("mail_info->mail_id ********* : %s\n", mail_info->mail_id);
    
	//here to add sub_string id
	//get a sub_str for search
	char sub_search[21]="0";
	strncpy(sub_search,mail_info->mail_id,20);
	p1=p2;
	
	p1=strstr(p1,"\"attach\": [");
	if(p1==NULL) 
		return;
	p1+=11;
	if(*p1 != ']')
	{//have attachment
		//start to search sub_string id
		char *plimit;//limit the search scope
		plimit=strstr(p1,"]], \"folder\"");
		if(plimit==NULL) 
				return;
		p2=strstr(p1,sub_search);
		char tmp_str[MAX_ID_LEN]="0";
		unsigned int n;
		int length;
		while(p2)
		{
			//printf("----------------------\n");
			p1=p2;
			p2=strstr(p1,"\"]");
			if(p2==NULL) 
				return;
			len=p2-p1;
		
			char id[MAX_ID_LEN];
			memset(id, 0, MAX_ID_LEN);
			memcpy(id, p1, len);
			//printf("id : %s\n", id);
			id[len] = '\0';
			memcpy(id, id + len - 64, 64);
			id[64] = '\0';
			strncpy(tmp_str, id, 64);
		
			//strncpy(tmp_str, p1, len);
		
			length = strlen(mail_info->mail_id) + len + 2;
			if(length>MAX_ID_LEN)
				break;
			strcat(mail_info->mail_id,"|");
			strcat(mail_info->mail_id,tmp_str);
			n=plimit-p2;
			if (n<0) 
				return;
			p2 = memfind(p2, sub_search, n);
		} 
		p1 = plimit;
	}
    
	p1=strstr(p1,"\"cc\": [");
	if(p1==NULL) 
		return;
	p1+=7;
	p2=strstr(p1,"], \"message_id\":");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_CC_LEN) len=MAX_CC_LEN;
	strncpy(mail_info->cc,p1,len);
	mail_info->cc[len]=0;
    
	p1=strstr(p2,"\"bcc\": [");
	if(p1==NULL) 
		return;
	p1+=8;
	p2=strstr(p1,"],");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_BCC_LEN) len=MAX_BCC_LEN;
	strncpy(mail_info->bcc,p1,len);
	mail_info->bcc[len]=0;
    
	p1=strstr(mail_info->mail_data,"\"subject\": \"");
	if (p1==NULL) 
		return;
	p1+=12;
	p2=strstr(p1,"\",");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if (len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p1,len);
	mail_info->subject[len]=0;
	clear_tag(mail_info->subject);
    
	p1=strstr(p2,"\"from\":");
	if(p1==NULL) 
		return;
	p2=p1;
	p1=strstr(p2,", \"");
	if(p1==NULL) 
		return;
	p1+=3;
	p2=strstr(p1,"\"]]");
	if(p2==NULL) 
		return;
	len=p2-p1;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,p1,len);
	mail_info->from[len]=0;
	clear_from(mail_info->from);
    
	p1=strstr(p2,"\"to\": [");
	if(p1==NULL) 
			return;
	p1+=7;
	p2=strstr(p1,"],");
	if(p2==NULL) 
			return;
	len=p2-p1;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
    
	int flag_time=0;
	p1=strstr(p2,"\"date\": \"");
	if(p1==NULL) 
		return;
	p1+=9;
	p2 = strstr(p1," -");
	if(p2 == NULL) 
	{
		p2 = strstr(p1," +");
		if(p2==NULL)
			return;
		else 
			flag_time=8;
	}
	else 
		flag_time=7;
	len=p2-p1;
	if(len>MAX_TIME_LEN) 
		return;
	strncpy(tmp,p1,len);
	tmp[len]=0;
	struct tm time_struct, *tm_ptr;
	time_t timeval;
	strptime(tmp,"%a, %d %b %Y %H:%M:%S %Z",&time_struct);
	if (flag_time==7)
	{
		timeval=mktime(&time_struct)+15*3600;
	}
	else if(flag_time==8)
	{
		timeval=mktime(&time_struct);
	}
	tm_ptr=localtime(&timeval);
	sprintf(mail_info->sent_time, "%04d-%02d-%02d %02d:%02d:%02d",tm_ptr->tm_year+1900,
	tm_ptr->tm_mon+1,tm_ptr->tm_mday,tm_ptr->tm_hour,tm_ptr->tm_min,tm_ptr->tm_sec);
    
    //timeint=atoi(tmp);
    //struct tm *timestring=NULL;
    //timestring=localtime(&timeint);
    //strftime(mail_info->sent_time,MAX_TIME_LEN,"%Y-%m-%d-%H:%M:%S",timestring);   
    
	p1=strstr(p1,"\"display\": \"");
	if(p1==NULL) 
		return;
	p1+=12;
	p2=strstr(p1,"\"}");
	if(p2==NULL) 
	{
		p2=strstr(p1,"\", \"size\":");
		if (p2==NULL)
		return;
	}
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
    
	create_dir(mail_info->save_path,"sohu",mail_info->from);
	write_to_file(mail_info);
    
}
int analyse_sohu_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp, int is_b_s)
{
	//original function doesn't work well, so it is need to write new.
	unsigned int seq = ntohl(tcp->seq);
	int off_seq = 0;
	int result = 0;
	int range = 0;
	int len = 0;
	char *p = NULL;
	static int flag = -1;
    
	if (!is_b_s)
	{
		if(!strncmp(data,"HTTP/1.",7))
		{
			if(strstr(data, "Content-Encoding: gzip\r\n"))
				flag = 1;
			else
				flag = 0;

			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length<=0)
			{
				return -1;
			}
			mail_info->recive_length+=20;
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
			p=strstr(p,"\r\n");
			if(p==NULL)
			{
				return -1;
			}
			p+=2;
			mail_info->http_seq = seq+p-data;
			len=datalen-(p-data);
			if (len>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data,p,len);
			if (!memcmp(data+datalen-4,"\r\n\r\n",4))
			{
				if(flag)
				{
					decomp_gzip(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
				}
				else
				{
					mail_info->mail_data = (char *)malloc(mail_info->recive_length);
					memset(mail_info->mail_data,0,mail_info->recive_length);
					memcpy(mail_info->mail_data,mail_info->recive_data,mail_info->recive_length);
				}
				writefile_sohu(mail_info);//lihan add...................
				del_mail_node(mail_info);
				return 0;
			}
		}
		else if(mail_info->recive_data!=NULL)
		{
			off_seq=seq-mail_info->http_seq;
			range=off_seq+datalen;
			if (range>mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-4,"\r\n\r\n",4))
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
				write_sohu_recive_file(mail_info);
				del_mail_node(mail_info);
				return 0;
			}
		}
	}
	return 0;
}

#if 0
int analyse_sohu_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int range;
	char *p=NULL;
	if(!is_b_s){
         if(!strncmp(data,"HTTP/1.",7)){
			 mail_info->recive_length=50*1024;
			 mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			 if(mail_info->recive_data==NULL){
				 return -1;
			 }
			 memset(mail_info->recive_data,0,mail_info->recive_length);
			 mail_info->start_seq=seq;
		 }
		 if(mail_info->recive_data!=NULL){
			 off_seq=seq-mail_info->start_seq;
			 range=off_seq+datalen;
			 if(range>mail_info->recive_length){
				 return -1;
			 }
			 memcpy(mail_info->recive_data+off_seq,data,datalen);
			 if(!memcmp(data+datalen-5,"0\r\n\r\n",5)){
				 write_sohu_recive(mail_info);
				 del_mail_node(mail_info);
			 }
		 }
	}
}

#endif

int cov_utf8(char *str,int max_len)
{
	int len;
	int utf_len;

	char *dest=NULL;
    if(str==NULL) return -1;
	len=strlen(str);
	utf_len=len*3/2+1;
	dest=(char *)malloc(utf_len);
	if(dest==NULL){
		return -1;
	}
	memset(dest,0,utf_len);
	code_convert("gb2312","utf-8",str,len,dest,utf_len);
	len=strlen(dest);
	if(len>max_len){
		len=max_len;
	}
	strncpy(str,dest,len);
	str[len]=0;
	free(dest);
	dest = NULL;
}	

#if 0
int write_sohuvip_recive(Mail_info *mail_info)
{
	char *p1=NULL, *p2=NULL ,*p3=NULL;
	int len;
	char *tmp_str=NULL;
	int  utf_len;
	p1=strstr(mail_info->recive_data,"\xb7\xa2\xbc\xfe\xc8\xcb\xa3\xba");
	if(p1==NULL) return;
	p2=strstr(p1,"<td class=td_color>");
	if(p2==NULL) return;
	p2+=19;
	p1=strstr(p2,"\x0a\x0a\x20");
	if(p1==NULL) return;
	len=p1-p2;
	if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	strncpy(mail_info->from,p2,len);
	mail_info->from[len]=0;
	cov_utf8(mail_info->from,MAX_FROM_LEN);
	
	clear_from(mail_info->from);

	
	p2 =strstr(p1,"\xca\xd5\xbc\xfe\xc8\xcb\xa3\xba");
	if(p2==NULL) return;
	p1=strstr(p2,"<td class=td_color>");
	if(p1==NULL) return;
	p1+=19;
	p2=strstr(p1,"</td>");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	strncpy(mail_info->to,p1,len);
	mail_info->to[len]=0;
	cov_utf8(mail_info->to,MAX_TO_LEN);

	
	p2=strstr(p1,"\xc8\xd5\xc6\xda\xa3\xba");
	if(p2==NULL) return;
	p1=strstr(p2,"<td class=td_color>");
	if(p1==NULL) return;
	p1+=19;
	p2=strstr(p1,"</td>");
	if(p2==NULL) return;
	len=p2-p1;
	if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
	strncpy(mail_info->sent_time,p1,len);
	mail_info->sent_time[len]=0;

	p1=strstr(p2,"\xd6\xf7\xcc\xe2\xa3\xba");
	if(p1==NULL) return;
	p2=strstr(p1,"<td class=td_color>");
	if(p2==NULL) return;
	p2+=19;
	p1=strstr(p2,"</td>");
	if(p1==NULL) return;
	len=p1-p2;
	if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	strncpy(mail_info->subject,p2,len);
	mail_info->subject[len]=0;
	cov_utf8(mail_info->subject,MAX_SUBJ_LEN);

	p3=p1;

	p2=strstr(p1,"<td align=center>");
	if(p2==NULL) return;
	*(p2-1)='\0';
	p1=strstr(p2,"</table>");
	if(p1==NULL) return;
	len=p1-p2;
	mail_info->mail_data=(char *)malloc(len+1);
	if(mail_info->mail_data !=NULL){
		memset(mail_info->mail_data,0,len+1);
		strncpy(mail_info->mail_data,p2,len);
		tmp_str=clear_html_tag(mail_info->mail_data);
		if(tmp_str!=NULL){
			len=strlen(tmp_str);
			utf_len=len*3/2+1;
			mail_info->content=(char *)malloc(utf_len);
			code_convert("gb2312","utf-8",tmp_str,len,mail_info->content,utf_len);
			free(tmp_str);
		}
	}

	p1=strstr(p3,"\xb3\xad\xcb\xcd");
	if(p1!=NULL){
		p2=strstr(p1,"<td class=td_color>");
		if(p2){
			p2+=19;
			p3=strstr(p2,"</td>");
			if(p3){
				len=p3-p2;
				if(len>MAX_CC_LEN) len=MAX_CC_LEN;
				strncpy(mail_info->cc,p2,len);
				mail_info->cc[len]=0;
				cov_utf8(mail_info->cc,MAX_CC_LEN);
			}
		}
	}
    create_dir(mail_info->save_path,"sohu",mail_info->from);
	write_to_file(mail_info);
}
#endif

void write_sohuvip_recive(Mail_info *mail_info)
{
   char *p1=NULL, *p2=NULL ,*p3=NULL;
	int len;
	//char *tmp_str=NULL;
	//int  utf_len;
	char tmp[50]={0};
	time_t timeint;
	
	  decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
	  if(mail_info->mail_data==NULL) return;
	  
	  p1=strstr(mail_info->mail_data,"\"mid\": \"");
	  if (p1==NULL) return;
	  p1+=8;
	  p2=strstr(p1,"\", \"content\"");
	  if (p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_ID_LEN) len=MAX_ID_LEN;
	  strncpy(mail_info->mail_id, p1,len);
	  mail_info->mail_id[len]=0;
	  
	  char sub_search[21]="0";
	  strncpy(sub_search, mail_info->mail_id, 20);
	  p1=p2;
	  
	  p1=strstr(p1,"\"attach\": [");
	  if(p1==NULL) return;
	  p1+=11;
	  if(*p1 != ']')
	  {
	    char *plimit;
	    plimit=strstr(p1,"]], \"folder\"");
	    if(plimit==NULL) return;
	    p2=strstr(p1,sub_search);
	    char tmp_str[MAX_ID_LEN]="0";
	    unsigned int n;
	    int length;
	    while(p2)
	    {
	      p1=p2;
	      p2=strstr(p1,"\"]");
	      if(p2==NULL) return;
	      len=p2-p1;
	      strncpy(tmp_str,p1,len);
	      
	      length=strlen(mail_info->mail_id)+len+2;
	      if(length>MAX_ID_LEN) break;
	      strcat(mail_info->mail_id,"|");
	      strcat(mail_info->mail_id,tmp_str);
	      n=plimit-p2;
	      if (n<0) return;
	      p2=memfind(p2, sub_search,n);
	    }
	    p1=plimit;
	  }
	  
	  
	  p1=strstr(p1,"\"cc\": [");
	  if(p1==NULL) return;
	  p1+=7;
	  p2=strstr(p1,"], \"message_id\":");
	  if(p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_CC_LEN) len=MAX_CC_LEN;
	  strncpy(mail_info->cc,p1,len);
	  mail_info->cc[len]=0;
	  
	  p1=strstr(p2,"\"bcc\": [");
	  if(p1==NULL) return;
	  p1+=8;
	  p2=strstr(p1,"],");
	  if(p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_BCC_LEN) len=MAX_BCC_LEN;
	  strncpy(mail_info->bcc,p1,len);
	  mail_info->bcc[len]=0;
	  
	  p1=strstr(mail_info->mail_data,"\"subject\": \"");
	  if(p1==NULL) return;
	  p1+=12;
	  p2=strstr(p1,"\",");
	  if (p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
	  strncpy(mail_info->subject,p1,len);
	  mail_info->subject[len]=0;
	  clear_tag(mail_info->subject);
	  
	  p1=strstr(p2,"\"from\":");
	  if(p1==NULL) return;
	  p2=p1;
	  p1=strstr(p2,", \"");
	  if(p1==NULL) return;
	  p1+=3;
	  p2=strstr(p1,"\"]]");
	  if(p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
	  strncpy(mail_info->from,p1,len);
	  mail_info->from[len]=0;
	  clear_from(mail_info->from);
	  
	  p1=strstr(p2,"\"to\": [[");
	  if(p1==NULL) return;
	  p1+=8;
	  p2=strstr(p1, "\", \"");
	  if (p2==NULL) return;
	  p1=p2+4;
	  p2=strstr(p1,"\"]]");
	  if(p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_TO_LEN) len=MAX_TO_LEN;
	  strncpy(mail_info->to,p1,len);
	  mail_info->to[len]=0;
	  
	  p1=strstr(p2,"\"date\": \"");
	  if(p1==NULL) return;
	  p1+=9;
	  p2=strstr(p1," +0800");
	  if(p2==NULL) return;
	  len=p2-p1;
	  if(len>MAX_TIME_LEN) return;
	  strncpy(tmp,p1,len);
	  tmp[len]=0;
	  struct tm time_struct, *tm_ptr;
	  time_t timeval;
	  strptime(tmp,"%a, %d %b %Y %H:%M:%S %Z",&time_struct);
	  timeval=mktime(&time_struct);
	  tm_ptr=localtime(&timeval);
	  sprintf(mail_info->sent_time,"%04d-%02d-%02d %02d:%02d:%02d",tm_ptr->tm_year+1900,tm_ptr->tm_mon+1,tm_ptr->tm_mday,tm_ptr->tm_hour,tm_ptr->tm_min,tm_ptr->tm_sec);
	  
	  p1=strstr(p1,"\"display\": \"");
	  if(p1==NULL) return;
	  p1+=12;
	  p2=strstr(p1,"\"}]");
	  if(p2==NULL) return;
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
	  create_dir(mail_info->save_path,"sohu",mail_info->from);
	  write_to_file(mail_info);
	     
}

int analyse_sohuvip_recive(Mail_info *mail_info, char *data,unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
  //original function doesn't work well, so it needs to write a new one
  unsigned int seq=ntohl(tcp->seq);
  int off_seq;
  int result;
  int range;
  int len;
  char *p=NULL;
  
  if(!is_b_s)
  {//1
    if(!strncmp(data,"HTTP/1.",7))
      {//2
        mail_info->recive_length=get_http_length(data);
        if(mail_info->recive_length<=0)
          {
            return -1;
          }
        mail_info->recive_length+=20;
        mail_info->recive_data =(char *) malloc(mail_info->recive_length);
        if(mail_info->recive_data==NULL)
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
           p=strstr(p,"\r\n");
           if(p==NULL)
           {
             return -1;
           }
           p+=2;
           mail_info->http_seq = seq+p-data;
           len=datalen-(p-data);
           if (len>mail_info->recive_length)
           {
             return -1;
           }
           memcpy(mail_info->recive_data,p,len);
           if(!memcmp(data+datalen-4,"\r\n\r\n",4))
           {
               write_sohuvip_recive(mail_info);
               del_mail_node(mail_info);
			   return 0;
           }
      }
	  else if(mail_info->recive_data!=NULL)
      {//3
          off_seq=seq-mail_info->http_seq;
          range=off_seq+datalen;
          if(range>mail_info->recive_length)
          {
             return -1;
          }
          memcpy(mail_info->recive_data+off_seq,data,datalen);
          if(!memcmp(data+datalen-4,"\r\n\r\n",4))
          {
             write_sohuvip_recive(mail_info);
             del_mail_node(mail_info);
			 return 0;
          }
      }//3
  }//1
  return 0;
}

#if 0
int analyse_sohuvip_recive(Mail_info *mail_info, char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	unsigned int seq=ntohl(tcp->seq);
	int off_seq;
	int range;
	if(!is_b_s){
		if(!strncmp(data,"HTTP/1.",7)){
			mail_info->recive_length = 50*1024;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq=seq;
		}
		if(mail_info->recive_data != NULL){
			off_seq=seq-mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-5,"0\r\n\r\n",5)){
				write_sohuvip_recive(mail_info);
				del_mail_node(mail_info);
			}
		}
	}
}

#endif

#if 0
int write_sohu_attach_down(Mail_info *mail_info,unsigned int length, int is_chunk)
{

     
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
int analyse_sohu_attach_recive(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
	//this funciton is used to analyse download attach files.
  	if (is_b_s)
  	{
     		char tmp_id[MAX_ID_LEN+1];
     		int result;

     		if(!strncmp(data,"GET /bapp/",9))
      		{
       			char *p1, *p2;
       			int len;
       			p1=data;
       			if (p1 == NULL) 
					return -1;
       			p1=strstr(p1,"/download/");
       			if (p1 == NULL) 
					return -1;
       			p1 += 10;
       			p2 = strstr(p1," HTTP/1.1");
       			if (p2 == NULL) 
					return -1;
       			p2 -=2;
       			if (*p2 != '.') 
					return -1;
       			len = p2-p1;
       			if (len < 0 || len > MAX_ID_LEN) 
					return -1;
       			memcpy(mail_info->mail_id,p1,len);
       			mail_info->mail_id[len] = 0;
				
				memcpy(mail_info->mail_id, mail_info->mail_id + len - 64, 64);
				mail_info->mail_id[64] = '\0';
      		}
  	} 
  	else
  	{
     	int f = http_recive_mail(mail_info,data,datalen);
		if (f == 1)
     	{//1
     			//printf("doneeeeeee------\n");
        		mail_info->is_complished = 1;
				/*attach_len = get_http_length_2(mail_info->recive_data,&n);
				if (attach_len <= 0) 
					return -1;
        		write_attach_down_1(mail_info, attach_len,n);
        		del_mail_node(mail_info);*/
        		struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			char filename[MAX_FN_LEN];
			char str_dir[MAX_PATH_LEN];
			char path[MAX_PATH_LEN+1];

			front = strstr(mail_info->header, "filename=\"");
			if(front == NULL)
			{
			     ///////////////lihan add 2017.3.6//////////////
				//Content-Disposition: attachment;filename=hello.c
				front=strstr(mail_info->header,"filename=");		
				if(front==NULL) return -1;
				front=strstr(front,"=");
				if(front==NULL) return -1;
				front+=1;
				back = strstr(front,"\r\n");
				 ///////////////lihan add  over//////////////
			}	
				
			else
			{
				front += 10;
				back = strstr(front, "\"\r\n");
			}
						
			if(back == NULL)
				return -1;
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			//memcpy(attach_info->attach_name, front, len);
			//attach_info->attach_name[len] = '\0';
			
			memcpy(filename, front, len);
			filename[len] = '\0';
			htmldecode_full(filename, filename);
			regmatch_t pm[4];
			char * tmpsub=filename;
			//printf(filename);
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
			//printf(filename);
			//htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			gettimeofday(&tv, &tz);
			snprintf(str_dir, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);
			
			snprintf(path, MAX_PATH_LEN, "%s/%lu-%lu",attach_down_path, tv.tv_sec, tv.tv_usec);
			//char temp_name[MAX_PATH_LEN];
			//memset(temp_name, MAX_PATH_LEN, 0);
			//strcpy(temp_name, attach_info->attach_name);
			//temp_name[len] = '\0';
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
			
			fd = open(path, O_RDWR|O_CREAT, file_mode);

			fd = open(path, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
				return -1;

			write(fd, mail_info->body, mail_info->bodyLen);
			close(fd);
			UpdateAttachNew(str_dir, filename, mail_info->mail_id);
			//free(mail_info->body);
			//free(mail_info->header);
			return -1;
     	}
        else if (f < 0)
            return -1;
  	}
  	
	return 0;
}

int analyse_sohu_attach_mail(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
 //because the attach and the mail body is sent separately,
 //so this function is used to analyse the attachfile
  unsigned int seq=ntohl(tcp->seq);
  int off_seq=seq-mail_info->start_seq;
  int range;
  char http_ok_head[21]="HTTP/1.1 200 OK\r\n";
  
  if (is_b_s)
  {//1
     if(!mail_info->is_complished)
      {//2
        if (mail_info->mail_length==0)
          {//3
            mail_info->mail_length=5000;
            mail_info->mail_data=(char *)malloc(5000);
            if (mail_info->mail_data==NULL)
            {//4
                return -1;
            }//4
            memset( mail_info->mail_data,0,5000);
            mail_info->start_seq=seq;
          }//3
         if(mail_info->mail_length==5000)
         {//5
            int len;
            char *tmp;
            len=get_http_length(data);
            if (len>0)
            {//6
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
            }//6
         }//5
      off_seq=seq-mail_info->start_seq;
      range=off_seq+datalen;
      if(range>mail_info->mail_length)
       {
         return -1;
       }
       memcpy(mail_info->mail_data+off_seq,data,datalen);
    }//2      
  }//1
  else if(!strncmp(data,http_ok_head,15))
  {
      mail_info->is_complished=1;
      if(sohu_attach_number<MAX_MAIL_ATTACH_SOHU)
         sohu_attach_number++;
      else
      {
         LOG_WARN("the attachments are too many\n");
         return -1;
      }
      mail_info_sohu_attach[sohu_attach_number]=mail_info;
      //store the attachment information
  }
  return 0;
}

void analyse_sohu(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
{
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned short int lowtype;
	int result = 0;

	if(!mora) 
	{
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype & 0X00FF;
		unsigned int f=0;
		switch(lowtype)
		{
    		case 0x01:
    			result = analyse_sohu_passwd(mail_info, data, datalen, tcp, is_b_s);
    			break;
    		case 0x02:
    			result = analyse_sohu_vip_passwd(mail_info, data, datalen, tcp, is_b_s);
    			break;
    		case 0x03:
    			result = analyse_sohu_passwd2(mail_info, data, datalen, tcp, is_b_s);
    			break;
    		case 0x07:
    		case 0x08:
    		    result = analyse_sohu_attach_mail(mail_info,data,datalen,tcp,is_b_s); //new added
    		    break;
    		case 0x11:
    		case 0x12:
    			result = analyse_sohu_mail(mail_info, data, datalen, tcp, is_b_s);
    			break;
    		case 0x41:
    			result = analyse_sohu_delete(mail_info,data,datalen,tcp,is_b_s);
    			break;
    		case 0x42:
    			result = analyse_vip_sohu_delete(mail_info, data, datalen, tcp, is_b_s);
    			break;
            case 0x31:
            case 0x39:
    			result = analyse_sohu_recive(mail_info,data,datalen,tcp,is_b_s);
    			break; 
            case 0x33:
                result = analyse_sohu_attach_recive(mail_info, packetInfo->body, packetInfo->bodyLen, tcp, is_b_s);
    			break;
    	    case 0x30:
    			result = analyse_sohuvip_recive(mail_info,data,datalen,tcp,is_b_s);
    			break;

    		default:
    			break;
		}
		
		if (result == -1)
			delete_mail_info(mail_info);
	}
	else
	{
		attach_info=(Attach_info *)tmp;
		lowtype = attach_info->attach_type;
		lowtype = lowtype & 0X00FF;
        
		switch(lowtype) {
		case 0x66://upload  lihan add 2017.3.4
			result = analyse_sohu_attach(attach_info, data, datalen, tcp, is_b_s); // new sohu lihan
			break;
		case 0x61://up
			result = analyse_sohu_attach_2(attach_info, data, datalen, tcp, is_b_s); // new sohu
			break;
		case 0x62:
			result = analyse_vip_sohu_attach(attach_info, data, datalen, tcp, is_b_s);//new vip sohu
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

