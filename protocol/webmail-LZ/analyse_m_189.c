/*
 * analyse_m_189.c   
 * lihan 
 * 2017.3.18
 * V 1.0
 */
 

/******************************** Description *********************************/

/*	189 Android APP
 *
 *	Analysis 189 mobile send mail and upload attachments
 *	Cell phone Android version for 5.1.1
 *	189 mobile Service version for V6.0.0
 *	Attachment is hello.c 
 *	
 */  
 
 
/********************************* Includes ***********************************/

#include "common.h"

/********************************* Defines ************************************/
int writefile_m_189(Mail_info *mail_info);//lihan add

/********************************* Code ************************************/

/* we don't need this function cause the content is a plain text, just write it to file*/
int url_decode_189_m(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
{
	//std::string result; 
	int j = 0;
	int hex = 0; 
	for (size_t i = 0; i < inlen; ++i)
	{  
		switch (inbuf[i])
		{
			case '+':  
				//result += ' ';  
				outbuf[j++] = ' ';
				break;  
			case '%': 
				if (isxdigit(inbuf[i + 1]) && isxdigit(inbuf[i + 2]))
				{
					//std::string hexStr = szToDecode.substr(i + 1, 2);  
					char hexStr[3] = {0};
					strncpy(hexStr, &inbuf[i + 1], 2);
					hex = strtol(hexStr, 0, 16);

					if (!(hex >= 48 && hex <= 57) || //0-9 
								(hex >=97 && hex <= 122) ||   //a-z 
								(hex >=65 && hex <= 90) ||    //A-Z 
								(hex == 0x2d ) || (hex == 0x2e) || (hex == 0x2f) || (hex == 0x5f)) //[-/_/./~] 
					{
						outbuf[j++] = char(hex);
						i += 2; 
					}
					else 
						outbuf[j++] = '%';
				}
				else {
					outbuf[j++] = '%';
					//result += '%';  
				}
				break; 
			default: 
				//result += szToDecode[i];  
				outbuf[j++] = inbuf[i];
				break;  
		} 

	}  
	return j;  
}

/*analyse send mail action*/
int analyse_m_189_send_mail(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp , int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int  off_seq;//Offset
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
	
	//HTTP/1.1 200 OK
	if(!strncmp(data, http_ok_head, 15)) 
	{
	    char *p1 = mail_info->mail_data;
		char *host_p = NULL;
		char *p3 = NULL;
	
		//	{to=12343592%40163.com
		if ((p3=strstr(p1, "to"))!= NULL)//lihan add   send(put) ...
		{
			get_time(data, mail_info->sent_time);
			mail_info->is_complished = 1;
			writefile_m_189(mail_info);
			del_mail_node(mail_info);
			
			return 0;
		}
	}	
	else 
	{
		return -1;
	}
}


/*Analyse upload file action step_2 (head ok)   lihan */
int analyse_m_189_upload_head(Attach_info *attach_info, char *data, unsigned int datalen, unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "&filename=(.*)&verify_code=";
	char *p = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;
	
	//filename="41.jpg"
	off_seq = seq - attach_info->start_seq;
    if (off_seq + datalen > attach_info->ok_len)
        return -1;

	memcpy(attach_info->ok_data + off_seq, data, datalen);
	
	p = strstr(attach_info->ok_data, "filename=\"");//file start
	if (p == NULL)
		return 0;
	p += 10;
	char * p2 = strstr(p, "\"");//file end
	int len = p2 - p;
	attach_info->path_of_sender = (char*)malloc(len+1);
	memcpy(attach_info->path_of_sender, p, len);
	attach_info->path_of_sender[len] = 0;
	
	p = strstr(p, "\r\n\r\n");
	if (p == NULL) 
	{
		return 0;
	}
	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;
	
	gettimeofday(&tv, &tz);//time
    snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);//path
	if (fd == -1)
	{	
		return -1;
	}
	write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; 

	return 0;
}

/*analyse upload file action step_1 (body ok)   lihan */
int analyse_m_189_upload(Attach_info *attach_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int result;

	if(is_b_s)
	{ //attach_body
		if (attach_info->is_writing)//Determine whether the attachment is completed or not.Initial value is 0
		{
			result = write_to_attach(attach_info, data, datalen+47, seq);
		} 
		else
		{
			result = analyse_m_189_upload_head(attach_info, data, datalen, seq);
		}
		
		return result;
   }
   else if(!attach_info ->is_get_ok)
   {
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";

		if(!strncmp(data, http_ok_head, 17))
		{
			attach_info ->is_writing = 0;
			attach_info->is_get_ok = 1;
			trim_attach(attach_info->path_of_here, 47);
			attach_info->is_complished = 1;
			
			return 0;
		}
	}
	
	return -1;
}


/*write to  DB */
int writefile_m_189(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL;
	size_t len;
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	int flag = 0;
	int i = 0;
	char *dest = (char *)calloc(1, mail_info->mail_length * 2);	
    if (!dest)
    {
        LOG_ERROR("calloc dest fail.\n");
        return -1;
    }
	
	/*Add URL decode,  convert "mail_info->mail_data" to "dest" */
	if (url_decode_189_m(mail_info->mail_data, mail_info->mail_length, dest, mail_info->mail_length * 2) <= 0)
	{
		return -1;
	}	
		
	//From=13554062593%40189.cn&       
	if ((p1 = strstr(dest, "From="))!= NULL)
	{	
		p1 += 5;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		if (p2 == NULL)
		{	
			return -1;
		}	
	
		if (len > MAX_TO_LEN)
		{	
			len = MAX_TO_LEN;
		}	
	
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
	}
       
	//subject=123456%E5%93%88%E5%93%88&
	if ((p1 = strstr(dest, "subject="))!= NULL)
	{
		p1 += 8;
		p2 = strstr(p1, "&");
		if (p2 == NULL)
		{	
			return -1;
		}	
		len = p2 - p1;
	
		if(len > MAX_SUBJ_LEN)
		{	
			len = MAX_SUBJ_LEN;
		}
		
		memcpy(mail_info->subject, p1, len);
		mail_info->subject[len] = 0;
	}
	
	//to=12343592%40163.com&
	if ((p1 = strstr(dest, "to="))!= NULL)
	{	
		p1 += 3;
		p2 = strstr(p1, "&");
		len = p2 - p1;
	
		if (p2 == NULL)
		{	
			return -1;
		}
	
		if (len > MAX_TO_LEN)
		{
			len = MAX_TO_LEN;
		}
		memcpy(mail_info->to, p1, len);
		mail_info->to[len] = 0;
	}
	
	//cc=12343592%40163.com&
	if ((p1 = strstr(dest, "cc="))!= NULL)
	{
		p1 += 3;
		p2 = strstr(p1, "&");
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
	
	//Bcc=47712028%40qq.com&
	if ((p1 = strstr(dest, "Bcc="))!= NULL)//lihan  
	{	  	
		p1 += 4;
		p2 = strstr(p1, "&");
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
  	
	//content=%3Chtml%3E%3Cbody%3E%E5%A4%8D%E5%8F%A4E%3C%2Fhtml%3E&
	if((p1=strstr(dest, "content="))!= NULL)  
	{
		p1 += 8;
		p2 = strstr(p1, "&");
		len = p2 - p1;
		
		if (p2 == NULL)
		{
			return -1;
		}
		mail_info->content = (char *)malloc(len + 1);
	
		if (mail_info->content == NULL)
		{
			return -1;
		}
		
		memcpy(mail_info->content, p1, len);
		mail_info->content[len] = 0;
	}
	
	free(dest);
	create_dir(mail_info->save_path, "189", mail_info->from);
	
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
	
	mail_info->num_of_attach = i;//lihan add 2017.3.23*/
	write_to_file_m(mail_info);//........lihan 2017.3.15
	
	return 0;
}

void analyse_m_189(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
{
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned short int lowtype;
	int result = 0;

	//mora == m_or_a  mail or Attach  //
	if(!mora) 
	{
		mail_info = (Mail_info *)tmp;
		lowtype = mail_info->mail_type;
		lowtype = lowtype & 0X00FF;
		
		switch(lowtype)
		{	
			case 0x11://send lihan
			result = analyse_m_189_send_mail(mail_info, data, datalen, tcp, is_b_s);
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
		attach_info = (Attach_info *)tmp;
		lowtype = attach_info->attach_type;
		lowtype = lowtype & 0X00FF;
		switch(lowtype) 
		{
			case 0x66://upload  lihan add 2017.3.4
			result = analyse_m_189_upload(attach_info, data, datalen, tcp, is_b_s); 
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

