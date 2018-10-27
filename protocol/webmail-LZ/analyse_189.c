
#include <regex.h>
#include <iconv.h>

#include "PacketParser.h"
#include "common.h"

#define CONV_P_OUTPUT_LEN 1000

int inflate_read (char *source, int len, char **dest, int *dest_size, int gzip);

int reg (char *src, char *pattern, regmatch_t * pm, int n);
/*lihan add url_decode_189  2017.3.22 */
int url_decode_189(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
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

int code_convert_2(char *from_charset, char *to_charset, char *inbuf, int inlen , char **outbuf, int *outlen)
{

	*outlen = 0;
	
	char * p_out_buff = (char *)malloc(CONV_P_OUTPUT_LEN);
	*outbuf = p_out_buff;

	int p_out_len = CONV_P_OUTPUT_LEN;
	
	iconv_t cd;
	int rc;

	cd = iconv_open(to_charset, from_charset);
	if(cd == (iconv_t)-1)
		return -1;
	while(iconv(cd, &inbuf, (size_t*)&inlen, &p_out_buff, (size_t*)&p_out_len) != -1) {
		if(inlen == 0)
		{
			*outlen=CONV_P_OUTPUT_LEN-p_out_len;
			iconv_close(cd);
			return 0;
		}
		else if(p_out_len == 0)
		{
			*outlen+=CONV_P_OUTPUT_LEN;
			p_out_buff = (char *)realloc(p_out_buff,*outlen+CONV_P_OUTPUT_LEN);
			*outbuf = p_out_buff;
		}
	}

	iconv_close(cd);
	return -1;
}

void clear_html_tag_2(char *content)
{
    char *p = content;
    int f = 0;
    while (*content)
    {
	if (*content == '<')
	{
	    if (strncmp (content, "<br", 3) == 0
		|| strncmp (content, "<BR", 3) == 4)
	    {
		*p = '\n';
		p++;
		content += 3;
		f = 1;
		continue;
	    }
	    f = 1;
	}
	else if (*content == '>')
	{
	    f = 0;
	}
	else if (*content == '&')
	{
	    if (strncmp (content, "&amp;", 5) == 0)
	    {
		*p = '&';
		p++;
		content += 5;
		continue;
	    }
	    else if (strncmp (content, "&gt;", 4) == 0)
	    {
		*p = '>';
		p++;
		content += 4;
		continue;
	    }
	    else if (strncmp (content, "&lt;", 4) == 0)
	    {
		*p = '<';
		p++;
		content += 4;
		continue;
	    }
	    else if (strncmp (content, "&nbsp;", 6) == 0)
	    {
		*p = ' ';
		p++;
		content += 6;
		continue;
	    }
	    else if (strncmp (content, "&apos;", 6) == 0)
	    {
		*p = '\'';
		p++;
		content += 6;
		continue;
	    }
	    else if (strncmp (content, "&quot;", 6) == 0)
	    {
		*p = '\"';
		p++;
		content += 6;
		continue;
	    }
	    else
	    {
		*p = *content;
		p++;
		content++;
		continue;
	    }
	}
	else if (f == 0 && *content != '\r' && *content != '\n')
	{
	    *p = *content;
	    p++;
	}
	content++;
    }
    *p = 0;
}

int analyse_189_password(Mail_info* mail_info, char* data, int data_len, int is_to_s)
{
    if(is_to_s)
    {
    	int f = http_recive_mail(mail_info, data, data_len);
    	if(f == 1)
        {
    		char *p1 = NULL, *p2 = NULL;
            char tmp_password[MAX_UN_LEN + 1] = {0};
            int len = 0;
            
    		p1 = strstr(mail_info->body, "userName=");
            if (!p1)
                return -1;
            
		    p1 += strlen("userName=");
		    p2 = strchr(p1, '&');
		    if (!p2)
                return -1;

            len = p2 - p1;
            if (len > (MAX_UN_LEN - 7))
                len = MAX_UN_LEN - 7;
            
            memcpy(mail_info->username, p1, len);
            strcat(mail_info->username, "@189.cn");

            p1 = strstr(p2, "password=");
            if (!p1)
                return -1;
            
            p1 += strlen("password=");
            p2 = strchr(p1, '&');
            if (!p2)
                return -1;

            len = (p2 - p1)>MAX_UN_LEN?MAX_UN_LEN:(p2 - p1);
            memcpy(tmp_password, p1, len);
            htmldecode_full(tmp_password, mail_info->passwd);
            store_account_db(mail_info);
            
    		return -1;
    	}
        else if (f < 0)
            return -1;
    }
	
    return 0;
}

int analyse_189_readMail(Mail_info * mail_info, char * data, int data_len, int is_to_s)
{
	if (!is_to_s)
	{
        char *p1 = NULL, *p2 = NULL, *p3 = NULL;
        int f = http_recive_mail(mail_info, data, data_len);
        if(f == 1)
        {
            char *p_content = NULL, *p_title = NULL	, *p_dest = NULL;
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
                    time_t timeval;
                    struct tm *tm_ptr; 
                    
                    p1 += 11;
                    p2 = strstr(p1, ",");
                    if (p2 - p1 > 10)
                        strncpy(mail_info->sent_time, p1, 10);
                    else if(!strncmp(p1, "null", 4))
                    {
                        timeval = time(NULL);
                        tm_ptr = localtime(&timeval);
                        snprintf(mail_info->sent_time, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);	
                    }
                    else
                        strncpy(mail_info->sent_time, p1, p2 - p1);
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
                create_dir(mail_info->save_path, "189", mail_info->from);
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

int analyse_189_sendMail(Mail_info * mail_info, char * data, int data_len, int is_to_s)
{
	//printf("---------------189----------\n");
	if(is_to_s)
	{
		int f = http_recive_mail(mail_info, data, data_len);
		if (f == 1)
		{
			char * p1, *p2;
			char *dest = (char *)calloc(1, mail_info->bodyLen * 2);	//lihan add
		    if (!dest)
		    {
		        LOG_ERROR("calloc dest fail.\n");
		        return -1;
		    }
			
			//lihan add url_decode_189 2017.3.22mail_data
			if (url_decode_189(mail_info->body, mail_info->bodyLen, dest, mail_info->bodyLen * 2) <= 0)
			{
					return -1;
			}
			
			if((p1=strstr(dest,"&from="))!=NULL)
			{
				p1+=6;
				p2 = strstr(p1,"&");
				memcpy(mail_info->from,p1,p2-p1>MAX_FROM_LEN?MAX_FROM_LEN:p2-p1);
			}	
		
			if((p1=strstr(dest,"&to="))!=NULL)
			{
				p1+=4;
				p2 = strstr(p1,"&");
				memcpy(mail_info->to,p1,p2-p1>MAX_TO_LEN?MAX_TO_LEN:p2-p1);
		    }
		
			if((p1=strstr(dest,"&cc="))!=NULL)
			{	
				p1+=4;
				p2 = strstr(p1,"&");
				memcpy(mail_info->cc,p1,p2-p1>MAX_CC_LEN?MAX_CC_LEN:p2-p1);
		    }
		
			if((p1=strstr(dest,"&bcc="))!=NULL)
			{	
				p1+=5;
				p2 = strstr(p1,"&");
				memcpy(mail_info->bcc,p1,p2-p1>MAX_BCC_LEN?MAX_BCC_LEN:p2-p1);
		    }
		
			if((p1=strstr(dest,"&subject="))!=NULL)
			{
				p1+=9;		
				p2 = strstr(p1,"&");
				memcpy(mail_info->subject,p1,p2-p1>MAX_SUBJ_LEN?MAX_SUBJ_LEN:p2-p1);
	        }
		
			if((p1 = memfind(p1,"&content=",mail_info->bodyLen-(p1-dest)))!=NULL)// mail_info->body ->dest
			{
				p1+=9;
				p2 = strstr(p1,"&");
				mail_info->content = (char*)malloc(p2-p1+1);
				memcpy(mail_info->content,p1,p2-p1);
				mail_info->content[p2-p1]=0;
				clear_html_tag_2(mail_info->content);
			
			}	
			create_dir(mail_info->save_path, "189" ,mail_info->from);
			  
			/////////////////////////// lihan   add time        ///////////////////////////////////	
			if((p1=strstr(dest,"&orgMid="))!=NULL)
			{	
				char dest1[MAX_TIME_LEN+1] = {0};
				time_t timeval;
			
				p1+=26;
				p2=strstr(p1, "&");
				memcpy(dest1, p1, 10);
			
		        struct tm *tm_ptr;
				timeval = strtol(dest1,NULL,0);
				tm_ptr = localtime(&timeval);
		        snprintf(mail_info->sent_time, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);	
			}
			free(dest);
			
			////////////////////////////////   add time  //////////////////////////////////////////	
						
			char filename[MAX_FN_LEN + 1];
			char writepath[MAX_PATH_LEN + 1];
			Attach_info *attach_tmp;
			Attachment *attachment;
			Attach_info *attach_info = attach_tab.head->next;
			int i = 0, flag = 0;
            
			while (attach_info != NULL) 
			{
				//printf("attach info ...\n");
				//printf("%s	...	%s\n", attach_info->ID_str, ID);
				if (!strcmp(attach_info->ID_str, mail_info->mail_id))
				{
					i++;
					get_file_name(attach_info->path_of_sender, filename);
					attachment = (Attachment *)malloc(sizeof(Attachment));
					if (attachment == NULL)
						break;
					//snprintf(attachment->loc_name, MAX_FN_LEN, "attach%d_%s", i, filename);
					snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
					snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
					if (!flag) 
					{//printf("11111111\n");
						attachment->next = NULL;
						mail_info->attach = attachment;
						flag++;
					} 
					else 
					{//printf("22222222\n");
						attachment->next = mail_info->attach->next;
						mail_info->attach->next = attachment;
					}
					snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);
					//printf("attachment->loc_name : %s\n", attachment->loc_name);
					//printf("attachment->loc_filename : %s\n", attachment->loc_filename);
					//printf("writepath : %s\n", writepath);
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
			write_to_file(mail_info);
			return -1;
		}
        else if (f < 0)
            return -1;
	}	
	
	return 0;
}

int analyse_189_upload(Attach_info * attach_info, char * data, int data_len, int is_to_s)
{
	if(is_to_s)
	{
		int f = http_recive_attach(attach_info,data,data_len);
		if(f==1)
		{
			attach_info->is_complished = 1;
			
			char * p1, *p2;
			int len;
			p1=attach_info->body;
			p2 = strstr(p1,"\r\n");
			char boundary[50]={0};
			memcpy(boundary,p1,p2-p1>49?49:p2-p1);
			
			char filename[31]={0},pathname[61]={0},attId[61]={0};
	         
			if((p1=strstr(p2,"\r\nContent-Disposition: form-data; name=\"key\""))!=NULL)
			{
				p1 = strstr(p1,"\r\n\r\n");
				p1+=4;
				p2 = strstr(p1,"\r\n");
				len = p2-p1;
				if(len > MAX_ID_LEN) len = MAX_ID_LEN;
				memcpy(attach_info->ID_str,p1,len);
				attach_info->ID_str[len]=0;
			}	
		
	        if((p1=strstr(p2,"\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\""))!=NULL)
			{	
				p1+=61;
				p2 = strstr(p1,"\"\r\n");
				len = p2-p1;
				attach_info->path_of_sender = (char *)malloc(len +1);
				memcpy(attach_info->path_of_sender,p1,len);
				attach_info->path_of_sender[len]=0;			
	        }
		
			p1 = strstr(p2,"\r\n\r\n");
			p1+=4;
			p2 = memfind(p1,boundary,attach_info->bodyLen-(p1-attach_info->body));
			p2-=2;
	    
			struct timeval tv;
			struct timezone tz;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd;
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
			fd = open(attach_info->path_of_here, O_WRONLY|O_CREAT,file_mode);
			if(fd==-1) return -1;
			write(fd,p1,p2-p1);
			close(fd);
		}
	}	
	return 0;
}

int analyse_189_download(Attach_info * attach_info, char * data, int data_len, int is_to_s)
{
	if(is_to_s)
	{
		if(!attach_info->ID_str[0])
		{
			char * p = strstr(data,"messageid=");
			if(!p) return -1;
			p+=10;
			char * p2 = strstr(p,"&");
			if(!p2) return -1;
			int len = p2-p;
			if(len > MAX_ID_LEN) len = MAX_ID_LEN;
			memcpy(attach_info->ID_str,p,len);
			attach_info->ID_str[len]=0;
		}
	}
	else if(attach_info->ID_str[0])
	{
		int f = http_recive_attach(attach_info,data,data_len);
		if(f==1)
		{	
			char * p1, * p2;
			if((p1=strstr(attach_info->header,"\r\nContent-Disposition: attachment; filename=\""))!=NULL)
			{	
				p1+=45;
				p2=strstr(p1,"\"\r\n");
				memcpy(attach_info->attname,p1,p2-p1);
				attach_info->attname[p2-p1]=0;
			}	
			int slen;
			char * s;
			code_convert_2("gb2312","utf8",attach_info->attname,strlen(attach_info->attname),&s,&slen);
			memcpy(attach_info->attname,s,slen);
			attach_info->attname[slen]=0;
			free(s);
			s = NULL;
			htmldecode_full(attach_info->attname,attach_info->attname);
			//printf("attname:%s\n",attach_info->attname);
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",attach_down_path, tv.tv_sec, tv.tv_usec);
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);

			if(strstr(attach_info->header,"Content-Encoding: gzip\r\n"))
			{
				inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				free(attach_info->body);
				attach_info->body=s;
				attach_info->bodyLen=slen;
			}
			
			fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
				return -1;
			write(fd, attach_info->body, attach_info->bodyLen);
			
			close(fd);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
            
			return -1;
		}
	}
	return 0;
}

int analyse_189(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned short type;
	int result = 0;     
	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
        
		switch (type)
		{
    		case 0x11:
                result = analyse_189_password(mail_info,packetInfo->body, packetInfo->bodyLen, is_to_s);
    			break;
    		case 0x21:
                result = analyse_189_readMail(mail_info,packetInfo->body, packetInfo->bodyLen, is_to_s);
    			break;
    		case 0x12:
                result = analyse_189_sendMail(mail_info, packetInfo->body, packetInfo->bodyLen, is_to_s);
    			break;
		}
		
		if (result == -1)
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
                result = analyse_189_upload(attach_info, packetInfo->body, packetInfo->bodyLen, is_to_s);
    			break;
    		case 0x62:
                result = analyse_189_download(attach_info, packetInfo->body, packetInfo->bodyLen, is_to_s);
    			break;
		}
        
		if (result == -1) 
		{
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}

