/*
 * analyse_m_sohu.c   
 * lihan 
 * 2017.3.14
 * V 1.0
 */
 

/******************************** Description *********************************/

/*	Sohu Android APP
 *
 *	Analysis Sohu mobile send mail and upload attachments
 *	Cell phone Android version for 5.1.1
 *	Sohu lightning Post version for V1.16
 *	Attachment for jpg images. Attachments can only upload pictures!!
 *	
 */  
 
 
/********************************* Includes ***********************************/

#include "common.h"

/********************************* Defines ************************************/
int writefile_m_sohu(Mail_info *mail_info);//lihan add

/********************************* Code ************************************/

/*analyse send mail action*/
int analyse_m_sohu_mail(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp , int is_b_s)
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

		//	{"from":"<ppag25938c86dc20@sohu.com>","to":["12343592<12343592@163.com>"]
	    if ((p3=strstr(p1, "\"from\""))!= NULL)//lihan add   send(put) ...
	    {
			get_time(data, mail_info->sent_time);
			mail_info->is_complished = 1;
			writefile_m_sohu(mail_info);
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
int analyse_m_sohu_attach_head(Attach_info *attach_info, char *data, unsigned int datalen, unsigned int seq)
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
    snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);//path
	if (fd == -1)
		return -1;
	
	write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; 

	return 0;
}

/*analyse upload file action step_1 (body ok)   lihan */
int analyse_m_sohu_attach(Attach_info *attach_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{
	unsigned int seq = ntohl(tcp->seq);
	int result;

	if(is_b_s)
	{ 	//attach_body
		if (attach_info->is_writing)//Determine whether the attachment is completed or not.Initial value is 0
		{
			result = write_to_attach(attach_info, data, datalen+47, seq);
		} 
		else
		{
			result = analyse_m_sohu_attach_head(attach_info, data, datalen, seq);
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
int writefile_m_sohu(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL;
	size_t len;
	char filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	int flag = 0;
	int i = 0;
	
	//"from":"<ppag25938c86dc20@sohu.com>"
	p1 = strstr(mail_info->mail_data, "from\":\"");
	if (p1 == NULL)
	{	
		return -1;
	}	
	p1 += 8;
	p2 = strstr(p1, ">");
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
	mail_info->to[len] = 0;
   
	//"subject":"咕咕123"
	p1 = strstr(mail_info->mail_data, "subject\":\"");
	if (p1 == NULL)
	{	
		return -1;
	}
	p1 += 10;
	p2 = strstr(p1, "\"");
	if (p2 == NULL)
	{	
		return -1;
	}	
	len = p2 - p1;
	
	if (len > MAX_SUBJ_LEN)
	{	
		len = MAX_SUBJ_LEN;
	}
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	
	//"to":["12343592<12343592@163.com>"]
	p1 = strstr(mail_info->mail_data, "to\":[\"");
	if (p1 == NULL)
	{
		return -1;
	}
	p1 += 15;
	p2 = strstr(p1, ">");
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

	//cc":["2369501824<2369501824@qq.com>"]
	if((p1 = strstr(mail_info->mail_data, "cc\":[\""))!= NULL)
	{
		p1 += 6;
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
	
	//bcc":["lihan20002<lihan20002@sina.com>"]
	if((p1 = strstr(mail_info->mail_data, "bcc\":"))!= NULL)//lihan  
    {	  	
		p1 += 7;
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
  	
	//"content":"呵呵123<p style=\"color: #0a8ee3; margin: 15px 25px 15px 0px;\">来自搜狐邮箱移动版</p>"
	if((p1=strstr(mail_info->mail_data, "content\":"))!=NULL)  
    {
		p1 += 10;
		p2 = strstr(p1, "</p>");
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
	
	mail_info->num_of_attach = i;//lihan add 2017.3.22*/
	write_to_file_m(mail_info);//........lihan 2017.3.15
	
	return 0;
}

int write_m_sohu_recive(Mail_info *mail_info)
{
	cJSON *root = NULL, *node = NULL, *array_node = NULL;
    
    root = cJSON_Parse(mail_info->recive_data);
    if (!root)
        return -1;

    node = cJSON_GetObjectItem(root, "envelope");
    if (node)
    {
        if (node->type == cJSON_Object)
        {
            cJSON *node1 = NULL, *node2 = NULL, *node3 = NULL, *node4 = NULL, *node5 = NULL, *node6 = NULL;
            cJSON* array_node2 = NULL;
            int array_size = -1;
            node1 = cJSON_GetObjectItem(node, "cc");
            if (node1)
            {
                if (node1->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node1);
                    if(array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node1, array_size);
                            if(array_node->type == cJSON_Array)
                            {
                                array_node2 = cJSON_GetArrayItem(array_node, 1);
                                strcat(mail_info->cc, array_node2->valuestring);
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->cc, " ");
                    }
                }
            }
            
            node2 = cJSON_GetObjectItem(node, "bcc");
            if(node2)
            {
                if (node2->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node2);
                    if(array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node2, array_size);
                            if(array_node->type == cJSON_Array)
                            {
                                array_node2 = cJSON_GetArrayItem(array_node, 1);
                                strcat(mail_info->bcc, array_node2->valuestring);
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->bcc, " ");
                    }
                }
            }
            
            node3 = cJSON_GetObjectItem(node, "from");
            if(node3)
            {
                if (node3->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node3);
                    if(array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node3, array_size);
                            if(array_node->type == cJSON_Array)
                            {
                                array_node2 = cJSON_GetArrayItem(array_node, 1);
                                strcat(mail_info->from, array_node2->valuestring);
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->from, "");
                    }
                }
            }
              
            node4 = cJSON_GetObjectItem(node, "to");
            if(node4)
            {
                if (node4->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node4);
                    if(array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node4, array_size);
                            if(array_node->type == cJSON_Array)
                            {
                                array_node2 = cJSON_GetArrayItem(array_node, 1);
                                strcat(mail_info->to, array_node2->valuestring);
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->to, " ");
                    }
                }
            }
            
            node5 = cJSON_GetObjectItem(node, "subject");
            if(node5)
            {
                if(node5->type == cJSON_String)
                {
                    strncpy(mail_info->subject, node5->valuestring, MAX_SUBJ_LEN);
                }
            }
            
            node6 = cJSON_GetObjectItem(node, "date_sent");
            if(node6)
            {
                if(node6->type == cJSON_Number)
                {
                    snprintf(mail_info->sent_time, MAX_TIME_LEN, "%d", node6->valueint);
                }
            }
         }

    }
    
    node = cJSON_GetObjectItem(root, "display");
    if (node)
    {
        if (node->type == cJSON_String)
        {
            mail_info->content = clear_html_tag(node->valuestring);
            clear_tag(mail_info->content);
        }
        else
        {
            cJSON_Delete(root);
            return -1;
        }
    }
        
    cJSON_Delete(root);

    create_dir(mail_info->save_path, "m_sohu", mail_info->from);
	write_to_file(mail_info);

    return 0;
}

int analyse_m_sohu_mail_recv(Mail_info *mail_info, char *data, unsigned int datalen, int is_b_s)
{
	if(is_b_s == 0)
	{
		int f = http_recive_mail(mail_info,data,datalen);
		if (1 == f)
		{
			if (strstr(mail_info->header, "Content-Encoding: gzip"))
			{
				char * dest = NULL;
				int result = decomp_gzip(mail_info->body, mail_info->bodyLen-2, &dest);
				if (result == -1 || dest == NULL)
				{
					return -1;
				}
				
				free(mail_info->body);
				mail_info->body = NULL;
				mail_info->recive_data = dest;
				dest = NULL;
				write_m_sohu_recive(mail_info);
				return -1;
			}
		}
        else if (f < 0)
            return -1;
	}
	return 0;
}

void analyse_m_sohu(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora)
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
			result = analyse_m_sohu_mail(mail_info, data, datalen, tcp, is_b_s);
			break;
			
	   		case 0x39:
			result = analyse_m_sohu_mail_recv(mail_info, data, datalen, is_b_s);
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
			result = analyse_m_sohu_attach(attach_info, data, datalen, tcp, is_b_s); 
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

