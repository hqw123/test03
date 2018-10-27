
#include "common.h"

int clear_u(char *str, char ctag)
{
	char *head=NULL,*end=NULL;
	char A,B,C,D;
	char x,y,z;
	char u1=0x0e;
	char u2=0x80;
	char tem[4];
	int value;
	if(str==NULL) return -1;
	head=str;
	end=head;
	while(*head!='\0'){
		if(*head==ctag && *(head+1)=='u'){
		         memcpy(tem,head+2,4);
		         value=get_value(tem);
		         if(value<0x0800)
		         {
		           A=((value>>6) & 0x1f) | 0xc0;
		           B=((value>>0) & 0x3f) | 0x80;
		           *(end++)=A;
		           *(end++)=B;
		         }
		         else
		         {
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
			}
			head+=6;
			continue;
		}else{
			if(end<head) *end=*head;
			end++;
			head++;
		}
	}
	*end='\0';
	return 0;
}

static char x2c(const char *what)
 {
     register char digit;

     digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
     digit *= 16;
     digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
     return (digit);
 }

/*
 URL����
 */
 size_t url_decode_2980(const char *src,char *dest)
 {
     char *cp=dest;

     while(*src!='\0')
     {
       if(*src=='+')
       {
        *dest++=' ';
       }
       else if(*src=='%' && *(src+1)!='u')
       {
        int ch;
        ch=x2c(src+1);
        *dest++=ch;
        src+=2;
       }
       else
       {
        *dest++=*src;
       }
       src++;
     }
     *dest='\0'; 
     return(dest-cp); 
 }

/*����:
%25u4E2D%25u6587%253Cbr%253E%2521%40%2523%2524%2525%255E%2526amp%253B%253Cbr%253E%2526lt%253Bhtml%2526gt%253B%253Cbr%253E
*/
char *deal_point(char *src, int len)
{
    if (src == NULL)
		return NULL;
	char *str = strdup(src);
    char *tmp = (char *)malloc(len+1);
    memset(tmp, 0, len+1);
    url_decode_2980(str, tmp);
    memset(str, 0, len+1);
    url_decode_2980(tmp, str);
    free(tmp);
    tmp = conv_to_xml_symbol(str);
    free(str);
    str = tmp;
    clear_u(str, '%');
    return str;
}

char *ptrcpy(char **pptr, char *src, char *startstr, char *endstr, int addlen)
{
    if (NULL==src || pptr==NULL)
        return NULL;
    char *p1=NULL, *p2=NULL;
    int len = 0;
    p1 = strstr(src, startstr);
    if (NULL == p1)
        return NULL;
    p1 += addlen;
    p2 = strstr(p1, endstr);
    if (NULL == p2)
        return NULL;
    len = p2-p1;
    if (len > 0)
    {
        *pptr = (char *)malloc(len+1);
        memcpy(*pptr, p1, len);
        (*pptr)[len] = 0;
    }
    return p2;
}

char *arrcpy_2(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN)
{
    if (NULL==src)
        return NULL;
    char *p1=NULL, *p2=NULL;
    int len = 0;
    p1 = strstr_2(src, startstr);
    if (NULL == p1)
        return NULL;
    p1 += addlen;
    p2 = strstr_2(p1, endstr);
    if (NULL == p2)
        return NULL;
  
    len = p2-p1;
    if (len > 0)
    {
        if (len > MAX_LEN)
            len = MAX_LEN;
        memcpy(arr, p1, len);
        arr[len] = 0;
    }
    return p2;
}

char *ptrcpy_2(char **pptr, char *src, char *startstr, char *endstr, int addlen)
{
    if (NULL==src || pptr==NULL)
        return NULL;
    char *p1=NULL, *p2=NULL;
    int len = 0;
    p1 = strstr_2(src, startstr);
    if (NULL == p1)
        return NULL;
    p1 += addlen;
    p2 = strstr_2(p1, endstr);
    if (NULL == p2)
        return NULL;
    len = p2-p1;
    if (len > 0)
    {
        *pptr = (char *)malloc(len+1);
        memcpy(*pptr, p1, len);
        (*pptr)[len] = 0;
    }
    return p2;
}

#define FREE(data) do{if(NULL!=data) {free(data);data=NULL;}}while(0)

void free_mail_header_body(Mail_info *mail_info)
{
    FREE(mail_info->header);
    mail_info->headerLen = 0;
    FREE(mail_info->body);
    mail_info->bodyLen = 0;
    mail_info->bodyTotal = 0;
}

void free_att_header_body(Attach_info *attach_info)
{
    FREE(attach_info->header);
    attach_info->headerLen = 0;
    FREE(attach_info->body);
    attach_info->bodyLen = 0;
    attach_info->bodyTotal = 0;
}

int analyse_send(void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(Mail_info *mail_info))
{
    Mail_info *mail_info = (Mail_info *)node; 
 
	if (is_to_s)
			return write_to_mail(mail_info, packetInfo->body, packetInfo->bodyLen, packetInfo->tcp);
    else if (!strncmp(packetInfo->body, "HTTP/1.1 200 OK\r\n", 15))
    {
        get_time(packetInfo->body, mail_info->sent_time);
        return callback(mail_info);
    }
	return -1;
 }


int analyse_upattach1(void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(Attach_info *attach_info))
{
    Attach_info *attach_info = (Attach_info *)node;
    if (1 == attach_info->is_complished)
        return -2;
    int f = 0;
    if (is_to_s)
    {
        f = http_recive_attach(attach_info,packetInfo->body,packetInfo->bodyLen);
        if (1 ==f )
        {
            attach_info->is_complished = 1;
            if (NULL == attach_info->header || NULL == attach_info->body)
                return -1;
            
            char *p1 = strstr(attach_info->body, "\r\n");
            int len = p1-attach_info->body;
            char *endflag = (char *)malloc(len+3);
            memcpy(endflag, "\r\n", 2);
            memcpy(endflag+2, attach_info->body, len);
            endflag[len+2] = 0;
            //printf("endflag:%s\n", endflag);
            char *p2 = arrcpy_2(attach_info->attach_name, attach_info->body, "filename=\"", "\"", 10, MAX_PATH_LEN);
            if (NULL == p2)
            {
            	free(endflag);
                return -1;
            }
            htmldecode_full(attach_info->attach_name, attach_info->attach_name);
            //printf("attach_name:%s\n", attach_info->attach_name);
            callback(attach_info);//��ȡid��
           // printf("id:%s\n", attach_info->ID_str);
            p1 = strstr(p2, "\r\n\r\n");
            if (NULL == p1)
            {
            	free(endflag);
                return -1;
            }
            p1 += 4;
            char *p3 = memnfind(p2, attach_info->bodyLen-(p2-attach_info->body), endflag, strlen(endflag));
            if (NULL == p3)
            {
            	free(endflag);
                return -1;
            }
            len = p3-p1;
            //printf("len:%d\n",len);
        	struct timeval tv;
        	struct timezone tz;
        	gettimeofday(&tv,&tz);
        	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
        	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        	int fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
    		write(fd, p1, len);
    		close(fd);
        	free(endflag);
			endflag = NULL;
        	free_att_header_body(attach_info);
    		return -2;
    	}
    }
    else
        return -2;
    return f;
}

/*-----------------2980����----------------------*/
#define M2980
static const char *send_id = "2980send";

//�Ҳ�������id
int write_2980_send(Mail_info *mail_info)
{
    if (NULL==mail_info || NULL==mail_info->mail_data)
        return -1;
    
	char *p1 = NULL, *p2 = NULL, *p3 = NULL, *tmp_str = NULL, *sit;
	size_t len, total_len;
	int result, fd, n, i = 0, flag = 0;
	
	htmldecode_full(mail_info->mail_data, mail_info->mail_data);
	
	p1 = strstr(mail_info->mail_data, "[emailAddress]=");
	if (!p1) 
	    return -1;
	p1 += strlen("[emailAddress]=");
	p2 = strchr(p1, '&');
    if(!p2)
        return -1;
        
	len = p2 - p1;

	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	
	p1 = strstr(mail_info->mail_data, "[mailTo]=");
	if(!p1)
        return -1;
    
	p1 += strlen("[mailTo]=");
	p2 = strchr(p1, '&');
	if(!p2)
        return -1;
    len = p2 - p1;
    if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;

	p1 = strstr(mail_info->mail_data, "[mailCc]=");
    if(!p1)
        return -1;

    p1 += strlen("[mailCc]=");
    p2 = strchr(p1, '&');
    if(!p2)
        return -1;
    
    len = p2 - p1;
    if (len > MAX_CC_LEN)
		len = MAX_CC_LEN;
	memcpy(mail_info->cc, p1, len);
	mail_info->cc[len] = 0;
	
	p1 = strstr(mail_info->mail_data, "[mailBcc]=");
    if(!p1)
        return -1;

    p1 += strlen("[mailBcc]=");
    p2 = strchr(p1, '&');
    if(!p2)
        return -1;
    
    len = p2 - p1;
    if (len > MAX_BCC_LEN)
		len = MAX_BCC_LEN;
	memcpy(mail_info->bcc, p1, len);
	mail_info->bcc[len] = 0;
	
	p1 = strstr(mail_info->mail_data, "[subject]=");
    if(!p1)
        return -1;
    p1 += strlen("[subject]=");
    p2 = strchr(p1, '&');
    if(!p2)
        return -1;
    
    len = p2 - p1;
    if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
    
	p1 = strstr(mail_info->mail_data, "[contents]=");
     if(!p1)
        return -1;

    p1 += strlen("[contents]=");
	p2 = strchr(p1, '&');
    if(!p2)
        return -1;
    
	len = p2 - p1;
	
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL) 
	{
		return -1;
	}
    
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	
	create_dir(mail_info->save_path, "2980" ,mail_info->from);//lihan

	result = str_163_convert1(mail_info->to, MAX_TO_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailto convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->cc, MAX_CC_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailcc convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailbcc convert failed\n");
		return -1;
	}
	result = str_163_convert1(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1) 
	{
		LOG_WARN("webmail:writefile163: mailsubject convert failed\n");
		return -1;
	}

	if (mail_info->content != NULL) 
	{
		tmp_str = conv_to_xml_symbol(mail_info->content);
		if (tmp_str == NULL) 
		{
			LOG_WARN("webmail:writefile163(): mailcontent convert_to_xml_symbol() failed\n");
			return -1;
		}
		free(mail_info->content);
		mail_info->content = clear_html_tag(tmp_str);
		free(tmp_str);
		tmp_str = NULL;
		if (mail_info->content == NULL) 
		{
			LOG_WARN("webmail:writefile163(): mailcontent clear_html_tag() failed\n");
			return -1;
		}
	}
    
	write_to_file(mail_info);
    return -1;
#if 0

    if (NULL==mail_info || NULL==mail_info->mail_data)
        return -1;

    htmldecode_full(mail_info->mail_data, mail_info->mail_data);
    

    char *p1 = NULL;
    p1 = arrcpy(mail_info->from, mail_info->mail_data,"[emailAddress]=", "&", strlen("[emailAddress]="), MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    //convert_contents(mail_info->from);
    p1 = arrcpy(mail_info->to, p1,"[mailTo]=", "&", strlen("[mailTo]="), MAX_TO_LEN);
    if (NULL == p1)
        return -1;
    //convert_contents(mail_info->to);
    p1 = arrcpy(mail_info->bcc, p1,"[mailBcc]=", "&", strlen("[mailBcc]="), MAX_BCC_LEN);
    if (NULL == p1)
        return -1;
    //convert_contents(mail_info->bcc);
    p1 = arrcpy(mail_info->cc, p1,"[mailCc]=", "&", strlen("[mailCc]="), MAX_CC_LEN);
    if (NULL == p1)
        return -1;
    //convert_contents(mail_info->cc);
    p1 = arrcpy(mail_info->subject, p1,"[subject]=", "&", strlen("[subject]="), MAX_SUBJ_LEN);
    if (NULL != p1)
    {
    
        char *tmp = deal_point(mail_info->subject, strlen(mail_info->subject));
        memcpy(mail_info->subject, tmp, strlen(tmp));
        mail_info->subject[strlen(tmp)] = 0;
        free(tmp);
		tmp = NULL;
    }
    else
        return -1;
    //clear_u(mail_info->subject, '%');
    p1 = ptrcpy(&mail_info->content, p1, "[contents]=", "&", strlen("[contents]="));
    if (NULL != p1)
    {
        char *tmp = deal_point(mail_info->content, strlen(mail_info->content));
        free(mail_info->content);
        mail_info->content = tmp;
    }

    create_dir(mail_info->save_path, "2980", mail_info->from);

    if (arrcpy(mail_info->mail_id, mail_info->mail_data, "&hdAttachList=", "&", 14, MAX_ID_LEN))
    {
        char *tmp = deal_point(mail_info->mail_id, strlen(mail_info->mail_id));
        memcpy(mail_info->mail_id, tmp, strlen(tmp));
        mail_info->mail_id[strlen(tmp)] = 0;
        free(tmp);
    }
   // printf("mid:%s\n", mail_info->mail_id);
    attac_mail(mail_info, 0);
	write_to_file(mail_info);
    return -1;
#endif    
}

int analyse_2980_send(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_send(node, packetInfo, is_to_s, write_2980_send);
}

int get_2980_upattid(Attach_info *attach_info)
{
    memcpy(attach_info->ID_str, attach_info->attach_name, strlen(attach_info->attach_name));
    attach_info->ID_str[strlen(attach_info->attach_name)] = 0;
}

int analyse_2980_upattach(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_upattach1(node, packetInfo, is_to_s, get_2980_upattid);
}

int analyse_2980_delattach(void *node, PacketInfo *packetInfo, int is_to_s)
{
    char *p1 = strstr_2(packetInfo->body, "filename=");
    if (p1)
    {
        p1 += 9;
        int len = packetInfo->bodyLen - (p1-packetInfo->body);
        if (len > MAX_ID_LEN)
            len = MAX_ID_LEN;
        char ID[MAX_ID_LEN+1] = {0};
        memcpy(ID, p1, len);
        char *tmp = deal_point(ID, len);
        memcpy(ID, tmp, strlen(tmp));
        ID[strlen(tmp)] = 0;
        free(tmp);
		tmp = NULL;
       // printf("del:%s\n", ID);
        Attach_info *attach_tmp = attach_tab.head->next;
		while (attach_tmp != NULL) 
        {
			if (!strcmp(attach_tmp->ID_str, ID)) 
            {
				del_attach_node(attach_tmp);
				delete_attach(attach_tmp);
				break;
			}
			attach_tmp = attach_tmp->next;
		}
        return -1;
    }
    return 0;
}

int write_2980_recv(Mail_info *mail_info)
{
    if (NULL == mail_info->mail_data || NULL == mail_info->header || NULL == mail_info->body)
        return -1;

    char *p1 = NULL, *p2 = NULL;

    p1 = arrcpy(mail_info->mail_id, mail_info->mail_data, "&mailid=", "&", 8, MAX_ID_LEN);
    if (NULL == p1)
        return -1;
    p1 = strstr(mail_info->body, "<div class=\"addhover_send\"");
    if (NULL == p1)
        return -1;
    p1 = arrcpy(mail_info->from, p1, "addr='", "'", 6, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    p1 = arrcpy(mail_info->sent_time, p1, "<span id=\"LbDate\">", "</span>", 18, MAX_TIME_LEN);
    if (NULL == p1)
        return -1;
    p1 = arrcpy(mail_info->to, p1, "<span class='spanbk' addr='", "'", 27, MAX_TO_LEN);
    if (NULL == p1)
        return -1;
    p2 = arrcpy(mail_info->cc, p1, "<span id=\"lbMailAcc\">", "</span>", 21, MAX_CC_LEN);
    p1 = arrcpy(mail_info->subject, p1, "<input type=\"hidden\" name=\"hdsubject\" id=\"hdsubject\" value=\"", "\" />", 60, MAX_SUBJ_LEN);
    if (NULL == p1)
        return -1;
    char *tmp = conv_to_xml_symbol(mail_info->subject);
    char *tmp2 = conv_to_xml_symbol(tmp);
    memcpy(mail_info->subject, tmp2, strlen(tmp2));
    mail_info->subject[strlen(tmp2)] = 0;
    free(tmp);
    free(tmp2);
    p1 = ptrcpy(&mail_info->content, p1, "<input type=\"hidden\" name=\"Mailcontent\" id=\"Mailcontent\" value=\"", "\" />", 64);
    if (NULL != p1)
    {
        tmp = conv_to_xml_symbol(mail_info->content);
        free(mail_info->content);
        mail_info->content = clear_html_tag(tmp);
        tmp2 = conv_to_xml_symbol(mail_info->content);
        free(mail_info->content);
        mail_info->content = tmp2;
        tmp2 = NULL;
        free(tmp);
        tmp = NULL;
    }
    
    create_dir(mail_info->save_path, "2980", mail_info->from);
	write_to_file(mail_info);
	
    return -1;
}

int analyse_2980_recv(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_recv((Mail_info *)node, packetInfo, is_to_s, write_2980_recv);
}

int write_2980_recv2(Mail_info *mail_info)
{
    if (NULL == mail_info->header || NULL == mail_info->body)
        return -1;

	cJSON *root = NULL, *node = NULL, *array_node = NULL;
    
    root = cJSON_Parse(mail_info->body);
    if (!root)
        return -1;

    node = cJSON_GetObjectItem(root, "message");
    if (node)
    {
        if (node->type == cJSON_Object)
        {
            cJSON *node1 = NULL, *node2 = NULL;
            cJSON* array_node2 = NULL;
            int array_size = -1;

            node1 = cJSON_GetObjectItem(node, "mailId");
            if (node1)
            {
                strncpy(mail_info->mail_id, node1->valuestring, MAX_ID_LEN - 1);
            }

            node1 = cJSON_GetObjectItem(node, "mailSubject");
            if(node1)
            {
                strncpy(mail_info->subject, node1->valuestring, MAX_SUBJ_LEN);
            }

            node1 = cJSON_GetObjectItem(node, "mailFrom");
            if (node1)
            {
                if (node1->type == cJSON_Object)
                {
                    node2 = cJSON_GetObjectItem(node1, "emailAddress");
                    if (node2)
                    {
                        strncpy(mail_info->from, node2->valuestring, MAX_FROM_LEN);
                    }
                    else
                    {
                        strcpy(mail_info->from, "");
                    }                   
                }
            }

            node1 = cJSON_GetObjectItem(node, "mailTo");
            if (node1)
            {
                if (node1->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node1);
                    if (array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node1, array_size);
                            if(array_node->type == cJSON_Object)
                            {
                                node2 = cJSON_GetObjectItem(array_node, "emailAddress");
                                strcat(mail_info->to, node2->valuestring);
                                strcat(mail_info->to, ",");
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->to, "");
                    }
                }
            }

            node1 = cJSON_GetObjectItem(node, "mailCc");
            if(node1)
            {
                if (node1->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node1);
                    if (array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node1, array_size);
                            if(array_node->type == cJSON_Object)
                            {
                                node2 = cJSON_GetObjectItem(array_node, "emailAddress");
                                strcat(mail_info->cc, node2->valuestring);
                                strcat(mail_info->cc, ",");
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->cc, "");
                    }
                }
            }

            node1 = cJSON_GetObjectItem(node, "mailBcc");
            if(node1)
            {
                if (node1->type == cJSON_Array)
                {
                    array_size = cJSON_GetArraySize(node1);
                    if (array_size > 0)
                    {
                        while(array_size-- > 0)
                        {
                            array_node = cJSON_GetArrayItem(node1, array_size);
                            if(array_node->type == cJSON_Object)
                            {
                                node2 = cJSON_GetObjectItem(array_node, "emailAddress");
                                strcat(mail_info->bcc, node2->valuestring);
                                strcat(mail_info->bcc, ",");
                            }
                        }
                    }
                    else
                    {
                        strcpy(mail_info->bcc, "");
                    }
                }
            }

            node1 = cJSON_GetObjectItem(node, "bodyHtmlText");
            if (node1)
            {
                mail_info->content = clear_html_tag(node1->valuestring);
                clear_tag(mail_info->content);
            }
            else
            {
                cJSON_Delete(root);
                return -1;
            }

            node1 = cJSON_GetObjectItem(node, "sendDate");
            if (node1)
            {
                strncpy(mail_info->sent_time, node1->valuestring, 10);
            }
         }

    }
        
    cJSON_Delete(root);

    create_dir(mail_info->save_path, "2980", mail_info->from);
	write_to_file(mail_info);

    return 0;
}


int analyse_2980_recv2(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_recv((Mail_info *)node, packetInfo, is_to_s, write_2980_recv2);
}

int get_2980_attid(Attach_info *attach_info)
{
    arrcpy(attach_info->ID_str, attach_info->ok_data, "&mailid=", "&", 8, MAX_ID_LEN);
}

int analyse_2980_downattach(void *node, PacketInfo *packetInfo, int is_to_s)
{
    return analyse_downattach(node, packetInfo, is_to_s, get_2980_attid);
}

int analyse_2980_login(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s)
{
	if (is_to_s)
	{
        char *p1 = strstr(packetInfo->body, "POST /ashx/loginSvc.aspx?pox=");
        if (NULL == p1)
            return -1;
        p1 += 29;
        char *p2 = strstr(p1, "&pw"); 
        if (NULL == p2)
            return -1;
        int len = p2 - p1;
        //@2980.com
        if (len+9 > MAX_UN_LEN)
            len = MAX_UN_LEN-9;
        memcpy(mail_info->username, p1, len);
        memcpy(mail_info->username+len, "@2980.com", 9);
        mail_info->username[len+9] = 0;

        p1 = p2+4;
        p2 = strstr(p1, " HTTP/1");
        len = p2-p1;
        if (len > MAX_PW_LEN)
            len = MAX_PW_LEN;
        memcpy(mail_info->passwd, p1, len);
        mail_info->passwd[len] = 0;
        //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
    	write_xml(mail_info);

    	FILE *fp;
            char passpath[MAX_PATH_LEN];
    	sprintf(passpath,"%s/pass.txt",mail_data_path);
    	fp=fopen(passpath,"a+");
    	if(fp==NULL)
            return -1;
    	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
    	fclose(fp);

    	insert_array(mail_info->username, mail_info->source_ip);

        return -1;
	}
    else
        return -1;   
}

int analyse_2980_login2(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s)
{
    if(is_to_s)
    {
        char *p1 = NULL,*p2 = NULL;
        int len = 0;

        p1 = strstr(packetInfo->body, "uname=");
        if (!p1)
            return -1;
			
        p1 += strlen("uname="); 
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;

        len = p2 - p1;
        if (len > (MAX_UN_LEN - 9))
            len = MAX_UN_LEN - 9;
        
        memcpy(mail_info->username, p1, len);
        strcat(mail_info->username, "@2980.com");

        p1 = strstr(p2, "password=");
        if(!p1)
            return -1;
			
        p1 += strlen("password=");
        p2 = strchr(p1, '&');
        if (!p2)
            return -1;

        len = (p2 - p1)>MAX_PW_LEN?MAX_PW_LEN:(p2 - p1);
        memcpy(mail_info->passwd, p1, len);
        store_account_db(mail_info);
        
        return -1;
    }
    
    return 0;
}

int analyse_2980(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
    if (0 == data_len || NULL == node)
        return 0;
    
	unsigned int type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;

		switch (type) 
		{
            case 0x01:
                result = analyse_2980_login(mail_info, packetInfo, is_to_s);
                break;
                
            case 0x02:
                result = analyse_2980_login2(mail_info, packetInfo, is_to_s);
                break;
                
            case 0x11:
                result = analyse_2980_send((void *)mail_info, packetInfo, is_to_s);
        		break;
        		
            case 0x21: // old
                result = analyse_2980_recv((void *)mail_info, packetInfo, is_to_s);
        		break;
        		
            case 0x22: // 2017.06.29
                result = analyse_2980_recv2((void *)mail_info, packetInfo, is_to_s);
                break;
            
            case 0x13:
                result = analyse_2980_delattach((void *)mail_info, packetInfo, is_to_s);
                break;
		}

		if (result == -1)
		{
			//free_mail_header_body(mail_info);
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
            result = analyse_2980_upattach((void *)attach_info, packetInfo, is_to_s);
            break;
        case 0x62:
            result = analyse_2980_downattach((void *)attach_info, packetInfo, is_to_s);
            break;
        
        default:
            break;
        }
        
		if (result == -1)
		{
			free_att_header_body(attach_info);
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
}

