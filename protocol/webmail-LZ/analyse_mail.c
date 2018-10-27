#include "common.h"



unsigned int data_len=0;
extern int clear_tag(char *src);
/*
void output_mail(Mail_info *node)
{
    if (NULL == node)
        return -1; ;
    printf("from:\t\t%s\n",node->from);
    printf("to:\t\t%s\n",node->to);
    printf("cc:\t\t%s\n",node->cc);
    printf("bcc:\t\t%s\n",node->bcc);
    printf("subject:\t\t%s\n",node->subject);
    printf("content:\t%s\n",node->content);
}
*/
/*
    *pdest��Ϊ��������Ҫ���������������黹��ָ�룬 ��Ϊָ���򽫳�����Ϊ0
  */
char *str_in_node(char **pdest, int dest_len, char *source, const int source_len, const char *pattern1, const char *pattern2, const int len1, const int len2)
{
    if (NULL == pdest || NULL == source ||  NULL == pattern1 )
        return NULL;
    
    char *pstart = NULL;
    char *pend  = NULL;
    char *dest = NULL;
    int len = 0;
    
    pstart = strstr(source, pattern1);
    if (NULL == pstart)
        return NULL;
    
    pstart += len1;
    if (NULL != pattern2)
    {
        pend = strstr(pstart, pattern2);
        if (NULL == pend)
            return NULL;
        pend += len2;
        len = pend-pstart;
        if (NULL == dest)
        {
            dest = (char *)malloc(len+2);
            memset(dest, 0, len+1);
        }
        strncpy(dest, pstart,len);
        dest[len+1] = '\0';
    }
    else
    {
        len = (source + source_len) - pstart;
         if (NULL == dest)
        {
            dest = (char *)malloc(len+2);
            memset(dest, 0, len+1);
        }
        strncpy(dest, pstart, len);
        dest[len+1] = '\0';
    }

    if (0 == dest_len)
    {
        free(*pdest);
        *pdest = dest;
        dest = NULL;
    }
    else
    {
        if (len > dest_len)
        {
            LOG_INFO("�����ռ䲻��\n");
            len = dest_len-2;
         }
        memcpy(pdest, dest, len+2);
        free(dest);
		dest = NULL;
    }

    if (NULL == pend)
        return pstart;
    else
        return pend;
    
    return NULL;
}

char *clear_name(char *source)
{
    if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;

	int result;
	if (result != -1)
		result = cns_str_ereplace(&str, "\\\\\".*?\\\\\"", "");
	return str;
}
char *clear_to(char *source)
{
    if (source == NULL)
		return NULL;

	char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
	int result;
	if (result != -1)
		result = cns_str_ereplace(&str, "\"", "");
	if (result != -1)
		result = cns_str_ereplace(&str, " ", "");
	if (result != -1)
		result = cns_str_ereplace(&str, "<", "");
	if (result != -1)
		result = cns_str_ereplace(&str, ">", "");
	return str;
}

char *clear_content_symbol(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
	int result;
	if (result != -1)
		result = cns_str_ereplace(&str, "\\\\n", "");
	if (result != -1)
		result = cns_str_ereplace(&str, "\\\\t", "");

	return str;
}

//\{\"name\":\".*?\",\"technical\":\"
char *clear_rec(char *source)
{
    if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
	int result;
	if (result != -1)
		result = cns_str_ereplace(&str, "\{\"name\":\".*?\",\"technical\":\"", "");
	if (result != -1)
	    result = cns_str_ereplace(&str, "\",\"type\":\".*?\"\}", "");
	    
	return str;
}

void writefilemail(Mail_info *mail_info)
{
 //to":["554101587@qq.com","xiyingit@163.com","xy.x@mail.com"]
	char patternfrom[]="\"from\":\"(.*)\",\"to\":";
	char patternto[]="\"to\":\\[\"(.*)\"\\],\"cc\":";
	//char patternto[]="\"to\":[\"(.*)\"],\"cc\":";
	char patterncc[]="\"cc\":\\[\"(.*)\"\\],\"bcc\":";
	char patternbcc[]="\"bcc\":\\[\"(.*)\"\\],\"subject\":";
	char patternsubject[]="\"subject\":\"(.*)\",\"body\":";
	char patterncontent[] = "\"body\":\"(.*)\",\"contentType\":";
	char patternRid[] = "\"mailId\":\"(.*)\",\"from\":";

	regcompile_1(mail_info->mail_data, patternfrom, mail_info->from,MAX_FROM_LEN);

    if (NULL != mail_info->from)
    {
        clear_from(mail_info->from);
        /*
            char *pstart = NULL;
            char *pend  = NULL;
            pstart = strstr(mail_info->from,"<");
            
            if (NULL!=pstart )
            {
                pend=strstr(pstart,">");
                if ( NULL!= pend)
                {
                    char *pfrom= NULL;
                    pfrom = (char *)malloc(MAX_FROM_LEN+1);
                    memset(pfrom,0,MAX_FROM_LEN+1);
                    memcpy(pfrom,pstart+1,pend-pstart-1);
                    memset(mail_info->from,0,MAX_FROM_LEN+1);
                    strcpy(mail_info->from,pfrom);
                    free(pfrom);
                }
            }
        */
    }

	char *tmp_p1 = NULL;
	char *tmp_p2 = NULL;

	memset(mail_info->to, 0, MAX_TO_LEN + 1);
	regcompile_1(mail_info->mail_data, patternto, mail_info->to, MAX_TO_LEN);
    if (NULL != mail_info->to)
    {
    	tmp_p1 = clear_name(mail_info->to);
		memset(mail_info->to, 0, MAX_TO_LEN + 1);
        strcpy(mail_info->to, tmp_p1);

		tmp_p2 = clear_to(mail_info->to);
		memset(mail_info->to, 0, MAX_TO_LEN + 1);
        strcpy(mail_info->to, tmp_p2);

		free(tmp_p1);
		tmp_p1 = NULL;
		free(tmp_p2);
		tmp_p2 = NULL;
    }
	
	memset(mail_info->cc, 0, MAX_CC_LEN + 1);
	regcompile_1(mail_info->mail_data, patterncc, mail_info->cc, MAX_CC_LEN);
    if (NULL != mail_info->cc)
    {
    	tmp_p1 = clear_name(mail_info->cc);
		memset(mail_info->cc, 0, MAX_CC_LEN + 1);
        strcpy(mail_info->cc, tmp_p1);

		tmp_p2 = clear_to(mail_info->cc);
		memset(mail_info->cc, 0, MAX_CC_LEN + 1);
        strcpy(mail_info->cc, tmp_p2);

		free(tmp_p1);
		tmp_p1 = NULL;
		free(tmp_p2);
		tmp_p2 = NULL;
    }
	
	memset(mail_info->bcc, 0, MAX_BCC_LEN + 1);
	regcompile_1(mail_info->mail_data, patternbcc, mail_info->bcc, MAX_BCC_LEN);
    if (NULL != mail_info->bcc)
    {
    	tmp_p1 = clear_name(mail_info->bcc);
		memset(mail_info->bcc, 0, MAX_CC_LEN + 1);
        strcpy(mail_info->bcc, tmp_p1);

		tmp_p2 = clear_to(mail_info->bcc);
		memset(mail_info->bcc, 0, MAX_CC_LEN + 1);
        strcpy(mail_info->bcc, tmp_p2);

		free(tmp_p1);
		tmp_p1 = NULL;
		free(tmp_p2);
		tmp_p2 = NULL;
    }
	regcompile_1(mail_info->mail_data, patternsubject, mail_info->subject, MAX_SUBJ_LEN);

    clear_tag(mail_info->subject);
	char ID[MAX_ID_LEN];
	memset(ID,0,MAX_ID_LEN);
	regcompile_1(mail_info->mail_data, patternRid, ID, MAX_SUBJ_LEN);

	char filename[MAX_FN_LEN] = {0};
	memset(mail_info->save_path,0,MAX_PATH_LEN + 1);
	create_dir(mail_info->save_path,"mail",mail_info->from);
	Attachment *attachment;
	Attach_info *attach_tmp;
	Attach_info *attach_info;
	char writepath[MAX_PATH_LEN] = {0};
	attach_info=attach_tab.head->next;
	int  i=0;
	int flag=0;
	while(attach_info!=NULL)
	{
	    //  printf("\n---%s---%s---%d---attach_info->ID_str:%s\n",__FILE__,__FUNCTION__,__LINE__,attach_info->ID_str); 
		if(!strcmp(attach_info->ID_str,ID))
		{
			//printf("\nhello");
			i++;
			attachment = (Attachment *)malloc((sizeof(Attachment))+1);
			memset(attachment,0,(sizeof(Attachment))+1);
			memset(attachment->loc_filename,0,MAX_FN_LEN+1);
			attachment->next =NULL;
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

	regcompile_2(mail_info->mail_data, patterncontent, &mail_info->content);
	
	if (mail_info->content != NULL) 
	{
		char *tmp_str = NULL;
	    tmp_str = clear_content_symbol(mail_info->content);
		free(mail_info->content);
        mail_info->content = clear_html_tag(tmp_str);
		free(tmp_str);
		tmp_str = NULL;

		if (NULL == mail_info->content)
			return;
		
        clear_tag(mail_info->content);
	}
	
    if(mail_info->mail_id)
	{
		free(mail_info->mail_id);
		mail_info->mail_id = NULL;
	}
	write_to_file(mail_info);
}

int get_mail_rcv_id(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	//pstart = strstr(mail_info->mail_data, "JSESSIONID=");
	pstart = strstr(mail_info->recive_data, "\"mailId\":\"");
	if (pstart == NULL)
		return -1;
	pstart += 10;
	pend = strstr(pstart, "\",");
	if (NULL == pend)
       {
           pend = strstr(pstart, "\n");
           if (NULL == pend)
            {
                LOG_ERROR("__%s__%d__error!\n");
                return -1;
            }
       }
	len = pend - pstart;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->connect_id, pstart, len);
	mail_info->connect_id[len] = 0;

	return 0;
}

int analyse_mail_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{
      //   printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,data );
	int result;
	char *dest = NULL;
	static int flag = -1;
	if (is_b_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, tcp);
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
		}
		if (!mail_info->is_complished) 
		{
			result = write_to_okdata(mail_info, data, datalen, tcp);
			if (result == -1)
				return -1;
		}
		if(datalen < 10 || ntohl(tcp->seq) + datalen - mail_info->http_seq > mail_info->recive_length - 4 || tcp->fin == 1)
		{
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 2, &dest);
				if (result == -1) 
				{
					LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
				free(mail_info->recive_data);
				mail_info->recive_data = dest;
				dest = NULL;
			}
           // printf("%s\n", mail_info->recive_data);
			write_mail_recive(mail_info);
			return 0;
		}
	}
}

#if 0
int write_mail_recive(Mail_info *mail_info)
{
	assert(mail_info != NULL);
	assert(mail_info->recive_data != NULL);

	char *pstart = NULL;
	char *pend  = NULL;
         char *pflag  = NULL;
	size_t len = 0;
	int result;
	Mail_info *pre_mail = NULL;
         
	pstart = strstr(mail_info->recive_data, "\"bcc\":[{\"name\":\"");
//         printf("\n---%s---%s---%d---pstart:\n%s\n",__FILE__,__FUNCTION__,__LINE__,pstart);
	if (pstart != NULL) 
        {           
                     char *tmp =  (char *)malloc(MAX_BCC_LEN);
                     memset(tmp,0,MAX_BCC_LEN);
		   pstart += strlen("\"bcc\":[{\"name\":\"");
                     pend = strstr(pstart, "],");
		   if (pend == NULL)
			return -1;
                    pflag = pend;
		   len = pend - pstart;
                     if(len>0)
                	   {
                		len = (len > MAX_BCC_LEN ? MAX_BCC_LEN : len);
                		memcpy(tmp, pstart, len);
                	   }
                     pstart = strstr(tmp,"technical\":\"");
                     char *bcc_tmp = (char *)malloc(MAX_BCC_LEN);
                     int flag1 = 0;
                     while (1)
                     {
                           memset(bcc_tmp,0,MAX_BCC_LEN);
                        	pstart = strstr(pstart, "technical\":\"");
                        	if (NULL == pstart)
                        		break;
                        	pstart += 12;
                        	pend = strstr(pstart, "\",\"type\":");
                        	if (pend == NULL)
                        		return -1;
                           if (flag1)
                            {
                                strcat(mail_info->bcc,",");
                                flag1 = 0;
                            }
                          // 
                        	len = pend - pstart;
                        	len = (len > MAX_BCC_LEN ? MAX_BCC_LEN : len);
                        	memcpy(bcc_tmp, pstart, len);
                              strcat(mail_info->bcc,bcc_tmp);
                        	pend += strlen("\",\"type\":");
                              flag1++;
                        }
                     free(bcc_tmp);
                     free(tmp);
                     mail_info->bcc[strlen(mail_info->bcc)+1] = 0;
	} 
        else 
        {
		mail_info->bcc[0] = 0;
	}
        if (NULL == pflag)
        {
                  pflag = mail_info->recive_data;
        }
//"cc":[{"name":"xiyingit","technical":"xiyingit@163.com","type":"mail"}]
	pstart = strstr(pflag, "\"cc\":[{\"name\":\"");
	if (pstart != NULL)
        {
                    char *tmp =  (char *)malloc(MAX_CC_LEN);
                     memset(tmp,0,MAX_CC_LEN);
		   pstart += strlen("\"cc\":[{\"name\":\"");
                     pend = strstr(pstart, "],");
		   if (pend == NULL)
			return -1;
                     pflag = pend;
		   len = pend - pstart;
                     if(len>0)
                	   {
                		len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
                		memcpy(tmp, pstart, len);
                	   }
                     pstart = strstr(tmp,"technical\":\"");
                    char *cc_tmp = (char *)malloc(MAX_CC_LEN);
                     int flag2 = 0;
                     while (1)
                     {
                           
                           memset(cc_tmp,0,MAX_CC_LEN);
                        	pstart = strstr(pend, "technical\":\"");
                        	if (NULL == pstart)
                        		break;
                        	pstart += 12;
                        	pend = strstr(pstart, "\",\"type\":");
                        	if (pend == NULL)
                        		return -1;
                           if (flag2)
                            {
                                    strcat(mail_info->cc,",");
                                    flag2 = 0;
                            }
                       //    
                        	len = pend - pstart;
                        	len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
                        	memcpy(cc_tmp, pstart, len);
                           strcat(mail_info->cc,cc_tmp);
                        	pend += strlen("\",\"type\":");
                              flag2++;
                        }
                     free(cc_tmp);
                     free(tmp);
                     mail_info->cc[strlen(mail_info->cc)+1] = 0;
	} 
        else 
        {   
		mail_info->cc[len] = 0;
	}

        if (NULL == pflag)
        {
                  pend = mail_info->recive_data;
        }
	pstart = strstr(pflag, "\"date\":new Date(Date.UTC(");
	if (pstart == NULL)
		return -1;
	pstart += 25;
	pend = strstr(pstart, ")),");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (len > MAX_TIME_LEN)
		return -1;
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
// change the string to time format, for example:2009-6-4 17:20:23
	int i;
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
						*p -= 10;
						memmove(p, p+1, MAX_TIME_LEN - (p - mail_info->sent_time + 1) - 1); 
						*p = '1';
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
	pstart = strstr(mail_info->recive_data, "\"from\":{\"name\":\"");
        if (pstart == NULL)
		return -1;
	pend = strstr(pstart, "technical\":\"");
	if (pend == NULL)
		return -1;
	pend += 12;
	pstart = strstr(pend, "\",\"type\":");
	if (pstart == NULL)
		return -1;
	len = pstart - pend;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pend, len);
	mail_info->from[len] = 0;

	pend = strstr(pstart, "subject\":\"");
	if (pend == NULL)
		return -1;
	pend += 10;
	pstart = strstr(pend, "\",");
	if (pstart == NULL)
		return -1;
	len = pstart - pend;
	if(len>0)
	{
		len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
		memcpy(mail_info->subject, pend, len);
		mail_info->subject[len] = 0;
	}
    
         pend = strstr(pstart, "\"to\":[{\"name\":\"");
         if (NULL == pend)
            return -1;
         pend += strlen("\"to\":[{\"name\":\"");
         char *to_tmp = (char *)malloc(MAX_TO_LEN);
         int to_flag = 0;
         while (1)
         {
                  
                  memset(to_tmp,0,MAX_TO_LEN);
            	pstart = strstr(pend, "technical\":\"");
            	if (NULL == pstart)
            		break;
            	pstart += 12;
            	pend = strstr(pstart, "\",\"type\":");
            	if (pend == NULL)
            		return -1;
                 if (to_flag)
                 {
                    strcat(mail_info->to,",");
                    to_flag = 0;
                 }
            	len = pend - pstart;
            	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
            	memcpy(to_tmp, pstart, len);
                  strcat(mail_info->to,to_tmp);
            	pend += strlen("\",\"type\":");
                  to_flag++;
            }
         free(to_tmp);
         mail_info->to[strlen(mail_info->to)+1] = 0;
	result = get_mail_rcv_id(mail_info);
	if (result == -1)
	{
		return -1;
	}
    
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->mail_id != NULL)
		{
			clear_from(pre_mail->from);
			strcpy(pre_mail->bcc, mail_info->bcc);
			strcpy(pre_mail->cc, mail_info->cc);
			strcpy(pre_mail->from, mail_info->from);
			strcpy(pre_mail->to, mail_info->to);
			strcpy(pre_mail->subject, mail_info->subject);
			strcpy(pre_mail->sent_time,mail_info->sent_time);
			create_dir(pre_mail->save_path, "mail" ,pre_mail->from);
			write_to_file(pre_mail);
			del_mail_node(pre_mail);
		}
	}
	return 0;
}
#endif



int write_mail_recive(Mail_info *mail_info)
{
	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;

    char *pstart = NULL;
    char *pend = NULL;
    size_t len;
    int result;
    Mail_info *pre_mail = NULL;

//printf("mail_info->recive_data:%s\n", mail_info->recive_data);
  //  p = str_in_node((char **)&mail_info->username, MAX_UN_LEN, mail_info->recive_data, node->real_bodyLen, "primaryLoginId\":\"", "\",\"", 17, 0) ;
/*
  pstart = strstr(mail_info->recive_data, "attachments\":[");
    if (NULL != pstart)
    {
        pstart += 14;
        if (*(pstart) == '{')
        {
            pstart = str_in_node(&mail_info->attach_name, 0, pstart, 300, "\"name\":\"", "\",", 8, 0);
            printf("attach_name:%s\n", mail_info->attach_name);
        } 
     }
      if (NULL == pstart)
      */
    pstart = mail_info->recive_data;
	pstart = strstr(pstart, "\"bcc\":[");
	if (pstart != NULL) 
	{
		pstart += 7;
		pend = strstr(pstart, "],");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		if(len>0)
		{
			len = (len > MAX_BCC_LEN ? MAX_BCC_LEN : len);
			memcpy(mail_info->bcc, pstart, len);
            mail_info->bcc[len] = 0;
			
			char *tmp_p1 = NULL;
			tmp_p1 = clear_rec(mail_info->bcc);
			memset(mail_info->bcc, 0, MAX_BCC_LEN + 1);
            strcpy(mail_info->bcc, tmp_p1);
			free(tmp_p1);
			tmp_p1 = NULL;
			
            // strcpy(mail_info->bcc,clear_to(mail_info->bcc));
		}
	} else {
		mail_info->bcc[0] = 0;
	}

	pstart = strstr(pend, "\"cc\":[");
	if (pstart != NULL) 
	{
		pstart += 6;
		pend = strstr(pstart, "],");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		if(len>0)
		{
			len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
			memcpy(mail_info->cc, pstart, len);
			mail_info->cc[len] = 0;

			char *tmp_p1 = NULL;
			tmp_p1 = clear_rec(mail_info->cc);
			memset(mail_info->cc, 0, MAX_BCC_LEN + 1);
            strcpy(mail_info->cc, tmp_p1);
			free(tmp_p1);
			tmp_p1 = NULL;
			
            //  strcpy(mail_info->cc,clear_to(mail_info->cc));
		}
	} else {
		mail_info->cc[len] = 0;
	}

	pstart = strstr(pend, "\"date\":new Date(Date.UTC(");
	if (pstart == NULL)
		return -1;
	pstart += 25;
	pend = strstr(pstart, ")),");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (len > MAX_TIME_LEN)
		return -1;
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;
// change the string to time format, for example:2009-6-4 17:20:23
	int i;
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
						*p -= 10;
						memmove(p, p+1, MAX_TIME_LEN - (p - mail_info->sent_time + 1) - 1); 
						*p = '1';
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

	pstart = strstr(mail_info->recive_data, "\"from\":{\"name\":\"");
	pend = strstr(pstart, "technical\":\"");
	if (pend == NULL)
		return -1;
	pend += 12;
	pstart = strstr(pend, "\",\"type\":");
	if (pstart == NULL)
		return -1;
	len = pstart - pend;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pend, len);
	mail_info->from[len] = 0;

	pend = strstr(pstart, "subject\":\"");
	if (pend == NULL)
		return -1;
	pend += 10;
	pstart = strstr(pend, "\",");
	if (pstart == NULL)
		return -1;
	len = pstart - pend;
	if(len>0)
	{
		len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
		memcpy(mail_info->subject, pend, len);
		mail_info->subject[len] = 0;
	}
	pstart = strstr(mail_info->recive_data, "\"to\":[");
	if (pstart != NULL)
    {
		pstart += strlen("\"to\":[");
		pend = strstr(pstart, "],");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		if(len>0)
		{
			len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
			memcpy(mail_info->to, pstart, len);
            mail_info->to[len] = 0;

			char *tmp_p1 = NULL;
			tmp_p1 = clear_rec(mail_info->to);
			memset(mail_info->to, 0, MAX_BCC_LEN + 1);
            strcpy(mail_info->to, tmp_p1);
			free(tmp_p1);
			tmp_p1 = NULL;
			
            //   strcpy(mail_info->to,clear_to(mail_info->to));
		}
    }
	result = get_mail_rcv_id(mail_info);
	if (result == -1)
	{
		return -1;
	}
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->mail_id != NULL)
		{
			clear_from(pre_mail->from);
			strcpy(pre_mail->bcc, mail_info->bcc);
			strcpy(pre_mail->cc, mail_info->cc);
			strcpy(pre_mail->from, mail_info->from);
			strcpy(pre_mail->to, mail_info->to);
			strcpy(pre_mail->subject, mail_info->subject);
			strcpy(pre_mail->sent_time,mail_info->sent_time);
			create_dir(pre_mail->save_path, "mail" ,pre_mail->from);
		//	write_to_file(pre_mail);
		//	del_mail_node(pre_mail);
		}
	}

	return 0;
}

int analyse_mail_body_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp ,int is_b_s)
{       //  printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,data );
	int result;
	char *dest = NULL;
	static int flag = -1;
	if (is_b_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, datalen, tcp);
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
		}
		if (!mail_info->is_complished) 
		{
			result = write_to_okdata(mail_info, data, datalen, tcp);
			if (result == -1)
				return -1;
		}
		if(datalen < 10 || ntohl(tcp->seq) + datalen - mail_info->http_seq > mail_info->recive_length - 4 || tcp->fin == 1) 
		{
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 2, &dest);
				if (result == -1) 
				{
					LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
				free(mail_info->recive_data);
				mail_info->recive_data = dest;
				dest = NULL;
			}
           // printf("%s\n", mail_info->recive_data);
			write_mail_body_recive(mail_info);
			del_mail_node(mail_info);
			return 0;
		}
	}
}

int write_mail_body_recive(Mail_info *mail_info)
{        // printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,mail_info->recive_data );
	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;
/*
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/REC-html40/loose.dtd">
<html><body><span style="font-family:Verdana"><span style="font-size:12px">����</span></span><!-- RW5kIEdNWCBNYWlsIEJvZHk= --></body></html>
  */

	size_t len;
	Mail_info *pre_mail = NULL;
	int result;
	char *front, *back;
	
	front = strstr(mail_info->mail_data, "&messageId=");
	if(front == NULL)
		return -1;
	front += 11;
	back = strstr(front, "&purpose=");
	if(back == NULL)
		return -1;
	len = back - front;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->mail_id, front, len);
	mail_info->mail_id[len] = 0;
	memcpy(mail_info->connect_id, mail_info->mail_id, len);

	front = strstr(mail_info->recive_data,"<html>");
    if(front)
    {
		front+=6;
		back=strstr(front,"</html>");
		len=back-front;
		if(len!=0)
		{
			mail_info->content = (char *)malloc(len+1);
			memset(mail_info->content,0,len);
			strncpy(mail_info->content,front,len);
			mail_info->content[len]=0;
			char *tmp_str = NULL;
			tmp_str = clear_content_symbol(mail_info->content);
			free(mail_info->content);
			mail_info->content = tmp_str;
			tmp_str = NULL;
		}
    }

// 	result = get_mail_rcv_id(mail_info);
// 	if (result == -1)
// 		return -1;
 
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->from != NULL)
		{
			clear_from(pre_mail->from);
			strcpy(pre_mail->mail_id, mail_info->mail_id);
			pre_mail->content = clear_html_tag(mail_info->content);
			clear_tag(pre_mail->content);
			down_contents(pre_mail->content);
			create_dir(pre_mail->save_path, "mail" ,pre_mail->from);
                 //  output_mail(pre_mail);
			write_to_file(pre_mail);               
			del_mail_node(pre_mail);
		}
	}
	return 0;
}

int analyse_mail_attach_recive(Mail_info *mail_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{// printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,data );
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	
	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN+1];
		int result;
	
		if (!strncmp(data, "GET /callgate-", 14) && strstr(data, "/attachment/download?"))
		{
			char *p1, *p2;
			int len_id;
			p1=strstr(data,"&messageId=");
			if(p1==NULL)
				return -1;
			p1+=11;
			p2=strstr(p1,"&attachment");
			if(p2==NULL) 
				return -1;
			len_id=p2 - p1;
			if (len_id < 0 || len_id > MAX_ID_LEN)
				return -1;
			memcpy(mail_info->mail_id, p1, len_id);
			mail_info->mail_id[len_id] = 0;
			data_len = 0;
			mail_info->mail_length = 0;
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			char *p1 = data;
			char *p2 = strstr(data,"\r\n\r\n");
			p2+=4;
			mail_info->mail_length=p2-p1;
			mail_info->recive_length=get_http_length(data);
			if(mail_info->recive_length<=0)
				return -1;
			mail_info->recive_length += 1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			
			if(mail_info->recive_data == NULL)
				return -1;
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq;
		
		}
		if (mail_info->recive_data !=NULL)
		{
			off_seq = seq - mail_info->http_seq;
			if(off_seq < 0)
				return -1;
			range = off_seq + datalen;
			if (range >= mail_info->recive_length)
				return -1;
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			data_len+=datalen;
		}
		if (data_len - mail_info->mail_length == mail_info->recive_length-1000)
		{
			mail_info->is_complished = 1;
			attach_len=get_http_length_2(mail_info->recive_data,&n);
			if (attach_len <= 0)
				return -1;
			write_attach_down_1(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}
	return 0;
}

int write_mail_rec_attach(Attach_info *attach_info)
{
    if (NULL == attach_info)
        return -1;
    char *p1 = NULL;
    char *p2 = NULL;

    p1=strstr(attach_info->recive_data,"messageId\"\r\n\r\n");
    if(p1 == NULL)
    {       
        return -1;
    }
    p1+=14;
    p2=strstr(p1,"\r\n");
    if(p2 == NULL)
    {       
        return -1;
    }
    strncpy(attach_info->ID_str,p1,p2-p1);//the rid of attach file
    attach_info->ID_str[p2-p1]=0;
    
    p1 = strstr(p2,"filename=\"");
    if(p1 == NULL)
    {       
        return -1;
    }
    p1 += 10;
    p2   =strstr(p1,"\"");
    if(p2 == NULL)
    {       
        return -1;
    }

    strncpy(attach_info->attach_name,p1,p2-p1);//the name of attach file


    p1 = strstr(p1,"Content-Type:");
    if(p1 == NULL)
    {       
        return -1;
    }
    p1 = strstr(p1,"\r\n\r\n");
    p1 += 4;

    p2 = memfind(p1, "\r\n------", attach_info->recive_length-(p1-attach_info->recive_data)-1000);
    if(p2 == NULL)
    {       
        return -1;
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
        return -1; 
    }
    write(fd,p1,p2-p1);
    close(fd);
    /*
    printf("\n---%s---%s---%d---attach_info->ID_str:%s\n",__FILE__,__FUNCTION__,__LINE__,attach_info->ID_str);           
    printf("---%s---%s---%d---attach_info->attach_name:%s\n",__FILE__,__FUNCTION__,__LINE__,attach_info->attach_name);
    printf("---%s---%s---%d---attach_info->path_of_here:%s\n",__FILE__,__FUNCTION__,__LINE__,attach_info->path_of_here);
*/
    return 0;
}

void analyse_mail_attach(Attach_info *attach_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{

	unsigned int seq=ntohl(tcp->seq);
	int result=0;
        int off_seq;
        int data_seq;
        int flag = 0;
        char *p;
        static int rec_ok = 0;
	if(is_b_s)
	{
		if ((!strncmp(data, "POST /callgate-",15)) && strstr(data, "/attachment/upload?"))
		{
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
       }
        
   // if((attach_info->recive_data != NULL && !attach_info->is_get_ok) || !strncmp(data + datalen - 4, "--\r\n", 4) || (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)))
         if((!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)))
        {
        //if(tcp->fin)
            attach_info->is_get_ok=1;
            attach_info->is_complished =1;
            write_mail_rec_attach(attach_info);
            rec_ok = 0;
        } 

}
	
    

void write_mail_psword(Mail_info *mail_info)
{
	char patternusername[]="&login=(.*)&password=";

	//char patternpassword[]="&password=(.*)&x=";
        char patternpassword[]="&password=(.*)&btnLogin=";
        memset(mail_info->username,0,MAX_UN_LEN+1);
        regcompile_1(mail_info->mail_data, patternusername, mail_info->username,MAX_UN_LEN); 
        convert_contents(mail_info->username);
        char *p=strstr(mail_info->username,"@mail.com");
        if(p == NULL)
        {
            int lengths = strlen(mail_info->username);
            strncpy(mail_info->username+lengths,"@mail.com",9);
            mail_info->username[lengths+9]=0;
        }
       
	regcompile_1(mail_info->mail_data, patternpassword, mail_info->passwd,MAX_PW_LEN);
	htmldecode_full(mail_info->passwd,mail_info->passwd);
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
	write_xml(mail_info);

	FILE *fp;
        char passpath[MAX_PATH_LEN];
	sprintf(passpath,"%s/pass.txt",mail_data_path);
	fp=fopen(passpath,"a+");
	if(fp==NULL)
        return;
	fprintf(fp,"\nusername=%s\npassword=%s\n",mail_info->username,mail_info->passwd);
	fclose(fp);

	insert_array(mail_info->username, mail_info->source_ip);
}

int analyse_mail_passwd(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
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
		write_mail_psword(mail_info);
		return -1;
	}

	return 0;
}

int analyse_mail_content(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
//         printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,data);
	unsigned  int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	char http_ok_head[18]="HTTP/1.1 200 OK\r\n";
	
	if(is_b_s)
	{
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
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefilemail(mail_info);
		del_mail_node(mail_info);
	}

	return 0;
}

void analyse_mail(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a)
{
  //   printf("---%s---%s---%d---data:\n%s\n",__FILE__,__FUNCTION__,__LINE__,data);
	Mail_info *mail_info;
	Attach_info *attach_info;
	unsigned int type;
	int result = 0;
	if(!m_or_a)
	{
		mail_info=(Mail_info *)tmp;
		type=mail_info->mail_type;
		type = type & 0X00FF;
		switch(type)
		{
			case 0x01:
				result = analyse_mail_passwd(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x11:
				result = analyse_mail_content(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x31:
				result = analyse_mail_recive(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x32:
				result = analyse_mail_body_recive(mail_info,data,datalen,tcp,is_b_s);
				break;
			case 0x33:
				result = analyse_mail_attach_recive(mail_info,data,datalen,tcp,is_b_s);
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
		type=attach_info->attach_type;
		type = type & 0x00FF;
		switch(type) 
		{
			case 0x61:
				analyse_mail_attach(attach_info,data,datalen,tcp,is_b_s);
				break;
			default :
				break;
		}
	}
}
