
#include "common.h"

char *m139_conv_to_utf8(char *src)  //转换成utf8格式
{
	char *tmp_str = NULL;
	char *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	utf8_len = len * 3 / 2 + 1;
	dest = (char *)malloc(utf8_len + 1);
	if (NULL == dest)
		return NULL;

	result = code_convert("gb18030", "utf-8", src, len, dest, utf8_len);
	if (-1 == result)
		return NULL;
	else 
		return dest;
}

int m139_str_convert(char *str, size_t max_len)//格式转换
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = m139_conv_to_utf8(str);
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

int gettime(char *tm_str, char *dest)
{
	struct tm  *tm_ptr;
	
	int time = atoi(tm_str);
	//timeval = mktime(&time_struct) + 8 * 3600;
	tm_ptr = localtime((time_t *)&time);
	snprintf(dest, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
}
int writefile139_sendmail(Mail_info *mail_info )
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; 
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char *p1 = NULL,  *p2 = NULL, *tmp = NULL,*tmp_to = NULL;
	size_t len, total_len;
		p1 = strstr(mail_info->mail_data, "&sid=" );
  	// save id
	if (p1 == NULL)
	{
		LOG_WARN("webmail:writefile139(): can not find ID\n");
		return -1;
	}
	else
	{
		p1 +=5;
		p2 = strstr(p1, "&&comefrom=");
		if(p2 == NULL)
			return -1;
		len = p2 - p1;
		if(len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(mail_info->mail_id,p1,len);
		mail_info->mail_id[len] = 0;
	}
	//printf("mail_id = %s\n",mail_info->mail_id);
	// save sender 
	p1 = strstr(mail_info->mail_data, "<string name=\"account\">");
	if(p1 == NULL)
	{
		LOG_WARN("webmail:writefile139(): can not find start \n");
		return -1;
	}
	else
	{
		p1 += 23;
		p2 = strstr(p1,"&lt;");
		p1 = p2;
		if (p2 == NULL )
		{
			LOG_WARN("webmail:writefile139(): can not find sender\n");
			return -1;
		}
		p2 = strstr(p1,"&gt;");
		if (p2 == NULL )
		{
			LOG_WARN("webmail:writefile139(): can not find sender\n");
			return -1;
		}
		p1 += 4;
		len = p2 - p1;
		if (len > MAX_FROM_LEN)
			len = MAX_FROM_LEN;
		memcpy(mail_info->from, p1, len);
		mail_info->from[len] = 0;
	}
	//printf("mail_info->from : %s\n",mail_info->from);
	// save receiver
    	p1 = strstr(p2,"<string name=\"to\">");
	if(p1 == NULL)
	{
		LOG_WARN("webmail:writefile139(): can not find receiverstart\n");
		return -1;
	}
	else
	{
		p1 += 18;
		p2 = strstr(p1,"</string>");
		if(p2 == NULL)
		{
			LOG_WARN("webmail:writefile139(): can not find receiver\n");
			return -1;
		}
		len = p2 - p1;
		if (len > MAX_TO_LEN)
			len = MAX_TO_LEN;
		memcpy(mail_info->to, p1, len);
		mail_info->to[len] = 0;
		//printf("mail_info->to1 : %s\n",mail_info->to);
		char *p3 = mail_info->to;
		char *p4 = strstr(p3,"&lt;");
		if(p4 != NULL)
		{
			p4 += 4;
			p3 = p4;
			p4 = strstr(p3,"&gt;");
			len = p4 - p3;
			if (len > MAX_FROM_LEN)
				len = MAX_FROM_LEN;
			memcpy(mail_info->to, p3, len);
			mail_info->to[len] = 0;
		}
		//printf("mail_info->to2 : %s\n",mail_info->to);
		/*tmp_to = clear_html_symbol(mail_info->to);
		memcpy(mail_info->to , tmp_to , strlen(tmp_to));
		mail_info->to[strlen(tmp_to)] = 0;
		free(tmp_to);*/
	}
	

	// save cc （抄送）
 	if ((p1 = strstr(p2, "<string name=\"cc\">")) != NULL)
	{
	    p1 += 18;
	    p2 = strstr(p1, "</string>"); 
	    if (NULL != p2)
	    {
		    len = p2 - p1;
		    memcpy(mail_info->cc , p1, len>MAX_CC_LEN?MAX_CC_LEN:len);
		    mail_info->cc[len] = 0;		
	    }
	    else 
	    {
		    mail_info->cc[0] = 0;
 	    }
	}
	// save bcc (秘密抄送)
	if ((p1 = strstr(p2, "<string name=\"bcc\">")) != NULL)
    {
	    p1 += 19;
	    p2 = strstr(p1, "</string>"); 
	    if (NULL != p2)
	    {
		    len = p2 - p1;
		    memcpy(mail_info->bcc , p1, len>MAX_BCC_LEN?MAX_BCC_LEN:len);
		    mail_info->bcc[len] = 0;
	    }
	    else 
	    {
		    mail_info->bcc[0] = 0;
 	    }
	}

	//save subject
	p1 = strstr(p2, "<string name=\"subject\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile139(): can not find mailsubject start\n");
		return -1;
	}
	else
	{
		p1 += 23;
 		p2 = strstr(p1 , "</string>");
		len = p2 - p1;
		if (p2 == NULL) 
		{
			LOG_WARN("webmail:writefile139(): can not find mailsubject end\n");
			return -1;
		}
		if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
		memcpy(mail_info->subject, p1, len);
		mail_info->subject[len] = 0;
	}
	//printf("mail_info->subject : %s\n",mail_info->subject);

	// save content
	p1 = strstr(p2, "<string name=\"content\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile139(): can not find mailcontent start\n");
		return -1;
	}
	else
	{
        p1 += 23;
        /*
 		p1 = strstr(p1 , "&lt;DIV&gt;");
		if (p1 == NULL)
		{
			mail_info->content = NULL;
			fprintf(stderr, "webmail:writefile163()");
			return -1;
		}
		p1 += 11;
		p2 = strstr(p1, "&lt;/DIV&gt;" );
		if (p2 == NULL) 
		{
			fprintf(stderr, "webmail:writefile139(): can not find mailsubject end\n");
			return -1;
		}
		*/
		p2 = strstr(p1, "</string>");
		len = p2 -p1;
		mail_info->content = (char *)malloc(len + 1);
		if (mail_info->content == NULL) 
		{
			LOG_WARN("webmail:writefile139()");
			return -1;
		}
		memcpy(mail_info->content, p1, len);
		mail_info->content[len] = 0;
        char  *tmp_str = NULL;
        tmp_str = conv_xml_symbol(mail_info->content);
        free(mail_info->content);
    	mail_info->content = clear_html_tag(tmp_str);
        free(tmp_str);
		tmp_str = NULL;

		if (NULL == mail_info->content)
			return -1;
		
	}
	
	create_dir(mail_info->save_path, "139" ,mail_info->from); // mail_info->save_path : /home/LzData/moduleData/webmail/year-mon-day/qq/********@qq.com_hour_min_sec
	//search attachment
	
	Attach_info *attach_tmp;
	Attachment *attachment;
	Attach_info *attach_info = attach_tab.head->next;
	int i = 0,flag = 0;
	
	while (attach_info != NULL) 
	{
		//printf("attach_info->ID_str : %s\n",attach_info->ID_str);
		if (!strcmp(attach_info->ID_str, mail_info->mail_id))
		{
			i++;
			get_file_name(attach_info->path_of_sender, filename);
			//printf("filename : %s\n",filename);
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL)
				break;
			
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			
			if (!flag) 
			{
				attachment->next = NULL;
				mail_info->attach = attachment;
				flag = 1;
			} 
			else 
			{
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			//snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);//lihan del
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);//lihan add
			//printf("attach path / writepath : %s\n",writepath);
			link(attach_info->path_of_here, writepath);//关联路径
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

	if (NULL == mail_info)
		return -1;
	//printf("write_to_file send mail 139\n");
	write_to_file(mail_info);
}
	
	
//139 send mail  获取全部数据后再找出所要的信息
int analyse_139_sendmail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;
	//printf("analyse_139_sendmail\n");
	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 \r\n", 7))
	{
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		writefile139_sendmail(mail_info);
		del_mail_node(mail_info);

		return 0;
	}
	else 
	{
		return -1;
	}
}

int writefile139_sendmsg(Mail_info *mail_info)
{
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; 
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1];
	char *p1 = NULL,  *p2 = NULL, *tmp = NULL;
	size_t len, total_len;
	
	// save sender 
	p1 = strstr(mail_info->mail_data, "CuserNumber");
	/////////////CuserNumber%3A%278613554062593%27%2Cloginname///////////////lihan from data 2017.2.28
	if(p1 == NULL)
	{
		//LOG_WARN("webmail:writefile139(): can not find start \n");
		return -1;
	}
	else
	{
		p2 = strstr(p1+11, "loginname");//.....lihan 
		if (p2 != NULL)
		{
			len = p2 - p1;
			if (len > MAX_FROM_LEN)
				len = MAX_FROM_LEN;
			if(len > 11)
				memcpy(mail_info->from, p1+(len-17), 17);//lihan......
			else 
				memcpy(mail_info->from, p1, len);
			mail_info->from[11] = 0;
		}
	}
	//printf("mail_info->from : %s\n",mail_info->from);

	p1 = strstr(p2, "<string name=\"smsContent\">");
	if (p1 == NULL) 
	{
		//LOG_WARN("webmail:writefile139(): can not find mailcontent start\n");
		return -1;
	}
	else
	{
 		p1 += 26;
		p2 = strstr(p1,"</string>");
		len = p2 -p1;
		mail_info->content = (char *)malloc(len + 1);
		if (mail_info->content == NULL) 
		{
			LOG_WARN("webmail:writefile139()\n");
			return -1;
		}
		memcpy(mail_info->content, p1, len);
		mail_info->content[len] = 0;
	}
	
	// save receiver
    	p1 = strstr(p2,"<string name=\"receiverNumber\">");
	if(p1 == NULL)
	{
		LOG_WARN("webmail:writefile139(): can not find receiverstart\n");
		return -1;
	}
	else
	{
		p1 += 30;
		p2 = strstr(p1,"</string>");
		len = p2 - p1;
		if (len > MAX_TO_LEN)
			len = MAX_TO_LEN;
		if(len>11)
			memcpy(mail_info->to, p1+(len-11), 11);
		else 
			memcpy(mail_info->to, p1, len);
		mail_info->to[11] = 0;
		
	}
	//printf("mail_info->to : %s\n",mail_info->to);

	mail_info->cc[0] = 0;
	mail_info->bcc[0] = 0;
	mail_info->subject[0] = 0;
	

	// save content
	create_dir(mail_info->save_path, "139" ,mail_info->from); // mail_info->save_path : /home/LzData/moduleData/webmail/year-mon-day/qq/********@qq.com_hour_min_sec
		
	//printf("write_to_file send mail 139\n");
	write_to_file(mail_info);
}
//139 send message 
int analyse_139_sendmsg(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;
	//printf("analyse_139_sendmsg\n");
	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		writefile139_sendmsg(mail_info);
		del_mail_node(mail_info);

		return 0;
	}
	else 
	{
		return -1;
	}
}

int writefile_139_rcvmail_id(Mail_info *mail_info)
{
	char *p1 = NULL, *p2 = NULL,*p3 = NULL;
	char tmp_id[MAX_ID_LEN + 1] = {0};
	size_t len_id;
	size_t len;
	p1 = mail_info->mail_data;
	if(p1 == NULL) 
		return -1;
	p2 = strstr(p1,"<string name=\"id\">");
	p3 = strstr(p1,"<string name=\"mid\">");
	if (p2 == NULL && p3 == NULL)
		return -1;
	if(p2)
	{
		p2 += 18;
		p1 = p2;
	}
	else 
	{
		p3 += 19;
		p1 = p3;
	}
	p2 = strstr(p1, "</string>");
	if (p2 == NULL) 
		return -1;
	len_id = p2 - p1;
	if (len_id < 0 || len_id > MAX_ID_LEN) 
		return -1;
	memcpy(tmp_id, p1,len_id);
	tmp_id[len_id] = 0;
	htmldecode_full(tmp_id,mail_info->mail_id);
	//printf("mail_info->mail_id: %s\n",mail_info->mail_id);
}

static char *clear_139_name(char *source)
{
	if (source == NULL)
		return NULL;
	
	char *str = strdup(source);
	if (str == NULL)
		return NULL;
	
	int result = 0;
	//if (result != -1)
		result = cns_str_ereplace(&str, "\\\\\"", "");
	if (result != -1)
	    result = cns_str_ereplace(&str, "\"", "");
	return str;
}

int writefile_139_rcvmail(Mail_info *mail_info)
{
    if (NULL != mail_info->body)
    {
        mail_info->recive_data = mail_info->body;
        mail_info->body = NULL;
        mail_info->recive_length = mail_info->bodyLen;
    }
	//printf("writefile_139_rcvmail***\n");
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = NULL;
	size_t len;
	int result;
	char code_encoding[20] = {"charset=gb2312"};
    
	writefile_139_rcvmail_id(mail_info);	
	//from
	pstart = strstr(mail_info->recive_data, "account:\"");
	if (pstart==NULL)
		return -1;
        pstart += 9;
	pend = strstr(pstart,"\",");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len>MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from,pstart,len);
	mail_info->from[len]=0;
	//printf("mail_info->from: %s\n",mail_info->from);

	//to
	pstart=strstr(pend,"to:\"");
	if (pstart==NULL) 
		return -1;
	pstart += 4;
	pend = strstr(pstart,"\",");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	//printf("mail_info->to: %s\n",mail_info->to);

	//subject
        pstart=strstr(pend, "subject:\"");
        if (pstart==NULL)
	{
		//printf("can not find subject start ..\n");
		return -1;
	}
        pstart+=9;
        pend=strstr(pstart,"\",");
        if (pend==NULL)
		return -1;
        len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject: %s\n",mail_info->subject);


	//senddate
	char senttime[MAX_TIME_LEN + 1];
	pstart=strstr(pend,"sendDate:");
	if (pstart==NULL) 
		return -1;
	pstart += 9;
	pend = strstr(pstart,",");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(senttime, pstart, len);//ch_time
	senttime[len] = 0;
	gettime(senttime,mail_info->sent_time);	
	
	//content
	pstart = strstr(pend, "content:\"");
	if (pstart==NULL) 
	{
		//printf("can not find content start ..\n");
		return -1;
	}
    pstart += 9;
    /*������2013-03-11�Ĺ�*/
    if (NULL == strstr_2(pstart, "<\\/BODY>"))
    {
    	pstart = strstr_2(pstart , "<div>");
    	
         if(pstart == NULL)
    	{
    		//printf("1111.......\n");
    		pstart = strstr_2(pend, "<div class=\\\"txt\\\">");
            if(pstart == NULL)
    			return -1;
    		pstart += 19;
    		
    		//pend = strstr(pstart , "<\\/div>");
    		pend = strstr(pstart , "\"}");
    		if(pend == NULL)
    		{
    			//printf("2222.......\n");
    			return -1;
    		}
    		mail_info->mail_type = 0x1342;
    		free(mail_info->mail_id);
    		mail_info->mail_id = NULL; 
    	}
    	else
    	{	
			pstart += 5;
			//pend = strstr(pstart, "<\\/DIV>");
			pend = strstr(pstart , "\"}");
			if (pend == NULL)
				return -1;
    	}
    }
    else
    {
        pstart = strstr_2(pstart, "<BODY");
        if (NULL == pstart)
            return -1;
        pstart += 5;
        pend = strstr_2(pstart, "<\\/BODY>");
        if (NULL == pend)
            return -1;
    }
	//printf("find content...\n");
	len = pend - pstart;
	mail_info->content = (char *)malloc(len + 1);
	memcpy(mail_info->content, pstart, len);
	
	mail_info->content[len] = 0;
	if (mail_info->content == NULL)
		return -1;

	clear_from(mail_info->from);
	result = m139_str_convert(mail_info->from, MAX_FROM_LEN);
	//printf("convert from :%s\n",mail_info->from);
	if (result == -1)
		return -1;
	result = m139_str_convert(mail_info->to, MAX_TO_LEN);
	
	if (result == -1)
		return -1;
	result = m139_str_convert(mail_info->sent_time, MAX_TIME_LEN);
	
	if (result == -1)
		return -1;
	/*result = m139_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;*/
	char *tmp_str ;

    tmp_str = conv_xml_symbol(mail_info->content);
    free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
    free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;
	
	clear_from(mail_info->from);
	create_dir(mail_info->save_path, "139", mail_info->from);
	write_to_file(mail_info);
    return -1;
}


int writefile_139_rcvmail1(Mail_info *mail_info)
{
    if (NULL==mail_info->recive_data && NULL!=mail_info->body)
    {
        mail_info->recive_data = mail_info->body;
        mail_info->body = NULL;
        mail_info->recive_length = mail_info->bodyLen;
    }
	//printf("writefile_139_rcvmail1***\n");
	char *pstart = NULL;
	char *pend = NULL;
	char *tmp = NULL,tmp_id[MAX_ID_LEN + 1];
	int len;
	int result;
	char code_encoding[20]={"charset=gb2312"};
		
	//from
	pstart = strstr(mail_info->recive_data, "'mid':'");
	if (pstart==NULL)
		return -1;
        pstart += 7;
	pend = strstr(pstart,"',\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	if (len < 0 || len > MAX_ID_LEN) 
		return -1;
	memcpy(tmp_id, pstart,len);
	tmp_id[len] = 0;
	htmldecode_full(tmp_id,mail_info->mail_id);
	

	char senttime[MAX_TIME_LEN + 1];
	pstart=strstr(pend,"'sendDate':");
	if (pstart==NULL) 
		return -1;
	pstart += 11;
	pend = strstr(pstart,",\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len=(len >MAX_TIME_LEN ? MAX_TIME_LEN : len);
	memcpy(senttime, pstart, len);//ch_time
	senttime[len] = 0;
	gettime(senttime,mail_info->sent_time);
	//from
	pstart=strstr(pend,"'from':'");
	if (pstart==NULL) 
		return -1;
	pstart += 8;
	pend = strstr(pstart,",\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;
	//to
	pstart=strstr(pend,"'to':'");
	if (pstart==NULL) 
		return -1;
	pstart += 6;
	pend = strstr(pstart,",\n");
	if (pend == NULL)
		return -1;
	len=pend-pstart;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;
	//printf("mail_info->to: %s\n",mail_info->to);

	//subject
        pstart=strstr(pend, "'subject':'");
        if (pstart==NULL)
	{
		//printf("can not find subject start ..\n");
		return -1;
	}
        pstart+=11;
        pend=strstr(pstart,",\n");
        if (pend==NULL)
		return -1;
        len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;
	//printf("mail_info->subject: %s\n",mail_info->subject);
	
	
	//content
	pstart = strstr(pend, "'summary':'");
	if (pstart==NULL) 
	{
		//printf("can not find content start ..\n");
		return -1;
	}
	pstart+=11;
        pend=strstr(pstart,",\n");
        if (pend==NULL)
		return -1;
        len = pend - pstart;
	
	//printf("find content...\n");
	len = pend - pstart;
	mail_info->content = (char *)malloc(len + 1);
	memcpy(mail_info->content, pstart, len);
	
	mail_info->content[len] = 0;
	if (mail_info->content == NULL)
		return -1;

	clear_from(mail_info->from);
	result = m139_str_convert(mail_info->from, MAX_FROM_LEN);
	//printf("convert from :%s\n",mail_info->from);
	if (result == -1)
		return -1;
	result = m139_str_convert(mail_info->to, MAX_TO_LEN);
	
	if (result == -1)
		return -1;
	result = m139_str_convert(mail_info->sent_time, MAX_TIME_LEN);
	
	if (result == -1)
		result -1;
	/*result = m139_str_convert(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;*/
	char *tmp_str = NULL;
	
	tmp_str = clear_html_symbol(mail_info->content);
	free(mail_info->content);
	mail_info->content = clear_html_tag(tmp_str);
    free(tmp_str);
	tmp_str = NULL;
	if (NULL == mail_info->content)
		return -1;

	clear_from(mail_info->from);
	create_dir(mail_info->save_path, "139", mail_info->from);
	write_to_file(mail_info);
    return -1;
}

char * get_real_data(char *data  ,int is_ok_chunked,unsigned int data_len)
{
	char *p1 = NULL;
	char *recive_tmp = (char *)malloc(data_len + 1);
	p1 = strstr(data, "\r\n\r\n");
	
	p1 +=4;
	if(is_ok_chunked)
	{	p1 = strstr(p1,"\r\n");
		p1 +=2;
	}
	memcpy(recive_tmp, p1, data_len);
	recive_tmp[data_len] = 0;
	free(data);
	data = recive_tmp;
	return data;
}
//139 receive mail
int analyse_139_rcvmail(void *node, PacketInfo *packetInfo, int is_to_s)
{
    Mail_info *mail_info = (Mail_info *)node;
	if(mail_info->mail_type == 0x1322)
	{
		//printf("deal mail...\n");
		return analyse_recv(mail_info, packetInfo, is_to_s, writefile_139_rcvmail);//writefile_139_rcvmail(mail_info);
	}
	else 
		return analyse_recv(mail_info, packetInfo, is_to_s, writefile_139_rcvmail1);
}


//写入附件信息
int write_139_attach_down(Attach_info *attach_info)
{
	//printf("write_139_attach_down***\n");
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char *p1 = attach_info->recive_data;
	char *p2 = NULL ,*dest = NULL;
	char filename[MAX_FN_LEN]="0";
	size_t len;
	char tmpname[MAX_FN_LEN]="0";
	if(p1==NULL) 
		return -1;
	//获取文件名
	p2 = strstr(p1,"attachment; filename=");
	if(p2==NULL)
	{
		p2 = strstr(p1,"attachment; filename=\"");
		if(p2 == NULL)
			return -1;
		p1 = p2;
		p1 += 22;
		p2 = strstr(p1,"\"");
	}
	else
	{
		p1 = p2;
 		p1 += 21;
		p2 = strstr(p1,"\r\n");
	} 
	if(p2==NULL) 
		return -1;
	len = p2-p1;
	if(len>MAX_FN_LEN) 
		len=MAX_FN_LEN;
	strncpy(tmpname,p1,len);
	tmpname[len] = 0;
	htmldecode_full(tmpname,attach_info->attname);  //assic译码
	char *tmp = clear_139_name(attach_info->attname);
    strcpy(attach_info->attname, tmp);
    attach_info->attname[strlen(tmp)] = 0;
    free(tmp);
	tmp = NULL;
	//printf("attach_info->recive_length 1 : %d \n",attach_info->recive_length);
	attach_info->recive_data = get_real_data(attach_info->recive_data , attach_info->is_ok_chunked ,attach_info->recive_length );
	if(attach_info->recive_data == NULL )
		return -1;
	//attach_info->recive_length = strlen(attach_info->recive_data);
	//printf("attach_info->recive_length 2 : %d \n",attach_info->recive_length);
	if(attach_info->ok_gzip)
	{
		int result = decomp_gzip_3(attach_info->recive_data, attach_info->recive_length, &dest);
		if(result == -1)
		{
			result = decomp_gzip_1(attach_info->recive_data, attach_info->recive_length, &dest);
			if(result == -1)
			{
				result = decomp_gzip_2(attach_info->recive_data, attach_info->recive_length, &dest);
				if(result == -1) 
                    result = decomp_gzip(attach_info->recive_data, attach_info->recive_length, &dest);
			}
		}
        
		if (result == -1) 
		{
			LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
				return -1;
		}
        
		free(attach_info->recive_data);
		attach_info->recive_data = dest;
		dest = NULL;
		attach_info->recive_length = strlen(attach_info->recive_data) ;
	}
	//printf("\nattach_info->recive_data = \n%s\n", attach_info->recive_data);
	
	//printf("attach_info->recive_length 2 : %d \n",attach_info->recive_length);
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", attach_down_path, tv.tv_sec, tv.tv_usec);
	
	int fd;
	fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	write(fd, attach_info->recive_data, attach_info->recive_length );
	
	
	close(fd);
   	
	char str_file[MAX_PATH_LEN];
	snprintf(str_file, MAX_PATH_LEN, "%lu-%lu",tv.tv_sec, tv.tv_usec);

	UpdateAttachNew(str_file, attach_info->attname, attach_info->ID_str);//连接对应的䒈邮件


}

int analyse_139_upattach_head(Attach_info *attach_info ,char *data,unsigned int data_len,unsigned int seq)
{
	int fd;
	size_t len;
	struct timeval tv;
	struct timezone tz;
	char  *p1 = NULL ,*p2 = NULL;
	char file_name_pattern[]="; filename=\"(.*)\"\r\nContent-Type: ";
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ;
	int off_seq = seq - attach_info->start_seq;

    if (off_seq + data_len > attach_info->ok_len)
    {
        LOG_WARN("ok_data need space!\n");
        return -1;
    }
    
	memcpy(attach_info->ok_data + off_seq, data, data_len); 
	p1 = strstr(attach_info->ok_data, "&sid=");
	if(p1 == NULL)
	{
		//printf("can not find sid \n");
		return -1;
	}
	p1 += 5;
	p2 = strstr(p1,"&");
	if (p2 == NULL)
		return -1;
	len = p2-p1;
	if (len > MAX_ID_LEN)
		return -1;
	strncpy(attach_info->ID_str, p1, len);
	attach_info->ID_str[len] = 0;
	//printf("**attach_info->ID_str : %s\n",attach_info->ID_str);

	//找到数据开始部分
	p1 = strstr(attach_info->ok_data, "filename=\"");
	if(p1 == NULL) 
	{
		//printf("can not find filename= \n");
		return 0;
	}
	//printf("have find filename**\n");
	p2 = strstr(p1,"\r\n\r\n");
	if(p2 == NULL) 
		return 0;
	p2 += 4;
	
	//printf("real data***\n");
	attach_info->start_seq = p2-attach_info->ok_data+attach_info->start_seq;  //指向数据真正开始部分
	regcompile_2(attach_info->ok_data,file_name_pattern, &attach_info->path_of_sender);//找文件名
	gettimeofday(&tv,&tz);
	snprintf(attach_info->path_of_here,MAX_PATH_LEN,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);  //上传的附件放在mail_temp_path里面

	//printf("attach_info->path_of_here : %s\n",attach_info->path_of_here);
	fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);//将文件写入path_of_here所指的路径
	if(fd == -1)  
		return  -1;
	write(fd,p2,off_seq + data_len - (p2-attach_info->ok_data));
	close(fd);
	attach_info->is_writing = 1;  
}

//139 upload attachment  对第一个数据包单独处理后，其余的接受一个存一个
int analyse_139_upload_attach(Attach_info * attach_info,char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int result;
	char *p1=NULL ,*p2=NULL;
	int len;

	if (is_to_s) 
	{
		if(strstr(data,"Accept: image")&&strstr(data,"360SE"))
			return -1;
		if(attach_info->is_writing)  //初始为0
		{//将其余段的数据写入文件
			result = write_to_attach(attach_info,data,data_len,seq);
		} 
		else 
		{//第一个数据包处理
			result = analyse_139_upattach_head(attach_info,data,data_len,seq); 
		}
		return result;
	}
	else 
	{
		if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15))
		{
		
		attach_info->is_complished = 1;
		trim_attach(attach_info->path_of_here,151);
		free(attach_info->ok_data);
	    attach_info->ok_data = NULL;
		return 0;
		}
	}
	
}

int get_139_id(Attach_info *attach_info)
{
    char *p1 = NULL ,*p2 = NULL;
	char tmp_id[MAX_ID_LEN + 1];
	int len;
	p1 = attach_info->ok_data;
	if (p1==NULL)
		return -1;
	p2=memfind(p1, "&mid=",150);
	if (p2==NULL)
		return -1;
	p1=p2+5;
	p2 = strstr(p1,"&");
	if (p2==NULL)
		return -1;
	len = p2 - p1;
	if (len < 0 || len > MAX_ID_LEN)
		return -1;
	memcpy(tmp_id, p1, len);
	tmp_id[len] = 0;
	htmldecode_full(tmp_id,attach_info->ID_str);
	return 0;
}

//139 download attachment
int analyse_139_download_attach(void *node, PacketInfo *packetInfo, int is_to_s)
{
    if (is_to_s)
	{
		if(strstr(packetInfo->body,"Accept: image")&&strstr(packetInfo->body,"360SE"))
			return -1;
	}
    return analyse_downattach(node, packetInfo, is_to_s, get_139_id);
}

int analyse_139_downattach(void *node, PacketInfo *packetInfo, int is_to_s)
{
       return  analyse_downattach(node, packetInfo, is_to_s, get_139_id);
}

int analyse_139_password(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
    if(is_to_s && (1 == http_recive_mail(mail_info, data, data_len)))
    {
        char* p1 = NULL, *p2 = NULL;
        char* tmp_data = mail_info->body;
        char tmp_name[MAX_UN_LEN + 1] = {0};
        char tmp_password[MAX_UN_LEN + 1] = {0};
        
        if(!tmp_data)
            return -1;
        
        p1 = strstr(tmp_data, "UserName=");
        if(!p1)
            return -1;

        p1 += strlen("Username=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_name, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_name, mail_info->username);
        if(!strstr(mail_info->username, "139.com"))
        {
            strcat(mail_info->username, "@139.com");
        }

        p1 = strstr(tmp_data, "Password=");
        if(!p1)
            return -1;

        p1 += strlen("Password=");
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

int analyse_139_recv_mail(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s)
{
    if (!is_to_s)
    {
        char *p1 = NULL, *p2 = NULL;
        int f = http_recive_mail(mail_info, packetInfo->body, packetInfo->bodyLen);
        if (f == 1)
        {
            char *p_content = strstr(mail_info->body, "\"msgContent\":");
            if (p_content)
            {
                p_content = p_content + strlen("\"msgContent\":") + 1;       //   1 is "\""
                char* p_label = strstr(p_content, "\"");
                if (!p_label)
                {
                    //printf("p_label can not found\n");
                    return -1;
                }
                
                mail_info->content = (char *)calloc(1, p_label - p_content + 1);
                if (NULL == mail_info->content)
                    return -1;
                
                memcpy(mail_info->content, p_content, p_label - p_content);
            }
            else
            {
                return -1;
            }

            if ((p1 = strstr(mail_info->body, "\"mailToAddr\":")) != NULL)
            {
                p1 += 14;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->to, p1, p2-p1>MAX_TO_LEN?MAX_TO_LEN:p2-p1);
            }

//not find corresponding data in receive mail packets
/************************************************************************************************
            if ((p1 = strstr(mail_info->body, "\"cc\":")) != NULL)
            {   
                p1 += 6;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->cc, p1, p2-p1>MAX_CC_LEN?MAX_CC_LEN:p2-p1);
            }
		
            if ((p1 = strstr(mail_info->body, "\"bcc\":")) != NULL)
            {
                p1 += 7;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->bcc, p1, p2-p1>MAX_CC_LEN?MAX_CC_LEN:p2-p1);
            }
		
            if ((p1 = strstr(mail_info->body, "\"SentDate\":")) != NULL)
            {		   
                char dest1[MAX_TIME_LEN + 1] = {0};
                time_t timeval;

                p1 += 12;
                //p2 = strstr(p1,"\"");
                memcpy(dest1, p1, 10);

                struct tm *tm_ptr;
                timeval = strtol(dest1, NULL, 0);
                tm_ptr = localtime(&timeval);
                snprintf(mail_info->sent_time, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);	
            }
*************************************************************************************************/		
            if ((p1 = strstr(mail_info->body, "\"mailSenderFrom\":")) != NULL)
            { 		
                p1 += 18;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->from, p1, p2-p1>MAX_FROM_LEN?MAX_FROM_LEN:p2-p1);
            }
	   
            if ((p1 = strstr(mail_info->body,"\"topic\":")) != NULL)
            {		
                p1 += 9;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->subject, p1, p2-p1>MAX_SUBJ_LEN?MAX_SUBJ_LEN:p2-p1);
            }
          
            create_dir(mail_info->save_path, "139", mail_info->from);
            write_to_file(mail_info);
            return -1;
        }
        else if (f < 0)
            return -1;
    }

    return 0;
}

int write_m_139_recive(Mail_info *mail_info)
{
	if(!mail_info->recive_data)
	{
		return -1;
	}

	char* p1 = NULL, *p2 = NULL, *p3 = NULL;
    
	p1 = strstr(mail_info->recive_data, "<script>");
	if(!p1)
	{
		return -1;
	}
	p1 += 8;
	p2 = strstr(p1, "</script>");
	if(!p2)
	{
		return -1;
	}

	char* buf = (char*)malloc(p2 - p1 + 1);
	if(!buf)
	{
		return -1;
	}
	memset(buf, 0, p2 - p1 + 1);
	memcpy(buf, p1, p2 - p1);

	if(strstr(buf, "letterInfo"))
	{
		p1 = strstr(buf, "account:\"");
		p1 += strlen("account:\"");
		
		if(p1)
		{
			p2 = strstr(p1, "\",");
			if(p2)
			{
				memcpy(mail_info->from, p1, p2-p1);
			}
		}

		p1 = strstr(buf, "to:\"");
		p1 += strlen("to:\"");
		if(p1)
		{
			p2 = strstr(p1, "\",");
			if(p2)
			{
				memcpy(mail_info->to, p1, p2-p1);
			}
		}

		p1 = strstr(buf, "subject:\"");
		p1 += strlen("subject:\"");
		if(p1)
		{
			p2 = strstr(p1, "\",");
			if(p2)
			{
				memcpy(mail_info->subject, p1, p2-p1);
			}
		}

		p1 = strstr(buf, "sendDate:");
		
		if(p1)
		{
            p1 += strlen("sendDate:");
			p2 = strstr(p1, ",");
			if(p2)
			{
				memcpy(mail_info->sent_time, p1, p2-p1);
			}
		}
        p1 = strstr(buf, "cc:\"");
        
        if(p1)
        {
            p1 += strlen("cc:\"");
            p2 = strstr(p1, "\",");
            if(p2)
            {
                memcpy(mail_info->cc, p1, p2-p1);
            }
        }
		
	}
	
	free(buf);

	p1 = strstr(mail_info->recive_data, "<body>");
	if(p1)
	{
		p1 += strlen("<body>");
		p2 = strstr(p1, "</body>");
		if(p2)
        {
            char *tmp = (char*)malloc(p2 - p1 + 1);
            memset(tmp, 0, p2 - p1 + 1);
            memcpy(tmp, p1, p2-p1);
            mail_info->content = clear_html_tag(tmp);
            free(tmp);
            clear_tag(mail_info->content);
            create_dir(mail_info->save_path, "139", mail_info->from);
            write_to_file(mail_info);
		}
			
	}
	return 0;
}

int analyse_m_139_recv_mail(Mail_info *mail_info, PacketInfo *packetInfo, int is_to_s)
{
	if(!is_to_s)
	{
		int f = http_recive_mail(mail_info, packetInfo->body, packetInfo->bodyLen);
		if(1 == f)
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
				write_m_139_recive(mail_info);
				return -1;
			}
            else
            {
                mail_info->recive_data = mail_info->body;
                write_m_139_recive(mail_info);
                mail_info->recive_data = NULL;
				return -1;
            }
		}
        else if (f < 0)
            return -1;
	}
	return 0;
}

int analyse_139(PacketInfo *packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned short type;
	int result = 0;

	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
			case 0x12:
				result = analyse_139_password(mail_info,data,data_len,ptcp,is_to_s);
				break;
                
			case 0x11://139 send mail
				result = analyse_139_sendmail(mail_info, data, data_len, ptcp, is_to_s);
				break;
                
			case 0x22://139 receive message
			case 0x23://139 receive message1
				result = analyse_139_rcvmail((void *)mail_info, packetInfo, is_to_s);
				break;
                
            case 0x24:
				result = analyse_139_recv_mail(mail_info, packetInfo, is_to_s);
				break;
				
            case 0x25:
				result = analyse_m_139_recv_mail(mail_info, packetInfo, is_to_s);
				break; 
				
			case 0x81://139 send message
				//printf("send message \n");
				result = analyse_139_sendmsg(mail_info, data, data_len, ptcp, is_to_s);
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
		case 0x61://139 upload attachment
			result = analyse_139_upload_attach(attach_info, data, data_len, ptcp, is_to_s);
			break;
		
		case 0x64: //139 download attachment
			result = analyse_139_download_attach((void *)attach_info, packetInfo, is_to_s);
			break;
		}
		if (result == -1) 
		{
			//printf("delete attachment .....\n");
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}

}
