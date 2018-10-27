
#include <regex.h>
#include <iconv.h>
#include <zlib.h>

#include "PacketParser.h"
#include "mail_type.h"

#define CHUNK 16384

int inflate_read (char *source, int len, char **dest, int *dest_size, int gzip)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];
    int totalsize = 0;
    
    /*  allocate  inflate  state  */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (gzip)
        ret = inflateInit2 (&strm, 47);
    else
        ret = inflateInit (&strm);

    if (ret != Z_OK)
        return ret;

    strm.avail_in = len;
    strm.next_in = (unsigned char *) source;

    /*  run  inflate()  on  input  until  output  buffer  not  full  */
    int i = 0;
    do
    {
        strm.avail_out = CHUNK;
        strm.next_out = out;

        ret = inflate (&strm, Z_NO_FLUSH);
        /*  state  not  clobbered  */
        switch (ret)
        {
            case Z_NEED_DICT:
            ret = Z_DATA_ERROR;
            /*  and  fall  through  */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
            inflateEnd (&strm);
            return ret;
        }
	
        have = CHUNK - strm.avail_out;
        totalsize += have;

        if(i == 0)
        {
            *dest = (char *)malloc(totalsize);
            i = 1;
        }
        else 
            *dest = (char *) realloc (*dest, totalsize);

        memcpy (*dest + totalsize - have, out, have);
    }
    while (strm.avail_out == 0);

    if (dest_size != NULL)
        *dest_size = strm.total_out;

    /*  clean  up  and  return  */
    (void) inflateEnd (&strm);

    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

int reg (char *src, char *pattern, regmatch_t * pm, int n)
{
	regex_t reg;
	int status;
	char errbuf[100];
	status = regcomp (&reg, pattern, REG_EXTENDED | REG_ICASE);
	if (status)
	{
		regerror (status, &reg, errbuf, 100);
		fprintf (stderr, "%s", errbuf);
		return 2;
	}
	status = regexec (&reg, src, n, pm, 0);
	if (status == REG_NOMATCH)
	{
		return 1;
	}
	else if (status)
	{
		regerror (status, &reg, errbuf, 100);
		fprintf (stderr, "%s", errbuf);
		return 3;
	}
	regfree (&reg);
	return 0;
}

void base64Decode (char *input, int in_len, char *out_str)
{
	static int map[256] = { 0 };
	static char b64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t inplen = in_len;
	int words = (inplen + 3) / 4;
	size_t i = 0, j = 0, k = 0;
	int word = 0;
	char *p = input;
	int padnum = 0;

	for (i = 0; i < 64; ++i)
	{
		map[(int) b64[i]] = i;
	}
	if (input[inplen - 1] == '=')
		padnum = 1;
	if (input[inplen - 1] == '=' && input[inplen - 2] == '=')
		padnum = 2;

	for (i = 0; i < words; i++)
	{
			word = 0;
			word |= map[(int) *p++];
			word <<= 6;
			word |= map[(int) *p++];
			word <<= 6;
			word |= map[(int) *p++];
			word <<= 6;
			word |= map[(int) *p++];

			out_str[k++] = word >> 16 & 0xFF;

			if (i + 1 == words && padnum == 2)
				break;

			out_str[k++] = word >> 8 & 0xFF;

			if (i + 1 == words && padnum == 1)
				break;

			out_str[k++] = word & 0xFF;
		}
	out_str[k] = '\0';
	return;
}

unsigned int getAttachSplitHash(char * s)
{
	unsigned int rt=0;
	while(*s!='\r' && *s!='\n')
	{
		rt+=(*s-'0');
		s++;
	}
	return rt;
}
int Get_Attach_Num()
{
	Attach_info *sjs = attach_tab.head->next;
	int i = 0, flag = 0;

	while (sjs != NULL) 
	{
		i++;
		sjs = sjs->next;
	}
	
	return i;
}

void show_mail_list()
{
	Mail_info * info = mail_tab.head;
	while(info)
	{
		//printf("%s\n", info->mail_id);
		info = info->next;
	}
}

char *conv_163_to_utf8(char *src)
{
	char *tmp_str = NULL, *dest = NULL;
	size_t len, utf8_len;
	int result;

	len = strlen(src);
	utf8_len = len * 3 / 2 + 1;
	dest = (char *)malloc(utf8_len + 1);
	if (NULL == dest) 
	{
		LOG_WARN("webmail:conv_163_to_utf8(): malloc() return NULL\n");
		return NULL;
	}
	result = code_convert("gb18030", "utf-8", src, len, dest, utf8_len);
	if (-1 == result) 
	{
		LOG_WARN("webmail:conv_163_to_utf8(): code_convert() return NULL\n");
		return NULL;
	} 
	else 
	{ 
		return dest;
	}
}

int str_163_convert1(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = conv_to_xml_symbol(str);
	if (tmp1 == NULL) {
		LOG_WARN("webmail:str_163_convert1(): conv_to_xml_symbol() return NULL\n");
		return -1;
	}
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;

	return 0;
}

int str_163_convert2(char *str, size_t max_len)
{
	char *tmp1 = NULL;
	size_t len;

	tmp1 = conv_163_to_utf8(str);
	if (NULL == tmp1) {
		LOG_WARN("webmail:str_163_convert2(): conv_163_to_utf8() return NULL\n");
		return -1;
	}
	len = strlen(tmp1);
	if (len > max_len)
		len = max_len;
	memcpy(str, tmp1, len);
	str[len] = 0;
	free(tmp1);
	tmp1 = NULL;
	
	return 0;
}

int writefile163(Mail_info *mail_info)
{
	Attach_info *attach_info;
	char *p1 = NULL, *p2 = NULL, *p3 = NULL, *tmp_str = NULL, *sit;
	size_t len, total_len;
	int result, fd, n, i = 0, flag = 0;
	Attachment *attachment = NULL;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

	htmldecode_full(mail_info->mail_data, mail_info->mail_data);
	
	p1 = strstr(mail_info->mail_data, "sid=");
	sit=p1;
	if (p1 != NULL) 
	{
		p1 += 4;
		p2 = strstr(p1, "&func=");
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		if (len > MAX_ID_LEN)
			len = MAX_ID_LEN;
		memcpy(ID, p1, len);
		ID[len] = 0;//printf("\nID = %s\n",ID);
		p2 += 8;
	} 
	else 
	{
		ID[0] = 0;
		LOG_WARN("webmail:writefile163(): can not find ID\n");
	}
	
	p1 = strstr(mail_info->mail_data, "<string name=\"account\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailfrom start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailfrom end\n");
		return -1;
	}
	p3 = memfind(p1, "&lt;", len);
	if (p3 != NULL) 
	{
		p2 = memfind(p1, "&gt;", len);
		if (p2 != NULL && p2 > p3 && p2 - p1 < len) 
		{
			p1 = p3 + 4;
			len = p2 - p1;
		}
	}
	if (len > MAX_FROM_LEN)
		len = MAX_FROM_LEN;
	memcpy(mail_info->from, p1, len);
	mail_info->from[len] = 0;
	p2 += 8;
	//printf("mail_info->from : %s\n", mail_info->from);

	p1 = strstr(p2, "<array name=\"to\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailto start\n");
		return -1;
	}
	p1 += 17;
	//p3 = strstr(p1, "</string></array>");
	p3 = strstr(p1, "</array>");
	if (p3 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailto end\n");
		return -1;
	}
	total_len = 0;
	p2 = p1;
	while (p2 < p3) 
	{
		p1 = strstr(p2, "<string>");
		if (p1 == NULL)
			break ;
		p1 += 8;
		p2 = strstr(p1, "</string>");
		if (p2 == NULL)
			break ;
		len = p2 - p1;
		if (p2 == NULL || (total_len + len + 1) > MAX_TO_LEN)  //为�?��?个�?�箱?��????��??��??
			break ;
		memcpy(mail_info->to + total_len, p1, len);
		total_len += len;
		mail_info->to[total_len] = ';';
		total_len++;
		mail_info->to[total_len] = 0;
		p2 += 9;
	}
	p2 = p3 + 17;

	p1 = strstr(mail_info->mail_data, "<array name=\"cc\">");
	if (p1 != NULL) 
	{
		p1 += 17;
		p3 = strstr(p1, "</string></array>");
		if (p3 == NULL)
			return -1;
		total_len = 0;
		p2 = p1;
		while (p2 < p3) 
		{
			p1 = strstr(p2, "<string>");
			if (p1 == NULL)
				break ;
			p1 += 8;
			p2 = strstr(p1, "</string>");
			if (p2 == NULL)
				break ;
			len = p2 - p1;
			if (p2 == NULL || (total_len + len + 1) > MAX_CC_LEN)
				break ;
			memcpy(mail_info->cc + total_len, p1, len);
			total_len += len;
			mail_info->cc[total_len] = ';';
			total_len++;
			mail_info->cc[total_len] = 0;
			p2 += 9;
		}
		p2 = p3 + 17;
	} 
	else 
	{
		mail_info->cc[0] = 0;
	}

	p1 = strstr(mail_info->mail_data, "<array name=\"bcc\">");
	if (p1 != NULL) 
	{
		p1 += 18;
		p3 = strstr(p1, "</string></array>");
		if (p3 == NULL)
			return -1;
		total_len = 0;
		p2 = p1;
		while (p2 < p3) 
		{
			p1 = strstr(p2, "<string>");
			if (p1 == NULL)
				break;
			p1 += 8;
			p2 = strstr(p1, "</string>");
			if (p2 == NULL)
				break;
			len = p2 - p1;
			if (p2 == NULL || (total_len + len + 1) > MAX_BCC_LEN)
				break;
			memcpy(mail_info->bcc + total_len, p1, len);
			total_len += len;
			mail_info->bcc[total_len] = ';';
			total_len++;
			mail_info->bcc[total_len] = 0;
			p2 += 9;
		}
		p2 = p3 + 17;
	} 
	else 
	{
		mail_info->bcc[0] = 0;
	}

	p1 = strstr(p2, "<string name=\"subject\">");
	if (p1 == NULL)
		p1 = strstr(mail_info->mail_data, "<string name=\"subject\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailsubject start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) {
		LOG_WARN("webmail:writefile163(): can not find mailsubject end\n");
		return -1;
	}
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;
	p2 += 8;
	//printf("mail_info->subject : %s\n", mail_info->subject);

	p1 = strstr(p2, "<string name=\"content\">");
	if (p1 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailcontent start\n");
		return -1;
	}
	p1 += 23;
	p2 = strstr(p1, "</string>");
	len = p2 - p1;
	if (p2 == NULL) 
	{
		LOG_WARN("webmail:writefile163(): can not find mailcontent end\n");
		return -1;
	}
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL) 
	{
		LOG_WARN("webmail:writefile163()");
		return -1;
	}
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += 8;
	//printf("mail_info->content : %s\n", mail_info->content);

	create_dir(mail_info->save_path, "163" ,mail_info->from);//lihan

	if (strstr(p2, "<object name=\"attachments\">") != NULL)
	//if (strstr(sit, "<object name=\"attrs\">") != NULL)
	{
		//printf("11111\n");
	
		int fd, atta_fd;
		struct stat st;
		char *mapped = NULL;
		char *p1, *p2;
		char filename[MAX_FN_LEN + 1];
		char writepath[MAX_PATH_LEN + 1];
		Attachment *attachment;
		int flag = 0, i = 0;

		//printf("ID : %s\n", ID);
		attach_info = find_attach(ID);
		if (attach_info == NULL)
			return -1;	   //?��?��?��?��???��??��?????
		
		//printf("2222222222222\n");
		
		fd = open(attach_info->path_of_here, O_RDWR);
		if (fstat(fd, &st) < 0) 
		{
			return -1;
		}

		mapped = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (mapped == NULL) 
		{
			close(fd);
			return -1;
		}
		p1 = mapped;
			
		while (1)
		{
			p1 = strstr(p1, "filename=\"");
			if (p1 == NULL)
				break;
			p1 += 10;
			if (*p1 == '\"')
				continue;
			p2 = strstr(p1, "\"\r\nContent-Type: ");
			if (p2 == NULL)
				break;
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if (attachment == NULL) 
			{
				LOG_WARN("webmail:writefile163(): attachment node malloc() return NULL\n");
				return -1;
			}
			if (!flag) 
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
			len = p2 - p1;
			if (len > MAX_PATH_LEN)
				len = MAX_PATH_LEN;
			memcpy(attachment->path_of_sender, p1, len);
			attachment->path_of_sender[len] = 0;
			i++;
			tmp_str = conv_163_to_utf8(attachment->path_of_sender);
			if (tmp_str == NULL) 
			{
				LOG_WARN("webmail:writefile163(): conv_163_to_utf8() return NULL\n");
				return -1;
			}
			get_file_name(tmp_str, filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
			free(tmp_str);
			tmp_str = NULL;
			p1 = strstr(p2, "\r\n\r\n");
			if (p1 == NULL) 
			{
				LOG_WARN("webmail:writefile163(): can not find attach content start\n");
				return -1;
			}
			p1 += 4;
			len = st.st_size - (p1 - mapped);
			p2 = memfind(p1, "Content-Disposition: form-data; name", len);//��????��??��??boundary ??��?��??�好��??��????件信?��????头已��?丢�?��?
			if (p2 == NULL) 
			{
				LOG_WARN("webmail:writefile163(): can not find attach content end\n");
				return -1;
			}
			snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
			atta_fd = open(writepath, O_RDWR | O_CREAT, file_mode);
			if (atta_fd == -1) 
			{
				p1 = p2;
				continue;
			}
			write(atta_fd, p1, p2 - p1);
			close(atta_fd);
			trim_attach(writepath, 45);
			p1 = p2;
		}
		munmap(mapped, st.st_size);
		close(fd);
		mail_info->num_of_attach = i;
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);
	} 
	else 
	{
		//printf("22222\n");
	
		char filename[MAX_FN_LEN + 1];
		Attach_info *attach_tmp;
		Attachment *attachment;
		Attach_info *attach_info = attach_tab.head->next;
		int i = 0, flag = 0;

		while (attach_info != NULL) 
		{
			//printf("attach info ...\n");
			//printf("%s	...	%s\n", attach_info->ID_str, ID);
			if (!strcmp(attach_info->ID_str, ID))
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
				snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_name);//lihan
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
	}

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
}

int writefile_vip_163_danya(Mail_info *mail_info)
{
	Attach_info *attach_info = NULL;
	char boundary[MAX_BOUN_LEN + 1];
	char *p1 = NULL, *p2 = NULL, *tmp_str = NULL, *tmp_str2 = NULL;
	size_t len, boun_len;
	int result, fd, n, i = 0, flag = 0;
	Attachment *attachment;
	mode_t file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
	char attach_tag[MAX_BOUN_LEN + 101];
	char filepath[MAX_PATH_LEN + 1], filename[MAX_FN_LEN + 1];
	char writepath[MAX_PATH_LEN + 1], ID[MAX_ID_LEN + 1];

	boun_len = get_boundary(mail_info->mail_data, boundary);
	if (boun_len == -1 || boun_len > MAX_BOUN_LEN) {
		return -1;
	}

	snprintf(attach_tag, MAX_BOUN_LEN + 100, "%s\r\nContent-Disposition: form-data; name=\"attachfile", boundary);

	p1 = strstr(mail_info->mail_data, "; NETEASE_VIP=");
	if (p1 == NULL)
		return -1;
	p1 += 14;
	p2 = strstr(p1, ";");
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len + 12 > MAX_FROM_LEN)
		len = MAX_FROM_LEN - 12;
	memcpy(mail_info->from, p1, len);
	memcpy(mail_info->from + len, "@vip.163.com", 12);
	mail_info->from[len + 12] = 0;
	p2++;

	p1 = strstr(p2, "name=\"text\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 15;
	p2 = strstr(p1, boundary);
	p2 -= 4;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, p1, len);
	mail_info->content[len] = 0;
	p2 += boun_len;

	p1 = strstr(p2, "name=\"to\"\r\n\r\n");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "name=\"to\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 13;
	p2 = strstr(p1, boundary);
	p2 -= 4;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_TO_LEN)
		len = MAX_TO_LEN;
	memcpy(mail_info->to, p1, len);
	mail_info->to[len] = 0;
	p2 += boun_len;

	p1 = strstr(p2, "name=\"cc\"\r\n\r\n");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "name=\"cc\"\r\n\r\n");
	if (p1 != NULL) {
		p1 += 13;
		p2 = strstr(p1, boundary);
		p2 -= 4;
		len = p2 - p1;
		if (p2 != NULL && len > 10) {
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

	p1 = strstr(p2, "name=\"bcc\"\r\n\r\n");
	if (NULL == p1)
		p1 = strstr(mail_info->mail_data, "name=\"bcc\"\r\n\r\n");
	if (p1 != NULL) {
		p1 += 14;
		p2 = strstr(p1, boundary);
		p2 -= 4;
		len = p2 - p1;
		if (p2 != NULL && len > 10) {
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

	p1 = strstr(p2, "name=\"subject\"\r\n\r\n");
	if (p1 == NULL)
		return -1;
	p1 += 18;
	p2 = strstr(p1, boundary);
	p2 -= 4;
	len = p2 - p1;
	if (p2 == NULL)
		return -1;
	if (len > MAX_SUBJ_LEN)
		len = MAX_SUBJ_LEN;
	memcpy(mail_info->subject, p1, len);
	mail_info->subject[len] = 0;

	create_dir(mail_info->save_path, "163" ,mail_info->from);

	while (1) {
		p1 = strstr(p2, attach_tag);
		if (p1 == NULL)
			break;
		p1 = strstr(p1, "; filename=\"");
		if (p1 == NULL)
			return -1;
		p1 += 12;
		p2 = strstr(p1, "\"\r\nContent-Type");
		len = p2 - p1;
		if (len == 0)
			continue;
		if (p2 == NULL)
			return -1;
		if (len > MAX_PATH_LEN)
			len = MAX_PATH_LEN;
		memcpy(filepath, p1, len);
		filepath[len] = 0;
		p1 = strstr(p2, "\r\n\r\n");
		if (p1 == NULL)
			return -1;
		p1 += 4;
		len = mail_info->mail_length - (p1 - mail_info->mail_data);
		p2 = memfind(p1, boundary, len);
		p2 -= 2;
		len = p2 - p1;
		if (p2 == NULL)
			return -1;
		get_file_name(filepath, filename);
		attachment = (Attachment *)malloc(sizeof(Attachment));
		if (attachment == NULL)
			return -1;
		i++;
		if (!flag) {
			attachment->next = NULL;
			mail_info->attach = attachment;
			flag = 1;
		} else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		tmp_str = conv_163_to_utf8(filename);
		if (tmp_str == NULL)
		{
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, filename);
		}
		else
		{
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d_%s", i, tmp_str);
			free(tmp_str);
			tmp_str = NULL;
		}
		
		snprintf(writepath, MAX_PATH_LEN, "%s/%s", mail_info->save_path, attachment->loc_filename);
		fd = open(writepath, O_RDWR | O_CREAT, file_mode);
		if (fd == -1)
			return -1;
		write(fd, p1, len);
		close(fd);
	}

	mail_info->num_of_attach = i;

	result = str_163_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = str_163_convert2(mail_info->cc, MAX_CC_LEN);
	if (result == -1)
		return -1;
	result = str_163_convert2(mail_info->bcc, MAX_BCC_LEN);
	if (result == -1)
		return -1;
	result = str_163_convert2(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;

	if (mail_info->content != NULL) 
	{
		tmp_str = conv_163_to_utf8(mail_info->content);
		if (tmp_str == NULL)
			return -1;

		free(mail_info->content);
		mail_info->content = clear_html_tag(tmp_str);
		free(tmp_str);
		tmp_str = NULL;
	}
	write_to_file(mail_info);
}

int proce_163_attach1_head(Attach_info *attach_info,char *data, unsigned int datalen, unsigned int seq)
{
	int fd;
	char *p1 = NULL, *p2 = NULL;
	struct timeval tv;
	struct timezone tz;
	mode_t file_mode = S_IRUSR | S_IWUSR |S_IRGRP|S_IROTH;
	int off_seq;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p1 = strstr(attach_info->ok_data, "filename=\"");
	if (p1 == NULL)
		return 0;
	p2 = strstr(p1, "\r\n\r\n");
	if (p2 == NULL) {
		return 0;
	}
	p2 += 4;
	attach_info->start_seq = p1 - attach_info->ok_data + attach_info->start_seq;
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
	if (fd == -1)
		return -1;
	write(fd, p1, off_seq + datalen - (p1 - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1;

	return 0;
}

int proce_163_attach2_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	struct timeval tv;
	struct timezone tz;
	char *p = NULL;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data,"filename=\"");
	if (p == NULL)
		return 0;
	p = strstr(p, "\r\n\r\n");
	if (p == NULL) {
		return 0;
	}
	p += 4;

	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);
	if (result == -1)
		return -1;
	result = regcompile_1(attach_info->ok_data, "&composeId=(.*)&offset=", attach_info->ID_str, MAX_ID_LEN);
	if (result == -1) {
		return -1;
	}

	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;
	gettimeofday(&tv, &tz);
	snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	fd = open(attach_info->path_of_here, O_RDWR|O_CREAT,file_mode);
	if (fd == -1)
		return -1;
	write(fd, p, off_seq + datalen - (p - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1; 

	return 0;
}

int proce_163_attach3_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
// 	char file_name_pattern2[] = "Mail-Upload-name: (.*?)\r\nMail-Upload-size";
	char file_name_pattern2[] = "Mail-Upload-name: (.*?)\r\n(Mail-Upload-size|Origin)";
	struct timeval tv;
	struct timezone tz;
	char *p = NULL;
	int off_seq;
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int result;

	off_seq = seq - attach_info->start_seq;
	if (off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);
	if(!strstr(attach_info->ok_data,"\r\n\r\n")) return 0;

	p = strstr(attach_info->ok_data,"filename=\"");
	if (p == NULL)
	{
		p = strstr(attach_info->ok_data,"Mail-Upload-name: ");
		if (p == NULL)
			return 0;
		else
		{
			p+=18;
			char * p2 = strstr(p,"\r\n");
			attach_info->path_of_sender=(char *)malloc(p2-p+1);
			memcpy(attach_info->path_of_sender,p,p2-p);
			attach_info->path_of_sender[p2-p]=0;
		}
	}
	else
	{
		p+=10;
		char * p2=strstr(p,"\"");
		if(!p2) return 0;
		attach_info->path_of_sender=(char *)malloc(p2-p+1);
		memcpy(attach_info->path_of_sender,p,p2-p);
		attach_info->path_of_sender[p2-p]=0;
	}
	htmldecode_full(attach_info->path_of_sender,attach_info->path_of_sender);

	
	
	//printf("attach_info->ok_data : %s\n", attach_info->ok_data);
/*
	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);
	if (result == -1)
	{
		result = regcompile_2(attach_info->ok_data, file_name_pattern2, &attach_info->path_of_sender);
		if(result == -1)
			return -1;
	}*/

	//result = regcompile_1(attach_info->ok_data, "sid=(.*)&", attach_info->ID_str, MAX_ID_LEN);
	//if (result == -1) {
	//	attach_info->ID_str[0] = 0;
	//}
	char * p2,*p3;
	p2=strstr(attach_info->ok_data,"sid=");
	if(!p2) return -1;
	p2+=4;
	p3=strstr(p2,"&");
	int len=p3-p2>MAX_ID_LEN?MAX_ID_LEN:p3-p2;
	memcpy(attach_info->ID_str,p2,len);
	attach_info->ID_str[len]=0;
	/*p2=strstr(attach_info->ok_data,"Mail-Upload-modtime: ");
	p2+=21;
	attach_info->recive_length=getAttachSplitHash(p2);// as a mark for split attach
	*/
	p2=strstr(attach_info->ok_data,"Mail-Upload-size: ");
	p2+=18;
	unsigned int totalSize=0;
	for(;*p2!='\r'&&*p2!='\n';p2++)
	{
		totalSize=totalSize*10+(*p2-'0');
	}
	attach_info->ok_length=totalSize;
	int f=0;
	Attach_info * att = attach_tab.head->next;
	while(att)
	{
		if(att!=attach_info &&strcmp(att->ID_str,attach_info->ID_str)==0&&att->recive_length!=att->ok_length)
		{
			att->is_complished=0;
			del_attach_node(attach_info);
			delete_attach(attach_info);
			attach_info=att;
			f=1;
			break;
		}
		att=att->next;
	}
	p=strstr(data,"\r\n\r\n");
	p+=4;
	attach_info->start_seq = p - data +seq;
	gettimeofday(&tv, &tz);
	if(!f) snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu", mail_temp_path, tv.tv_sec, tv.tv_usec);
	//printf("mail_temp_path : %s\n", mail_temp_path);
	//printf("attach_info->path_of_here : %s\n", attach_info->path_of_here);
	/*char temp[MAX_PATH_LEN + 1];
	memset(temp, 0, MAX_PATH_LEN + 1);
	int codeid = code_convert("gb2312", "default", attach_info->path_of_here, strlen(attach_info->path_of_here), temp, MAX_PATH_LEN);
	if (codeid != -1)
	{
		//printf("*** utf-8 ***\n");
		memset(attach_info->path_of_here, 0, MAX_PATH_LEN + 1);
		sprintf(attach_info->path_of_here, "%s", temp);
}*/
	fd = open(attach_info->path_of_here, O_WRONLY|O_CREAT);
	if (fd == -1)
		return -1;
	//if(!memcmp(data+datalen-4,"--\r\n",4) || strstr(data,"\r\n----"))
	//	datalen -= 46;
		//datalen = strstr(data,"\r\n----") - data;
	lseek(fd,attach_info->recive_length,SEEK_SET);
	//printf("ok_length:%d, recive_length:%d,attach_info:%p\n",attach_info->ok_length,attach_info->recive_length,attach_info);
	write(fd, p, datalen-(p-data));
	close(fd);
	attach_info->is_writing = 1;
	return 0;
}

int write_163_psword(Mail_info *mail_info)
{//printf("\nwrite_163_psword\n");
	char *p1 = NULL, *p2= NULL;
	size_t len;
	int set;

	p1 = strstr(mail_info->mail_data, "username=");
	if (p1 == NULL)
	{
		set=6;
		p1 = strstr(mail_info->mail_data, "&user=");
	}
	else
	{
		set=9;
	}
	if (p1 == NULL)
		return -1;

	p1 += set;
	p2 = strstr(p1, "&");
	len = p2 - p1;
	if (p2 == NULL || len > MAX_UN_LEN)
		return -1;
	memcpy(mail_info->username, p1, len);
	mail_info->username[len] = 0;
	htmldecode_full(mail_info->username,mail_info->username);
	if (!(strstr(mail_info->username, "@163.com") || strstr(mail_info->username, "@126.com") || strstr(mail_info->username, "@yeah.net"))) 
	{
		if (len + 8 > MAX_UN_LEN)
			return -1;
		strcat(mail_info->username, "@163.com");
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
	//LOG_INFO("mail_info->password = %s\n", mail_info->passwd);
	fclose(fp);

	return 0;
}

int analyse_163_passwd(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//printf("\nanalyse_163_passwd\n");
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
		if(strstr(mail_info->mail_data,"&password="))
		{
			write_163_psword(mail_info);
			return -1;
		}
	}
	else if(!strncmp(data,http_ok_head,9))
	{
		//printf("Data recive successfully!");
		write_163_psword(mail_info);
		return -1;
	}

	return 0;
}

int analyse_163_login(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{
    if(is_b_s && (1 == http_recive_mail(mail_info, data, datalen)))
    {
        char* p1 = NULL, *p2 = NULL;
        char* tmp_data = mail_info->body;
        char tmp_name[MAX_UN_LEN + 1] = {0};
        char tmp_password[MAX_UN_LEN + 1] = {0};
        
        if(!tmp_data)
            return -1;
        
        p1 = strstr(tmp_data, "username=");
        if(!p1)
            return -1;

        p1 += strlen("username=");
        p2 = strchr(p1, '&');
        if(!p2)
            return -1;

        memcpy(tmp_name, p1, (p2 - p1) > MAX_UN_LEN ? MAX_UN_LEN : (p2 - p1));
        htmldecode_full(tmp_name, mail_info->username);
        if(!strstr(mail_info->username, "163.com") && !strstr(mail_info->username, "yeah.net"))
        {
            strcat(mail_info->username, "@163.com");
        }

        p1 = strstr(tmp_data, "password=");
        if(!p1)
            return -1;

        p1 += strlen("password=");
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

int analyse_163_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{//printf("\n							  163\n");
	int result;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			if (!strncmp(data, "<?xml version=\"1.0\"?><object/>", 32)) 
			{
				return -1;
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
	{
		//printf("analyse_163_mail ... mail up ...\n");
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		writefile163(mail_info);   //��??? ?????? ?? ???��??
		del_mail_node(mail_info);

		return 0;
	} 
	else 
	{
		return -1;
	}
}

int analyse_163_mail2(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s) 
{
	int result;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} 
	else 
	if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 302 Found\r\n", 12))
	{
		mail_info->is_complished = 1;
		get_time(data, mail_info->sent_time);
		writefile_vip_163_danya(mail_info);
		del_mail_node(mail_info);
		return 0;
	} 
	else 
	{
		return -1;
	}
}

int writefile163_rcvmail1(Mail_info *mail_info)
{
	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;

	char *pstart = NULL, *front, *back;
	char *pend = NULL;
	char *tmp_str = NULL;
	char tmp_from[MAX_FROM_LEN + 1];
	size_t len;
	int result;
	
//LOG_INFO("******* 111 ********\n%s\n", mail_info->mail_data);
	
	front = strstr(mail_info->mail_data, "&mid=");
	if(front == NULL)
		return -1;
	front += 5;
	back = strstr(front, " HTTP/1.1\r\n");
	if(back == NULL)
		return -1;
	len = back - front;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->mail_id, front, len);
	mail_info->mail_id[len] = 0;
	//htmldecode_full(mail_info->mail_id, mail_info->mail_id);
	//printf("\nmail_info->mail_id : %s\n", mail_info->mail_id);

	//fetch from
	pstart = strstr(mail_info->recive_data, "'from':['");
	if (pstart == NULL)
		return -1;
	pstart += 9;
	pend = strstr(pstart, "']");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	//fetch to
	pstart = strstr(pend, "'to':['");
	if (pstart == NULL)
		return -1;
	pstart += 7;
	pend = strstr(pstart, "']");
	len = pend - pstart;
	len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
	memcpy(mail_info->to, pstart, len);
	mail_info->to[len] = 0;

	//fetch cc
	pstart = strstr(pend, "'cc':['");
	if (pstart != NULL) {
		pstart += 7;
		pend = strstr(pstart, "']");
		len = pend - pstart;
		len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
		memcpy(mail_info->cc, pstart, len);
		mail_info->cc[len] = 0;
	}

	//fetch subject
	pstart = strstr(pend, "'subject':'");
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pend = strstr(pstart, "',\n");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;

	pstart = strstr(pend, "\n'sentDate':new Date(");
	if (pstart == NULL)
		return -1;
	pstart += 21;
	pend = strstr(pstart, "),");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (len > MAX_TIME_LEN)
		return -1;
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;

	//fetch content
	pstart = strstr(pend, "'content':'");
	if (pstart == NULL)
		return -1;
	pstart += 11;
	pend = strstr(pstart, "'},\n'text':");
	if (pend == NULL) {
		pend = strstr(pstart, "</body>");
		if (pend == NULL) {
			pend = strstr(pstart, "}}}]}");
			if (pend == NULL)
				return -1;
		}

	}
	len = pend - pstart;
	mail_info->content = (char *)malloc(len + 1);
	if (mail_info->content == NULL)
		return -1;
	memcpy(mail_info->content, pstart, len);
	mail_info->content[len] = 0;

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

/*
	result = str_163_convert1(mail_info->from, MAX_FROM_LEN);
	if (result == -1)
		return -1;
	result = str_163_convert1(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;
	result = str_163_convert1(mail_info->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;
*/
	tmp_str = clear_html_tag(mail_info->content);
	if (tmp_str == NULL)
		return -1;
	free(mail_info->content);
	mail_info->content = tmp_str;
/*	mail_info->content = conv_xml_symbol(tmp_str);
	free(tmp_str);
	tmp_str = NULL;
	if (mail_info->content == NULL)
		return -1;
*/
	tmp_str = NULL;

	clear_from(mail_info->from);
	create_dir(mail_info->save_path, "163", mail_info->from);
	write_to_file(mail_info);

	return 0;
}

int get_163_rcv_id2(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;

	pstart = strstr(mail_info->mail_data, "P_INFO=");
	if (pstart == NULL)
		return -1;
	pstart += 7;
	pend = strstr(pstart, "; ");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
	memcpy(mail_info->connect_id, pstart, len);
	mail_info->connect_id[len] = 0;

	return 0;
}

int writefile163_rcvmail2(Mail_info *mail_info)
{
	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;

	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	int result;

	pstart = strstr(mail_info->body, "</style>\r\n");
	if(pstart == NULL)
		return -1;
		
	pstart += 10;
	mail_info->content = pstart;
	char *tmp = clear_html_tag(mail_info->content);
	if (tmp != NULL)
	{
		mail_info->content = tmp;
		pend = strstr(mail_info->content, "<script language=\"javascript\">");
		if(pend == NULL)
			pend = strstr(mail_info->content, "<script type=\"text/javascript\">");
		if(pend)
		{
			int length = pend - mail_info->content;
			char * temp = (char *)malloc(length + 1);
			memset(temp, 0, length + 1);
			memcpy(temp, mail_info->content, length);
			free(mail_info->content);
			mail_info->content = temp;
		}
		pend = strstr(mail_info->content, "try{parent.JS.modules");
		if(pend == NULL)
			pend = strstr(mail_info->content, "try{if(parent.");
		if(pend)
		{
			int length = pend - mail_info->content;
			char * temp = (char *)malloc(length + 1);
			memset(temp, 0, length + 1);
			memcpy(temp, mail_info->content, length);
			free(mail_info->content);
			mail_info->content = temp;
		}
	}

	mail_info->mail_type = 0x0423;
	Mail_info *pre_mail = NULL;
	pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
	if (pre_mail != NULL)
	{
		if(pre_mail->from != NULL)
		{
			strcpy(pre_mail->mail_id, mail_info->mail_id);
			clear_from(pre_mail->from);
			pre_mail->content = clear_html_tag(mail_info->content);
			clear_tag(pre_mail->content);
			down_contents(pre_mail->content);
			create_dir(pre_mail->save_path, "163" ,pre_mail->from);
			write_to_file(pre_mail);
//			write_oracle_db_cookieinfo(pre_mail);
			del_mail_node(pre_mail);
			del_mail_node(mail_info);
		}
	}
	else if(strlen(mail_info->from) > 0)
	{
// 		printf("mail_info->mail_id : %s\n", mail_info->mail_id);
// 		printf("mail_info->from : %s\n", mail_info->from);
// 		printf("mail_info->bcc : %s\n", mail_info->bcc);
// 		printf("mail_info->cc : %s\n", mail_info->cc);
// 		printf("mail_info->to : %s\n", mail_info->to);
// 		printf("mail_info->subject : %s\n", mail_info->subject);
// 		printf("mail_info->sent_time : %s\n", mail_info->sent_time);
// 		printf("mail_info->content : %s\n", mail_info->content);
        create_dir(mail_info->save_path, "163", mail_info->from);
		write_to_file(mail_info);
//		write_oracle_db_cookieinfo(mail_info);
		del_mail_node(mail_info);
	}
	
	return 0;
}

int analyse_163_rcvmail1(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;
	char *dest = NULL;

	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			//printf("result : %d\n", result);
			return result;
		}
	} 
	else 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_okdata(mail_info, data, data_len, ptcp);
			if (result == -1)
			{
				//printf("write_to_okdata ... Error!\n");
				return -1;
			}
		}
		
		if ((ntohl(ptcp->seq) + data_len - mail_info->http_seq == mail_info->recive_length) || data_len < 7 || (strncmp(data + data_len - 7, "\r\n0\r\n\r\n", 7) == 0) || (strncmp(data + data_len - 5, "}}}]}", 5) == 0)) 
		{
			char *hostp = NULL;

			mail_info->is_complished = 1;
			
			hostp = strstr(mail_info->mail_data, "Host:");
			if (hostp == NULL)
			{
				//printf("hostp ... Error!\n");
				return -1;
			}
			if (memfind(hostp, "vip", 50) == NULL) 
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
			
			writefile163_rcvmail1(mail_info);
			del_mail_node(mail_info);
			
			return 0;
		}
	}
}

int analyse_163_rcvmail2(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result = 0;
	int f_val = 0;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;

    if (!is_to_s)
    {
        f_val = http_recive_mail(mail_info, data, data_len);
        if (1 == f_val)
        {
            if (NULL == mail_info->body || NULL == mail_info->header)
                return -1;
            
            mail_info->is_complished = 1;
			if(strstr(mail_info->header, "Content-Encoding: gzip\r\n"))
				flag = 1;
			else
				flag = 0;

            if(flag == 1)
            {
                if (mail_info->is_ok_chunked)
                {
                    Chunked(mail_info);//printf("\nmail_info->recive_length2222 = %d, mail_info->recive_data2222 = %s\n",mail_info->recive_length,mail_info->recive_data);
                    result = decomp_gzip_3(mail_info->body, mail_info->bodyLen, &dest);
                    if(result == -1)
                    {
                        result = decomp_gzip_1(mail_info->body, mail_info->bodyLen, &dest);
                        if(result == -1)
                        {
                            result = decomp_gzip_2(mail_info->body, mail_info->bodyLen, &dest);
                            if(result == -1) 
                                result = decomp_gzip(mail_info->body, mail_info->bodyLen, &dest);
                        }
                    }
                }
                else
                {
                    result = decomp_gzip_3(mail_info->body, mail_info->bodyLen - 2, &dest);
                    if(result == -1)
                    {
                        result = decomp_gzip_1(mail_info->body, mail_info->bodyLen - 2, &dest);
                        if(result == -1)
                        {
                            result = decomp_gzip_2(mail_info->body, mail_info->bodyLen - 2, &dest);
                            if(result == -1) 
                                result = decomp_gzip(mail_info->body, mail_info->bodyLen - 2, &dest);
                        }
                    }
                }
                
                if (result == -1) 
                {
                    LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
                    return -1;
                }
                
                free(mail_info->body);
                mail_info->body = dest;
                dest = NULL;
            }

            writefile163_rcvmail2(mail_info);
            return 0;
    	}
        else if (f_val < 0)
            return -1;
    }

    return 0;
}

int writefile163_rcvmail3(Mail_info *mail_info)
{
	size_t len;
	//Mail_info *pre_mail = NULL;
	int result;
	char *front, *back, *pstart, *pend;
	char *tmp = NULL;

	strcpy(mail_info->connect_id, mail_info->mail_id);
	
	pstart = strstr(mail_info->recive_data, "\n'from':['");
    if (pstart)
    {
        pstart += 10;
        pend = strstr(pstart, "'],\n");
        if (pend)
        {
            len = pend - pstart;
            len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
            memcpy(mail_info->from, pstart, len);
            mail_info->from[len] = 0;
        }
    }
	else
	{
		mail_info->from[0] = 0;
	}
    
	pstart = strstr(pend, "\n'to':['");
    if (pstart)
    {
        pstart += 8;
        pend = strstr(pstart, "'],\n");
        if (pend)
        {
            len = pend - pstart;
            len = (len > MAX_TO_LEN ? MAX_TO_LEN : len);
            memcpy(mail_info->to, pstart, len);
            mail_info->to[len] = 0;
        }
    }
	else
	{
		mail_info->to[0] = 0;
	}

	pstart = strstr(pend, "\n'cc':['");
    if (pstart)
    {
        pstart += 8;
        pend = strstr(pstart, "'],\n");
        if (pend)
        {
            len = pend - pstart;
            len = (len > MAX_CC_LEN ? MAX_CC_LEN : len);
            memcpy(mail_info->cc, pstart, len);
            mail_info->cc[len] = 0;
        }
    }
	else
	{
		mail_info->cc[0] = 0;
	}

	pstart = strstr(pend, "\n'bcc':['");
    if (pstart)
    {
        pstart += 8;
        pend = strstr(pstart, "'],\n");
        if (pend)
        {
            len = pend - pstart;
            len = (len > MAX_BCC_LEN ? MAX_BCC_LEN : len);
            memcpy(mail_info->bcc, pstart, len);
            mail_info->bcc[len] = 0;
        }
    } 
	else 
	{
		mail_info->bcc[0] = 0;
	}

	makeStr(mail_info->from);
	makeStr(mail_info->to);
	makeStr(mail_info->cc);
	makeStr(mail_info->bcc);

	pstart = strstr(pend, "\n'subject':'");
    if (pstart)
    {
        pstart += 12;
        pend = strstr(pstart, "',\n");
        if (pend)
        {
            len = pend - pstart;
            len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
            memcpy(mail_info->subject, pstart, len);
            mail_info->subject[len] = 0;
        }
    }
	else 
	{
		mail_info->subject[0] = 0;
	}

	do 
	{
	    pstart = strstr(pend, "\n'sentDate':new Date(");
	    if (pstart)
    	{
            pstart += 21;
            pend = strstr(pstart, "),");
            if (pend == NULL)
                break;
                
            len = pend - pstart;
            if (len > MAX_TIME_LEN)
                break;
                
            memcpy(mail_info->sent_time, pstart, len);
            mail_info->sent_time[len] = 0;

            int i = 0;
            pend = mail_info->sent_time;
            for (i = 0; i < 5; i++) 
            {
                pstart = strstr(pend, ",");
                if (pstart == NULL)
                break;
                switch (i) 
                {
                    case 0:
                        *pstart = '-';
                        break;
                    
                    case 1:
                        *pstart = '-';
                        {
                            char *p = pstart - 1;
                            (*p)++;
                            if (*p > '9') 
                            {
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
        }
    }while(0);

	mail_info->mail_type = 0x0422;
	Mail_info *pre_mail = NULL;
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
			strcpy(pre_mail->cookie_data,mail_info->cookie_data);
			create_dir(pre_mail->save_path, "163" ,pre_mail->from);
			write_to_file(pre_mail);
//			write_oracle_db_cookieinfo(pre_mail);
			del_mail_node(pre_mail);
			del_mail_node(mail_info);
			return 1;
		}
	}
	else if(mail_info->content != NULL)
	{
	    create_dir(mail_info->save_path, "163", mail_info->from);
		write_to_file(mail_info);
//		write_oracle_db_cookieinfo(mail_info);
		del_mail_node(mail_info);
		return 1;
	}

	/*clear_from(pre_mail->from);

	//printf("write 163 recv ...\n");
	create_dir(pre_mail->save_path, "163" ,pre_mail->from);
	write_to_file(pre_mail);
	del_mail_node(pre_mail);*/

    mail_info->mail_type = 0x0426;
	mail_info->is_complished = 0;
	return 0;
}

int analyse_163_rcvmail3(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result=0;
	char *dest = NULL;
	static int flag = -1;
	static int flagg = -1;
	
	if (is_to_s) 
	{
		if (!mail_info->is_complished) 
		{
			result = write_to_mail(mail_info, data, data_len, ptcp);
			//printf("result : %d\n", result);
			if(IS_MOVE_WEBMAIL == 1 && data_len>0 && strstr(mail_info->mail_data,"%3Cstring%20name%3D%22mode%22%3Eboth%3C%2Fstring%3E"))
				mail_info->mail_type = 0x8122;
			return result;
		}
	} 
	else 
	{
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{
			if(strstr(data, "Content-Encoding: gzip"))
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
				//printf("\ngzip ...\n");
				result = write_to_okdata(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				//printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 1;
			}
			
			if (result == -1)
			{
				//printf("write_to_okdata ... Error!\n");
				return -1;
			}
		}
		
		if (data_len < 10 /*|| (ntohl(ptcp->seq) + data_len - mail_info->http_seq >= mail_info->recive_length)*/ || ptcp->fin || !memcmp(data + data_len - 5, "0\r\n\r\n", 5) || !memcmp(data + data_len -2, "\0\0", 2) || !strncmp(data + data_len - 2, "}}",2))
		{
			//printf("analyse_163_rcvmail3 over...\n");
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					//printf("111111\n");
					Chunked(mail_info);//printf("\nmail_info->recive_length111 = %d, mail_info->recive_data1111 = %s\n",mail_info->recive_length,mail_info->recive_data);
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(mail_info->recive_data, mail_info->recive_length, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(mail_info->recive_data, mail_info->recive_length, &dest);
							if(result == -1) result = decomp_gzip(mail_info->recive_data, mail_info->recive_length, &dest);
						}
					}
				}
				else
				{
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length - 2, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(mail_info->recive_data, mail_info->recive_length - 2, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(mail_info->recive_data, mail_info->recive_length - 2, &dest);
							if(result == -1) 
                                result = decomp_gzip(mail_info->recive_data, mail_info->recive_length - 2, &dest);
						}
					}
				}
                
				if (result == -1)
				{
					LOG_WARN("webmail:analyse_163_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
                
				free(mail_info->recive_data);
				mail_info->recive_data = dest;		 //printf("\nmail_info->recive_data = %s\n",mail_info->recive_data);
				dest = NULL;
			}
            
			get_cookie(mail_info->mail_data, mail_info->cookie_data);
			htmldecode_full(mail_info->mail_data, mail_info->mail_data);
            
			char *i = NULL, *j = NULL;
			int len;
			i = strstr(mail_info->mail_data, "<string name=\"id\">");
			if(i == NULL)
				return 0;
				
			i += 18;
			j = strstr(i, "</string>");
			if(j == NULL)
				return 0;
				
			len = j - i;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(mail_info->mail_id, i, len);
			mail_info->mail_id[len] = '\0';
			htmldecode_full(mail_info->mail_id, mail_info->mail_id);
			writefile163_rcvmail3(mail_info);
			//del_mail_node(mail_info);
			
			return 0;
		}
	}
	
	return result;
}

int analyse_163_rcvmail4(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	static int seq_get = 0;
	static int seq_post = 0;
	int result;
	
	if(!strncmp(data, "GET /js6/read/readhtml.jsp?mid=", 31))
	{
		seq_get = ntohl(ptcp->seq) + data_len;
		result = analyse_163_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	else if(ntohl(ptcp->seq) == seq_get || ntohl(ptcp->ack_seq) == seq_get)
	{
		seq_get = ntohl(ptcp->seq) + data_len;
		result = analyse_163_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
    //  "/js6/s?sid=" is WEB request in PC, "/m/s?sid=" is WEB request in Android Phone
	else if ((!strncmp(data, "POST /js6/s?sid=", 16) || !strncmp(data, "POST /m/s?sid=", 14))
            && memfind(data, "func=mbox:readMessage", 100) != NULL)
	{
		seq_post = ntohl(ptcp->seq) + data_len;
		result = analyse_163_rcvmail3(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}
	else if(ntohl(ptcp->seq) == seq_post || ntohl(ptcp->ack_seq) == seq_post)
	{
		seq_post = ntohl(ptcp->seq) + data_len;
		result = analyse_163_rcvmail3(mail_info, data, data_len, ptcp, is_to_s);
		if (result == -1)
		{
			//printf("Error ... delete mail info ...\n");
			return -1;
		}
	}

	return 0;
}

int proce_163_okdata1(Attach_info *attach_info)
{
	char *dest = NULL;
	int result;

	if (attach_info->ok_gzip) 
    {
		result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
		if (result == -1) 
        {
			return -1;
		}
		free(attach_info->ok_data);
		attach_info->ok_data = dest;
		dest = NULL;
	}
    
	attach_info->is_get_ok = 0;
	attach_info->is_complished = 1;
    
	result = regcompile_1(attach_info->ok_data, "\'id\':\'(.*)\',\n\'account\':", attach_info->ID_str, MAX_ID_LEN);
	if (result == -1) 
    {
		return -1;
	}
	return 0;
}

int proce_163_okdata3(Attach_info *attach_info)
{
	char *dest = NULL;
	int result;
	
	//printf("%s\n", attach_info->ok_data);

	if (attach_info->ok_gzip) 
    {
		result = decomp_gzip(attach_info->ok_data, attach_info->ok_len - 1, &dest);
		if (result == -1) 
        {
			return -1;
		}
        
		free(attach_info->ok_data);
		attach_info->ok_data = dest;
		dest = NULL;
	}
	attach_info->is_get_ok = 0;
	attach_info->is_complished = 1;
	//printf("attach_info->ok_data : %s\n", attach_info->ok_data);
	if (attach_info->ID_str[0] == 0) {
		result = regcompile_1(attach_info->ok_data, "\'composeId\':\'(.{10,32})\'[,\\}]", attach_info->ID_str, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}
	}
	char * front = strstr(attach_info->ID_str, "&composeId=");
	if(!front)
	{
		front = strstr(attach_info->ID_str, "&uid=");
		if(!front)
			return -1;
	}
	int len = front - attach_info->ID_str;
    if (len > MAX_ID_LEN)
        len = MAX_ID_LEN;
	
	memcpy(attach_info->ID_str, attach_info->ID_str, len);
	attach_info->ID_str[len] = '\0';
	//printf("attach_info->ID_str... : %s\n", attach_info->ID_str);
	
	return 0;
}

int analyse_163_attach_1(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	int result;
	unsigned int seq = ntohl(ptcp->seq);

	if (is_to_s) 
	{
		if (attach_info->is_writing) 
		{
			//printf("%s\n",data);
			result = write_to_attach(attach_info, data, data_len, seq);
		} 
		else 
		{
			//printf("%s\n",data);
			result = proce_163_attach1_head(attach_info, data, data_len, seq);
		}
		
		return result;
	} 
	else 
	{
		if (attach_info->is_get_ok) 
		{
			int off_seq = seq - attach_info->ok_start_seq;

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
			if (!memcmp(data + data_len - 14, "</body></html>", 14) || !memcmp(data + data_len - 2, "\0\0\0", 3)) 
			{
				result = proce_163_okdata1(attach_info);
				return result;
			}
			
			return 0;
		} 
		else 
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) 
		{
			int len;
			char *p = NULL;

			attach_info->is_writing = 0;
			attach_info->is_get_ok = 1;

			if (strstr(data, "\r\nContent-Encoding: gzip\r\n") != NULL) 
			{
				attach_info->ok_gzip = 1;
			} 
			else 
			{
				attach_info->ok_gzip = 0;
			}

			len = get_http_length(data);
			if (len == -1)
				return -1;
            
			attach_info->ok_len = len;
            if (attach_info->ok_data)
            {
                free(attach_info->ok_data);
                attach_info->ok_data = NULL;
            }
            
			attach_info->ok_data = (char *)malloc((size_t)(len + 100));
			if (NULL == attach_info->ok_data)
				return -1;
			memset(attach_info->ok_data, 0, len + 1);

			p = strstr(data, "\r\n\r\n");
			if (p == NULL)
				return -1;
			p += 4;
			len = data_len - (p - data);
			if (len < 0 || len > attach_info->ok_len)
				return -1;
			memcpy(attach_info->ok_data, p, len);
			attach_info->ok_start_seq = seq + p - data;

			if (!memcmp(data + data_len - 14, "</body></html>", 14)|| !memcmp(data + data_len - 2, "\0\0\0", 3)) 
			{
				result = proce_163_okdata1(attach_info);
				return result;
			}
			
			return 0;
		}
		
		return -1;
	}
}

int analyse_163_attach_2(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;

	if (is_to_s) {
		if (attach_info->is_writing) {
			result = write_to_attach(attach_info, data, data_len, seq);
		} else {
			result = proce_163_attach2_head(attach_info, data, data_len, seq);
		}
		return result;
	} else {
		if (!attach_info->is_get_ok) {
			if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)){
				trim_attach(attach_info->path_of_here, 49);
				attach_info->is_get_ok = 0;
				attach_info->is_complished = 1;
				return 0;
			} else {
				return -1;
			}
		}
	}
}

int analyse_163_attach_3(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;

	if (is_to_s) 
	{
		//printf("***** 111111111 *******\n");
		if (attach_info->is_writing) 
		{
			//if(!memcmp(data+data_len-4,"--\r\n",4) || strstr(data,"\r\n----"))
			//	data_len -= 46;
				//data_len = strstr(data,"\r\n----") - data;
			result = write_to_attach_2(attach_info, data, data_len, seq);
		} 
		else 
		{
			result = proce_163_attach3_head(attach_info, data, data_len, seq);
		}
		
		//printf("result = %d\n", result);

		return result;
	} 
	else
	{
		/*if (attach_info->is_get_ok) 
		{
			//printf("***** 2222222222 *******\n");
			int off_seq = seq - attach_info->ok_start_seq;

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
			if (data[data_len - 1] == '}') 
			{
				result = proce_163_okdata3(attach_info);
				return result;
			}
			
			return 0;
		}*/ 
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) 
		{
//LOG_INFO("http ok-----------\n");
			char *p = NULL, * p2=NULL;
			unsigned int offlen=0;
			unsigned int len=0;
			attach_info->is_writing = 0;
			attach_info->is_complished=1;
//{'offset':786432,'length':196608}
			p=strstr(data,"{'offset':");
			if(!p) 
			{
				if(strstr(data,"'fileName'")&&strstr(data,"'size'"))
				{
					attach_info->recive_length=attach_info->ok_length;
					return 0;
				}
				return -1;
			}
			p+=10;
			
			for(;*p!=',';p++)
			{
				offlen=offlen*10+(*p-'0');
			}
			if(attach_info->recive_length!=offlen) return -1;
			p=strstr(p,"'length':");
			if(!p) return -1;
			p+=9;
			for(;*p!='}';p++)
			{
				len=len*10+(*p-'0');
			}
			attach_info->recive_length+=len;
			
			//if(1==1) return 0;
			//printf("%s\n", data);

			if (strstr(data, "\r\nContent-Encoding: gzip\r\n") != NULL) 
			{
				attach_info->ok_gzip = 1;
			} 
			else 
			{
				attach_info->ok_gzip = 0;
			}

			len = get_http_length(data);
			//printf("len : %d\n", len);
			if (len == -1)
				return -1;
				
			attach_info->ok_len = len;
            if (attach_info->ok_data)
            {
                free(attach_info->ok_data);
                attach_info->ok_data = NULL;
            }
            
			attach_info->ok_data = (char *)malloc((size_t)(len + 100));
			if (NULL == attach_info->ok_data)
				return -1;
			
			memset(attach_info->ok_data, 0, len + 1);
			p = strstr(data, "\r\n\r\n");
			if (p == NULL)
				return -1;
			p += 4;
			len = data_len - (p - data);
			if (len < 0 /*|| len > attach_info->ok_len*/)
				return -1;
			
			memcpy(attach_info->ok_data, p, len);
			attach_info->ok_start_seq = seq + p - data;

			//if (data[data_len - 1] == '}')
			//{
			result = proce_163_okdata3(attach_info);
			//if(result ==0) //printf("downdown-------------------\n");
			//LOG_INFO("downdown-------------------\n");
			return result;
			
			//}

			//return 0;
		}
		return 0;
	}
	return 0;
}

int analyse_163_down_attach(PacketInfo *packetInfo,Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	static int dataLen = 0;
	static int isChunked = -1;

	if(!is_to_s)
	{
		int f=http_recive_attach(attach_info,data,data_len);
		if(f==1)
		{
			//printf(attach_info->header);
			//printf("bodylen:%d,%s",attach_info->bodyLen,attach_info->body);	
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

			front = strstr(attach_info->header, "; filename=\"");
			if(front == NULL)
				return 0;
			front += 12;
			back = strstr(front, "\"\r\n");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			//memcpy(attach_info->attach_name, front, len);
			//attach_info->attach_name[len] = '\0';
			memcpy(attach_info->attname, front, len);
			attach_info->attname[len] = '\0';
			regmatch_t pm[3];
			char * tmpsub=attach_info->attname;
			int ret = reg(tmpsub,"=\\?(\\S+)\\?B\\?(.+)\\?=",pm,3);
			if(!ret)
			{
				char charset[15]={0};
				memcpy(charset,tmpsub+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
				char * tmpsub2 = (char *)malloc(len+1);
				if(!tmpsub2) return 0;
				base64Decode(tmpsub+pm[2].rm_so,pm[2].rm_eo-pm[2].rm_so, tmpsub2);
				code_convert(charset,"utf8",tmpsub2,strlen(tmpsub2),tmpsub,100);
				free(tmpsub2);
				tmpsub2 = NULL;
			}

			//htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			htmldecode_full(attach_info->attname, attach_info->attname);
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",attach_down_path, tv.tv_sec, tv.tv_usec);
			//char temp_name[MAX_PATH_LEN];
			//memset(temp_name, MAX_PATH_LEN, 0);
			//strcpy(temp_name, attach_info->attach_name);
			//temp_name[len] = '\0';
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);
			char * s;
			int slen;
			if(strstr(attach_info->header,"Content-Encoding: gzip\r\n"))
			{
				inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				//int f=inflate_read(attach_info->body,attach_info->bodyLen,&s,&slen,1);
				//if(f!=Z_OK){ printf("gzip decode error");return -1;}
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
			free(attach_info->body);
			attach_info->body = NULL;
			free(attach_info->header);
			attach_info->header = NULL;
			return -1;
		}
	}
	else
	{
		char * p1=strstr(data,"&mid=");
		if(!p1) return -1;
		p1+=5;
		char * p2=strstr(p1,"&");
		int len=p2-p1;
		if(len>MAX_ID_LEN) len=MAX_ID_LEN;
		memcpy(attach_info->ID_str,p1,len);
		attach_info->ID_str[len]=0;
		htmldecode_full(attach_info->ID_str, attach_info->ID_str);
	}
	return 0;
	if (attach_info->is_writing == 1)
	{//printf("\n1\n");
		attach_info->ok_len += data_len;
		if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
		{//printf("\n2\n");
			/*memcpy(attach_info->recive_data+(attach_info->ok_len-data_len-dataLen), data, attach_info->recive_length-(attach_info->ok_len-data_len-dataLen));
			if(attach_info->ok_gzip)
			{printf("\n3\n");
				char *tmp = (char *)malloc(attach_info->recive_length*30);
				memset(tmp,0,attach_info->recive_length*30);
				decomp_gzip_2(attach_info->recive_data,attach_info->recive_length-1000,&tmp);
				if(tmp == NULL) 
					return;
				free(attach_info->recive_data);
				attach_info->recive_data = tmp;
				attach_info->recive_length=strlen(attach_info->recive_data)+1000;
			}printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
			if (fd == -1)
				return -1;
			write(fd, attach_info->recive_data, attach_info->recive_length-1000);
			close(fd);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;*/
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
			{
				return -1;
			}
			lseek(fd, 0, SEEK_END);
			if(isChunked)
			{
				data_len -= 7;
			}
			write(fd, data, data_len);
			close(fd);
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}
		else
		{//printf("\n4\n");//printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
			//memcpy(attach_info->recive_data+(attach_info->ok_len-data_len-dataLen), data, data_len);
			int fd = open(attach_info->path_of_here, O_RDWR);
			if (fd == -1)
			{
				return -1;
			}
			lseek(fd, 0, SEEK_END);
			write(fd, data, data_len);
			close(fd);
		}
		
		/*if(ptcp->fin == 1 || strstr(data + data_len - 4, "\r\n\r\n"))
		{
			UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
			return -1;
		}*/
	}
	else
	{//printf("\n5\n");
		if(!strncmp(data, "HTTP/1.", 7))
		{//printf("\n6\n");
			struct timeval tv;
			struct timezone tz;
			char * front,* back;
			int len, fd;
			mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

			front = strstr(data, "; filename=\"");
			if(front == NULL)
				return 0;
			front += 12;
			back = strstr(front, "\"\r\n");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_PATH_LEN ? MAX_PATH_LEN : len);
			//memcpy(attach_info->attach_name, front, len);
			//attach_info->attach_name[len] = '\0';
			memcpy(attach_info->attname, front, len);
			attach_info->attname[len] = '\0';
			regmatch_t pm[3];
			char * tmpsub=attach_info->attname;
			int ret = reg(tmpsub,"=\\?(\\S+)\\?B\\?(.+)\\?=",pm,3);
			if(!ret)
			{
				char charset[15]={0};
				memcpy(charset,tmpsub+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
				char * tmpsub2 = (char *)malloc(len+1);
				if(!tmpsub2) return -1;
				base64Decode(tmpsub+pm[2].rm_so, pm[2].rm_eo-pm[2].rm_so, tmpsub2);
				code_convert(charset,"utf8",tmpsub2,strlen(tmpsub2),tmpsub,100);
				free(tmpsub2);
				tmpsub2 = NULL;
			}

			//htmldecode_full(attach_info->attach_name, attach_info->attach_name);
			htmldecode_full(attach_info->attname, attach_info->attname);
			gettimeofday(&tv, &tz);
			snprintf(attach_info->path_of_here, MAX_PATH_LEN, "%s/%lu-%lu",attach_down_path, tv.tv_sec, tv.tv_usec);
			//char temp_name[MAX_PATH_LEN];
			//memset(temp_name, MAX_PATH_LEN, 0);
			//strcpy(temp_name, attach_info->attach_name);
			//temp_name[len] = '\0';
			snprintf(attach_info->attach_name, MAX_PATH_LEN, "%lu-%lu", tv.tv_sec, tv.tv_usec);

			front = strstr(data, "\r\n\r\n");
			front += 4;
			attach_info->recive_length = get_http_length(data);
			attach_info->recive_length += 1000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL)
				return -1;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			if(strstr(data,"Transfer-Encoding: chunked\r\n"))
			{
				isChunked = 1;
				front = strstr(front,"\r\n");
				front += 2;
			}
			if(strstr(data,"Content-Encoding: gzip\r\n"))
			{
				attach_info->ok_gzip = 1;
			}
			/*if(front == NULL)
			{
				front = strstr(data, "Connection: keep-alive\r\n\r\n");
				if(front == NULL)
					return 0;
				front += 26;
			}
			else
				front += 21;*/
			attach_info->ok_len = data_len;
			dataLen = front-data;
			attach_info->is_writing = 1;
			if(strstr(data + data_len - 4, "\r\n\r\n") || attach_info->recive_length-1000 == attach_info->ok_len - dataLen)
			{
				memcpy(attach_info->recive_data, front, attach_info->recive_length-1000);
				if(attach_info->ok_gzip)
				{
					char *tmp = (char *)malloc(attach_info->recive_length*30);
					memset(tmp,0,attach_info->recive_length*30);
					decomp_gzip_2(attach_info->recive_data,attach_info->recive_length-1000,&tmp);
					if(tmp == NULL) 
						return -1;
					free(attach_info->recive_data);
					attach_info->recive_data = tmp;
					attach_info->recive_length=strlen(attach_info->recive_data)+1000;
				}//printf("\nattach_info->recive_length = %d\n",attach_info->recive_length);
				fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
				if (fd == -1)
					return -1;
				write(fd, attach_info->recive_data, attach_info->recive_length-1000);
				close(fd);
				UpdateAttachNew(attach_info->attach_name, attach_info->attname, attach_info->ID_str);
				return -1;
			}
			else
			{
				//memcpy(attach_info->recive_data, front, dataLen);
				fd = open(attach_info->path_of_here, O_RDWR|O_CREAT, file_mode);
				if (fd == -1)
					return -1;
				write(fd, front, data_len - (front - data));
				close(fd);
			}
		}
		else
		{//printf("\n7\n");
			int len;
			char *front, *back;
			front = strstr(data, "&mid=");
			if(front == NULL)
				return 0;
			front += 5;
			back = strstr(front, "&part=");
			if(back == NULL)
				return 0;
			len = back - front;
			len = (len > MAX_ID_LEN ? MAX_ID_LEN : len);
			memcpy(attach_info->ID_str, front, len);
			attach_info->ID_str[len] = '\0';
			htmldecode_full(attach_info->ID_str, attach_info->ID_str);
		}
	}
	
	return 1;
}

/*int analyse_163_attach_recive(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_b_s)
{printf("						 analyse_163_attach_recive\n");
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	static int dataLen = 0;
	
	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN+1];
		int result;
	
		if (!strncmp(data, "GET /js3/down/", 14) && strstr(data, "&mode=download&l=read&action=download_attach"))
		{
			char *p1, *p2;
			int len_id;
			p1=strstr(data,"&mid=");
			if(p1==NULL)
				return -1;
			p1+=5;
			p2=strstr(p1,"&part=");
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
		if (!strncmp(data, "HTTP/1.", 7))
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
			range = off_seq + data_len;
			if (range >= mail_info->recive_length)
				return -1;
			memcpy(mail_info->recive_data+off_seq,data,data_len);
			dataLen+=data_len;
		}
		if (dataLen - mail_info->mail_length == mail_info->recive_length-1000 || strstr(data + data_len - 4, "\r\n\r\n"))
		{
			mail_info->is_complished = 1;
			attach_len=get_http_length_2(mail_info->recive_data,&n);
			if (attach_len <= 0)
				return -1;
			write_attach_down_1(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}
}
*/
int analyse_163_delete(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq;
	int off_seq;
	int result;

	seq = ntohl(ptcp->seq);
	off_seq = seq - mail_info->start_seq;
	if (is_to_s) {
		if (!mail_info->is_complished) {
			if (!strncmp(data, "<?xml version=\"1.0\"?><object><string name=\"action\">sa", 53)) {
				return -1;
			}
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} else if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
		char ID_pattern[] = "name=\"composeId\">(.*)</string><array name=";
		char file_pattern[] = "array name=\"items\"><string>(.*)</string></array>";
		char ID[MAX_ID_LEN + 1];
		char file_path[MAX_PATH_LEN + 1];
		Attach_info *attach_tmp = NULL;

		result = regcompile_1(mail_info->mail_data, ID_pattern, ID, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}
		result = regcompile_1(mail_info->mail_data, file_pattern, file_path, MAX_ID_LEN);
		if (result == -1) {
			return -1;
		}

		attach_tmp = attach_tab.head->next;
		while (attach_tmp != NULL) {
			if (!strcmp(attach_tmp->ID_str, ID) && !strcmp(attach_tmp->path_of_sender, file_path)) {
				del_attach_node(attach_tmp);
				delete_attach(attach_tmp);
				break;
			}
			attach_tmp = attach_tmp->next;
		}

		return -1;
	} else {
		return -1;
	}
}

int writefile163_vip_en_rcvmail1(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	size_t total_len;
	int result;
	char *pto = NULL;
	char *pcc = NULL;
	char *pover = NULL;

	if (mail_info == NULL || mail_info->recive_data == NULL)
		return -1;

	result = get_yeah_rcvid(mail_info);
	if (result == -1)
		return -1;

	pstart = strstr(mail_info->recive_data, "<html>\r\n\r\n<head><title>");
	if (pstart == NULL)
		return -1;
	pstart += 23;
	pend = strstr(pstart, "</title>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_SUBJ_LEN ? MAX_SUBJ_LEN : len);
	memcpy(mail_info->subject, pstart, len);
	mail_info->subject[len] = 0;

	pstart = strstr(pend, "name=\"from_mail\" value=\"");
	if (pstart == NULL)
		return -1;
	pstart += 24;
	pend = strstr(pstart, "\">");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	len = (len > MAX_FROM_LEN ? MAX_FROM_LEN : len);
	memcpy(mail_info->from, pstart, len);
	mail_info->from[len] = 0;

	pstart = strstr(pend, "<th>Date:"); //search character send time "?? ??
	if (pstart == NULL)
		return -1;
	pstart = strstr(pstart, "<td>");
	if (pstart == NULL)
		return -1;
	pstart += 4;
	pend = strstr(pstart, "</td>");
	if (pend == NULL)
		return -1;
	len = pend - pstart;
	if (len > MAX_TIME_LEN)
		return -1;
	memcpy(mail_info->sent_time, pstart, len);
	mail_info->sent_time[len] = 0;

	pto = strstr(pend, "<th>To:"); //search character send mailname "?�件��?
	if (pto == NULL)
		return -1;
	pcc = strstr(pto, "<th>Cc:"); //search character send mailname "????��?
	if (pcc != NULL) {
		pover = pcc;	
	} else {
		pover = mail_info->recive_data + mail_info->recive_length;
	}
	pend = pto;
	pstart = pto;
	total_len = 0;
	pstart = strstr(pend, "&to=");
	if (pstart == NULL)
		return -1;
	do {
		pstart += 4;
		pend = strstr(pstart, "\"");
		if (pend == NULL)
			return -1;
		len = pend - pstart;
		total_len += len;
		if (total_len > len)
			total_len++;
		if (total_len > MAX_TO_LEN)
			break;
		if (total_len > len)
			mail_info->to[total_len - len - 1] = ';';
		memcpy(mail_info->to + total_len - len, pstart, len);
		mail_info->to[total_len] = 0;
		pstart = strstr(pend, "&to=");
	} while (pstart != NULL && pstart < pover);

	if (pcc != NULL) {
		pstart = pcc;
		pend = pcc;
		pover = mail_info->recive_data + mail_info->recive_length;
		total_len = 0;
		pstart = strstr(pend, "&to=");
		if (pstart == NULL)
			return -1;
		do {
			pstart += 4;
			pend = strstr(pstart, "\"");
			if (pend == NULL)
				return -1;
			len = pend - pstart;
			total_len += len;
			if (total_len > len)
				total_len++;
			if (total_len > MAX_CC_LEN)
				break;
			if (total_len > len)
				mail_info->cc[total_len - len - 1] = ';';
			memcpy(mail_info->cc + total_len - len, pstart, len);
			mail_info->cc[total_len] = 0;
			pstart = strstr(pend, "&to=");
		} while (pstart != NULL && pstart < pover);
	}
	
	result = str_163_convert2(mail_info->to, MAX_TO_LEN);
	if (result == -1)
		return -1;

	result = str_163_convert2(mail_info->sent_time, MAX_TIME_LEN);
	if (result == -1)
		return -1;

	return 0;
}

int writefile163_vip_en_rcvmail2(Mail_info *mail_info)
{
	char *pstart = NULL;
	char *pend = NULL;
	size_t len;
	Mail_info *pre_mail = NULL;
	int result;
	char *tmp = NULL;


	result = get_yeah_rcvid(mail_info);
	if (result == -1)
		return -1;

	pre_mail = find_mail_head(mail_info->connect_id, mail_info);
	if (pre_mail == NULL)
		return -1;
	pstart = strstr(mail_info->recive_data, "<body>");
	if (pstart == NULL) {
		del_mail_node(pre_mail);
		return -1;
	}
	pstart += 6;
	pend = strstr(pstart, "</body>");
	if (pend == NULL) {
		del_mail_node(pre_mail);
		return -1;
	}
	len = pend - pstart;
	pre_mail->content = (char *)malloc(len + 1);
	if (pre_mail->content == NULL) {
		del_mail_node(pre_mail);
		return -1;
	}
	memcpy(pre_mail->content, pstart, len);
	pre_mail->content[len] = 0;

	result = str_163_convert2(pre_mail->subject, MAX_SUBJ_LEN);
	if (result == -1)
		return -1;

	tmp = clear_html_tag(pre_mail->content);
	if (tmp == NULL)
		return -1;
	free(pre_mail->content);
	pre_mail->content = conv_163_to_utf8(tmp);
	free(tmp);
	tmp = NULL;
	if (pre_mail->content == NULL)
		return -1;

	clear_from(mail_info->from);

	create_dir(pre_mail->save_path, "163" ,pre_mail->from);
	write_to_file(pre_mail);
	del_mail_node(pre_mail);
	return 0;
}

int analyse_163_vip_en_rcvmail1(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
{
	int result;
	char *dest = NULL;


	if (is_to_s) {
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} else { //if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
		if (!mail_info->is_complished) {
			result = write_chunked_okdata(mail_info, data, data_len, ptcp);
			if (result == -1)
				return -1;
		}
		if (data_len < 9 || strncmp(data + data_len - 9, "\r\n</html>", 9) == 0 || data_len < 14 || strncmp(data + data_len - 14, "</html>\r\n0\r\n\r\n", 14) == 0) {
			mail_info->is_complished = 1;
			result = writefile163_vip_en_rcvmail1(mail_info);
			return result;
		}
	}
}

int analyse_163_vip_en_rcvmail2(Mail_info *mail_info,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s)
{
	int result;
	char *dest = NULL;

	if (is_to_s) {
		if (!mail_info->is_complished) {
			result = write_to_mail(mail_info, data, data_len, ptcp);
			return result;
		}
	} else { //if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9)) {
		if (!mail_info->is_complished) {
			// Can't not define if it's chunked or not
			result = write_to_okdata(mail_info, data, data_len, ptcp); 
			if (result == -1)
				return -1;
		}
		if (ptcp->fin || data_len < 20 || (ntohl(ptcp->seq) + data_len - mail_info->http_seq > mail_info->recive_length - 100) || strstr(data + data_len - 20, "</html>") != NULL) {
			mail_info->is_complished = 1;
			writefile163_vip_en_rcvmail2(mail_info);
			del_mail_node(mail_info);
			return 0;
		}
	}
}

int analyse_163(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
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
		//	printf("analyse_163_mail ...\n");
			result = analyse_163_mail(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x12:
		//	printf("analyse_163_mail2 ...\n");
			result = analyse_163_mail2(mail_info, data, data_len, ptcp, is_to_s);  //163 vip 淡�????
			break;
		case 0x01:
		//	printf("analyse_163_passwd ...\n");
			result = analyse_163_passwd(mail_info, data, data_len, ptcp, is_to_s);  //login form hao123
			break;
        case 0x02:
            result = analyse_163_login(mail_info, data, data_len, ptcp, is_to_s);
            break;
		case 0x41:
		//	printf("analyse_163_delete ...\n");
			result = analyse_163_delete(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x21:
		//	printf("analyse_163_rcvmail1 ...\n");
			result = analyse_163_rcvmail1(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x22:
		//	printf("analyse_163_rcvmail333 ...\n");
			result = analyse_163_rcvmail3(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x23:
		//	printf("analyse_163_rcvmail222 ...\n");
			result = analyse_163_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x24:	//0x24 and 0x25 are for 163 vip english editon
		//	printf("analyse_163_vip_en_rcvmail1 ...\n");
			result = analyse_163_vip_en_rcvmail1(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x25:
		//	printf("analyse_163_vip_en_rcvmail2 ...\n");
			result = analyse_163_vip_en_rcvmail2(mail_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x26:
		//	printf("analyse_163_rcvmail4 ...\n");
		//	printf(data);
			result = analyse_163_rcvmail4(mail_info, data, data_len, ptcp, is_to_s);
			break;
		/*case 0x26:
			//printf("analyse_163_attach_recive ...\n");
			result = analyse_163_attach_recive(mail_info, data, data_len, ptcp, is_to_s);
			break;*/
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
		//	printf("analyse_163_attach_1 ...\n");
			result = analyse_163_attach_1(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x62:
		//	printf("analyse_163_attach_2 ...\n");
			result = analyse_163_attach_2(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x63:
		//	printf("analyse_163_attach_3 ...\n");
			result = analyse_163_attach_3(attach_info, data, data_len, ptcp, is_to_s);
			break;
		case 0x64: //163 down attach
		//	printf("analyse_163_down_attach ...\n");
		//	printf("down attach----\n");
            result = analyse_163_down_attach(packetInfo, attach_info, data, data_len, ptcp, is_to_s);
			break;
		}
        
		if (result == -1) 
		{
		//	printf("analyse_163_attach error ...\n");
			//printf(data);
			del_attach_node(attach_info);
			delete_attach(attach_info);
		}
	}
    
	fflush(stdout);
}

