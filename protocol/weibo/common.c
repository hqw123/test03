#include "weibo_common.h"
#include <ctype.h>

#define _REG_
regmatch_t *regcompile(char *src,char *pattern)
{
  size_t len;
  regex_t re;
  regmatch_t *subs = NULL;
  char errbuf[128];
  int err, i;
  
  //printf("***************\n compost id : %s \n***************\n",src);
 
  err=regcomp(&re,pattern,REG_EXTENDED);
  if(err)
  {
   len=regerror(err,&re,errbuf,sizeof(errbuf));
   fprintf(stderr, "error:regcomp:%s\n",errbuf);
   return NULL;
  }
  const size_t n = re.re_nsub;
  size_t nmatch = (n+1) *sizeof(regmatch_t);
 // subs= (regmatch_t *)malloc(nmatch);
 subs = (regmatch_t *)malloc((n+1)*10*sizeof(regmatch_t));
  err=regexec(&re,src,(size_t)nmatch,subs,0);
  if(err==REG_NOMATCH)
  {
    //fprintf(stderr, "sorry,no match...\n");
    regfree(&re);
    return NULL;
  }
  else if(err)
  {
    len= regerror(err,&re,errbuf,sizeof(errbuf));
    fprintf(stderr, "error:regexec:%s\n",errbuf);
    regfree(&re);
    return NULL;
  }
  regfree(&re);
  return subs;
}

reg_rtn_struct wb_cns_reg(const char *src, const char *pattern)
{
	reg_rtn_struct reg_rtn_struct_var;

#define OVECCOUNT 10
	pcre *re;
	const char *error;
	int erroffset;
	int ovector[OVECCOUNT];
	int rc, i;

	reg_rtn_struct_var.rtn = -1;
	reg_rtn_struct_var.pstart = -1;
	reg_rtn_struct_var.pend = -1;

	re = pcre_compile(pattern, PCRE_DOTALL, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "webmail:wb_cns_reg(): pcre_compile()failed at offset %d: %s\n", erroffset, error);
		return reg_rtn_struct_var;
	}
	rc = pcre_exec(re, NULL, src, strlen(src), 0, 0, ovector, OVECCOUNT);
	if (rc < 0) {
		/*
		if (rc == PCRE_ERROR_NOMATCH)
			fprintf(stderr, "Sorry, no match...\n");
		else
			fprintf(stderr, "Matching error %d\n", rc);
		*/
		free(re);
		return reg_rtn_struct_var;
	}
	
	reg_rtn_struct_var.rtn = 0;
	reg_rtn_struct_var.pstart = ovector[0];
	reg_rtn_struct_var.pend = ovector[1];

	free(re);
	return reg_rtn_struct_var;
}

int wb_cns_str_ereplace(char **src, const char *pattern, const char *newsubstr)
{
	if (strcmp(pattern, newsubstr) == 0) 
    {
		return 0;
	}

	reg_rtn_struct reg_rtn_struct_var;
	int rtn = 0;
	int pstart = 0;
	int pend = 0;
	char *dest = *src;
	char *tmp;
	char *new_tmp_str = dest;
	int new_tmp_str_len = 0;

	while (!rtn) 
    {
		reg_rtn_struct_var = wb_cns_reg(new_tmp_str, pattern);
		rtn = reg_rtn_struct_var.rtn;
		pstart = reg_rtn_struct_var.pstart;
		pend = reg_rtn_struct_var.pend;

		if (!rtn) 
        {
			tmp = (char *)calloc(sizeof(char), strlen(dest) + strlen(newsubstr) - (pend-pstart) +1);
			if (tmp == NULL)
				break;
            
			strncpy(tmp, dest, new_tmp_str_len + pstart);
			tmp[new_tmp_str_len + pstart] = '\0';
            
			strcat(tmp, newsubstr);
			strcat(tmp, new_tmp_str + pend);
            
			free(dest);
			dest = tmp;
			tmp = NULL;
            
			new_tmp_str_len = new_tmp_str_len + pstart + strlen(newsubstr);
			new_tmp_str = dest + new_tmp_str_len;
		}
	}
    
	*src = dest;
	return 0;
}
#undef _REG_

#define _STRING_
char *strnstr(char *str, char *substr, size_t n)
{
	size_t i, len;
	char *p = str;
	char *p1 = NULL;
	char *p2 = NULL;
	
	if (str == NULL || substr == NULL || n < strlen(substr))
		return NULL;
	len = n - strlen(substr) + 1;
	for (i = 0; i < len; i++) {
		if (*p != *substr) {
			p++;
			continue;
		}
		
		p1 = substr;
		p2 = p;
		while (*p1 != 0) {
			if (*(++p2) != *(++p1))
				break;
		}
		if (*p1 == 0) {
			return p;
		}
		p++;
	}
	return NULL;
}

char *memnfind(char *src, size_t srcLen, char *pat, size_t patLen, int *curlen)
{
	size_t i, len;
	char *p = src;
	char *p1 = NULL;
	char *p2 = NULL;
	size_t j = 0;
	if (src == NULL || pat == NULL || srcLen<patLen)
		return NULL;

	len = srcLen - patLen + 1;
	for (i = 0; i < len; i++)
	{
		if (*p != *pat)
		{
			p++;
			continue;
		}
		
		p1 = pat;
		p2 = p;
		j = 0;
		while (j < patLen) 
		{
			j++;
			if (*(++p2) != *(++p1))
				break;
		}
		if (j == patLen)
		{
			if (NULL != curlen)
				*curlen = i;
			return p;
		}
		p++;
	}
	return NULL;
}

int wb_charcmp_nosense(char c1, char c2)
{
	if(c1>='A' && c1<='Z') c1=c1+32;
	if(c2>='A' && c2<='Z') c2=c2+32;
	if(c1==c2) return 1;
	else return 0;
}

char * wb_strstr_2(char * s, char * sub)
{
	int len = strlen(sub);
	if(len==0) return s;
	int i;
	int f;
	while(*s)
	{
		if(wb_charcmp_nosense(*s,*sub))
		{
			f=0;
			for(i=1;i<len;i++)
			{
				if(*(s+i)==0 || !wb_charcmp_nosense(*(s+i),*(sub+i)))
				{
					f=1;break;
				}
			}
			if(!f) return s;
		}
		s++;
	}
	return NULL;
}
char *wb_arrcpy(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN)
{
    if (NULL==src)
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
        if (len > MAX_LEN)
            len = MAX_LEN;
        memcpy(arr, p1, len);
        arr[len] = 0;
    }
    return p2;
}

char *wb_arrcpy_2(char arr[], char *src, char *startstr, char *endstr, int addlen, int MAX_LEN)
{
    if (NULL==src)
        return NULL;
    char *p1=NULL, *p2=NULL;
    int len = 0;
    p1 = wb_strstr_2(src, startstr);
    if (NULL == p1)
        return NULL;
    p1 += addlen;
    p2 = wb_strstr_2(p1, endstr);
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
char *wb_ptrcpy(char **pptr, char *src, char *startstr, char *endstr, int addlen)
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

char *wb_ptrcpy_2(char **pptr, char *src, char *startstr, char *endstr, int addlen)
{
    if (NULL==src || pptr==NULL)
        return NULL;
    char *p1=NULL, *p2=NULL;
    int len = 0;
    p1 = wb_strstr_2(src, startstr);
    if (NULL == p1)
        return NULL;
    p1 += addlen;
    p2 = wb_strstr_2(p1, endstr);
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

#undef _STRING_

#define _CODE_

int wb_ulong_to_ipstr(unsigned int sip, char dip[16])
{
        memset(dip, 0, 16);
        sprintf(dip, "%d.%d.%d.%d", sip&0x000000FF, (sip>>8)&0x0000FF,(sip>>16)&0x00FF,sip>>24);
        return 0;
}

char wb_chartoint(char x)
{
	if(x>='0'&&x<='9')
		x=x-'0';
	else if(x>='a' && x<='f'){
		x-='a';
		x+=10;
	}else if(x>='A' && x<='F'){
		x-='A';
		x+=10;
	}

	return x;
}
int wb_get_value(char str[4])
{
   int sum=0;
   int i;
   for(i=0;i<4; i++)
   sum=sum*16+wb_chartoint(str[i]);
   return sum;
}

void wb_clear_u(char *str, char ctag)
{
	char *head=NULL,*end=NULL;
	char A,B,C,D;
	char x,y,z;
	char u1=0x0e;
	char u2=0x80;
	char tem[4];
	int value;
	if(str==NULL) return;
	head=str;
	end=head;
	while(*head!='\0'){
		if(*head==ctag && *(head+1)=='u'){
		         memcpy(tem,head+2,4);
		         value=wb_get_value(tem);
		         if(value<0x0800)
		         {
		           A=((value>>6) & 0x1f) | 0xc0;
		           B=((value>>0) & 0x3f) | 0x80;
		           *(end++)=A;
		           *(end++)=B;
		         }
		         else
		         {
			A=wb_chartoint(*(head+2));
			B=wb_chartoint(*(head+3));
			C=wb_chartoint(*(head+4));
			D=wb_chartoint(*(head+5));
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
 URLΩ‚¬Î
 */
 size_t wb_url_decode(const char *src,char *dest)
 {
    if (NULL==src||NULL==dest)
        return -1;
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
//url±‡¬Î
static const char c2x_table[] = "0123456789ABCDEF";
static unsigned char *c2x(unsigned what,unsigned char *where)
{
    *where++ = '%';
    *where++ = c2x_table[what>>4];
    *where++ = c2x_table[what&0xf];
    return where;
}
static int unsafechar(unsigned char ch)
{
    unsigned char *p=&ch;

    if( *p == ' ' || *p == '%' || *p == '\\' || *p == '^' || *p == '[' || *p == ']' || *p == '`' \
                  || *p == '+' || *p == '$' || *p == ','  || *p == '@' || *p == ':' || *p == ';' \
                  || *p == '/' || *p == '!' || *p == '#'  || *p == '?' || *p == '=' || *p == '&' || *p == '.' || *p>0x80 )
    {
      return(1);
    }
    else{
      return(0);
    }

}
size_t url_encode(const char *src, char *dest)
{
    char *cp=dest;

    while(*src!='\0')
    {
      unsigned char *p=(unsigned char*)src;
      if(*p==' '){
       *dest++='+';
      }
      else if(unsafechar(*p))
      {
       unsigned char w[3]={'\0'};
       c2x(*p,w);
       *dest=w[0];
       *(dest+1)=w[1];
       *(dest+2)=w[2];
       dest+=3;
      }
      else
      {
       *dest++=*p;
      }
      src++;
    }
    *dest='\0';

    return(dest-cp);
}

/*¥¶¿Ì:
%25u4E2D%25u6587%253Cbr%253E%2521%40%2523%2524%2525%255E%2526amp%253B%253Cbr%253E%2526lt%253Bhtml%2526gt%253B%253Cbr%253E
*/
char *wb_deal_point(char *src, int len)
{
    if (src == NULL)
		return NULL;
	char *str = strdup(src);
    char *tmp = (char *)malloc(len+1);
    memset(tmp, 0, len+1);
    wb_url_decode(str, tmp);
    memset(str, 0, len+1);
    wb_url_decode(tmp, str);
    free(tmp);
    tmp = wb_conv_to_xml_symbol(str);
    free(str);
    str = tmp;
    wb_clear_u(str, '%');
    return str;
}

char *wb_clear_html_tag(char *source)
{
	if (source == NULL)
		return NULL;
	char *str = strdup(source);
	int result;

	result = wb_cns_str_ereplace(&str, "<[sS][tT][Yy][Ll][Ee].*?</[Ss][Tt][Yy][Ll][Ee]>", "");

	if (result != -1)
		result = wb_cns_str_ereplace(&str, "<[^>]+>", "");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "<[Bb][Rr]>", "\n");

	return str;
}

char *wb_conv_to_xml_symbol(char *source)
{
	if (source == NULL)
		return NULL;
	char *str = strdup(source);
	int result;

	result = wb_cns_str_ereplace(&str, "&lt;", "<");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "&gt;", ">");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "&amp;", "&");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "&apos;", "'");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "&quot;", "\"");
//	if (result != -1)
//		result = wb_cns_str_ereplace(&str, "&.{2,7};", "*");

	return str;
}

void wb_makeStr(char * str)
{
	char * i = str, * j = str;
	while(*i && *j)
	{
		if(*i != '\'')
		{
			*j = *i;
			j++;
		}
		
		i++;
	}
	
	*j = '\0';
}

int wb_regcompile_1(char *src,char *pattern,char *matched,int length)
{
    if (src == NULL)
        return -2;
    size_t len;
    regmatch_t *subs = regcompile(src, pattern);
    if (NULL == subs)
        return -1;
    len=subs[1].rm_eo-subs[1].rm_so;
    if(len<length){
        memcpy(matched,src+subs[1].rm_so,len);
        matched[len]='\0';
    }else{
        memcpy(matched,src+subs[1].rm_so,length);
        matched[length]='\0';
    }
  return 0;
}

int wb_regcompile_2(char *src,char *pattern,char **matched)
{
    if (src == NULL)
        return -2;
    size_t len;
    regmatch_t *subs = regcompile(src, pattern);
    if (NULL == subs)
        return -1;

    len=subs[1].rm_eo-subs[1].rm_so;

    *matched = (char *)malloc((size_t)(len + 1));
    if (*matched == NULL) {
        return -1;
    }

    memcpy(*matched, src + subs[1].rm_so, len);
    (*matched)[len]='\0';
    return 0;
}

const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="; 
static char find_pos(char ch)   
{ 
    char *ptr = (char*)strrchr(base, ch);//the last position (the only) in base[] 
    return (ptr - base); 
} char *base64_encode(const char* data, int data_len) 
{ 
    //int data_len = strlen(data); 
    int prepare = 0; 
    int ret_len; 
    int temp = 0; 
    char *ret = NULL; 
    char *f = NULL; 
    int tmp = 0; 
    char changed[4]; 
    int i = 0; 
    ret_len = data_len / 3; 
    temp = data_len % 3; 
    if (temp > 0) 
    { 
        ret_len += 1; 
    } 
    ret_len = ret_len*4 + 1; 
    ret = (char *)malloc(ret_len); 
      
    if ( ret == NULL) 
    { 
        LOG_FATAL("No enough memory.\n"); 
        exit(0); 
    } 
    memset(ret, 0, ret_len); 
    f = ret; 
    while (tmp < data_len) 
    { 
        temp = 0; 
        prepare = 0; 
        memset(changed, '\0', 4); 
        while (temp < 3) 
        { 
            //printf("tmp = %d\n", tmp); 
            if (tmp >= data_len) 
            { 
                break; 
            } 
            prepare = ((prepare << 8) | (data[tmp] & 0xFF)); 
            tmp++; 
            temp++; 
        } 
        prepare = (prepare<<((3-temp)*8)); 
        //printf("before for : temp = %d, prepare = %d\n", temp, prepare); 
        for (i = 0; i < 4 ;i++ ) 
        { 
            if (temp < i) 
            { 
                changed[i] = 0x40; 
            } 
            else 
            { 
                changed[i] = (prepare>>((3-i)*6)) & 0x3F; 
            } 
            *f = base[changed[i]]; 
            //printf("%.2X", changed[i]); 
            f++; 
        } 
    } 
    *f = '\0'; 
      
    return ret; 
      
} 
char *base64_decode(const char *data, int data_len) 
{ 
    int ret_len = (data_len / 4) * 3; 
    int equal_count = 0; 
    char *ret = NULL; 
    char *f = NULL; 
    int tmp = 0; 
    int temp = 0; 
    char need[3]; 
    int prepare = 0; 
    int i = 0; 
    if (*(data + data_len - 1) == '=') 
    { 
        equal_count += 1; 
    } 
    if (*(data + data_len - 2) == '=') 
    { 
        equal_count += 1; 
    } 
    if (*(data + data_len - 3) == '=') 
    {//seems impossible 
        equal_count += 1; 
    } 
    switch (equal_count) 
    { 
    case 0: 
        ret_len += 4;//3 + 1 [1 for NULL] 
        break; 
    case 1: 
        ret_len += 4;//Ceil((6*3)/8)+1 
        break; 
    case 2: 
        ret_len += 3;//Ceil((6*2)/8)+1 
        break; 
    case 3: 
        ret_len += 2;//Ceil((6*1)/8)+1 
        break; 
    } 
    ret = (char *)malloc(ret_len); 
    if (ret == NULL) 
    { 
        LOG_FATAL("No enough memory.\n"); 
        exit(0); 
    } 
    memset(ret, 0, ret_len); 
    f = ret; 
    while (tmp < (data_len - equal_count)) 
    { 
        temp = 0; 
        prepare = 0; 
        memset(need, 0, 4); 
        while (temp < 4) 
        { 
            if (tmp >= (data_len - equal_count)) 
            { 
                break; 
            } 
            prepare = (prepare << 6) | (find_pos(data[tmp])); 
            temp++; 
            tmp++; 
        } 
        prepare = prepare << ((4-temp) * 6); 
        for (i=0; i<3 ;i++ ) 
        { 
            if (i == temp) 
            { 
                break; 
            } 
            *f = (char)((prepare>>((2-i)*8)) & 0xFF); 
            f++; 
        } 
    } 
    *f = '\0'; 
    return ret; 
}


#undef _CODE_


#define CHUNK 16384
int inflate_read_2 (char *source, int len, char **dest, int *dest_size, int gzip, int windowBits)
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
		ret = inflateInit2 (&strm, windowBits);
	else
		ret = inflateInit (&strm);
	if (ret != Z_OK)
		return ret;
	strm.avail_in = len;
	strm.next_in = (unsigned char *) source;
	
	/*  run  inflate()  on  input  until  output  buffer  not  full  */
	int i=0;
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
		
		if(i==0)
		{
			*dest=(char *)malloc(totalsize);
			i=1;
		}
		else 
			*dest = (char *) realloc (*dest, totalsize);
		
		memcpy (*dest + totalsize - have, out, have);
	}while (strm.avail_out == 0);
		
	if (dest_size != NULL)
		*dest_size = strm.total_out;
	
	/*  clean  up  and  return  */
	(void) inflateEnd (&strm);
	
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
	
}

int decompress_2(char * * pbody, int *pbodyLen)
{
	if (!pbody || !*pbody || !pbodyLen)
		return 1;
	char *body = *pbody;
	int bodyLen = *pbodyLen;
	char *s = NULL;
	int slen;
	if(inflate_read_2(body,bodyLen,&s,&slen,1, 47)!=Z_OK)
	{ 
		if(inflate_read_2(body,bodyLen,&s,&slen,1, 31)!=Z_OK)
		{ 
			if(inflate_read_2(body,bodyLen,&s,&slen,1, 15)!=Z_OK)
			{ 
				if(inflate_read_2(body,bodyLen,&s,&slen,1, -15)!=Z_OK)
				{ 
					LOG_ERROR("gzip decode error\n");
					return -1;
				}
			}
		}
	}
	else
	{
		free(body);
		body=s;
		s = NULL;
		bodyLen=slen;
	}
	*pbody = body;
	*pbodyLen = bodyLen;
	return 0;
}


int wb_get_time(char *data, char *dest)
{
    if (NULL==data || NULL==dest)
        return -1;
	char *p1,*p2;
	char tm_str[MAX_TIME_LEN + 1];
	time_t timeval;
	struct tm time_struct, *tm_ptr;
	struct tm *time_ptr;

	p1 =strstr(data,"\r\nDate: ");
    if (NULL == p1)
        return -1;
	p1 += 8;
	p2 =strstr(p1,"\r\n");
	strncpy(tm_str, p1, p2 - p1);
	tm_str[p2 - p1] = 0;

	strptime(tm_str, "%a, %d %b %Y %H:%M:%S %Z", &time_struct);
	timeval = mktime(&time_struct) + 8 * 3600;
	tm_ptr = localtime(&timeval);
	snprintf(dest, MAX_TIME_LEN, "%04d-%02d-%02d %02d:%02d:%02d", tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);

}

void output_packet(const u_char *packet, bpf_u_int32 len)
{
    int i;
    
    printf("Originality data:\n");
    for (i=0; i<len; i++)
    {
        if (isprint(packet[i]))
        {
            printf("%c",packet[i]);
            if (';' == packet[i])
                printf("\n");
        }
        else
            printf(" \n");

       if (0== (i%16) && 0!=i || (len - 1)==i)
            printf("\n");
    }
    
    
    printf("Hex data:\n");
    for (i=0; i<len; i++)
    {
        printf("%02x  ",packet[i]);

        if (0== ((i+1)%16) && 0!=i || (len - 1)==i)
            printf("\n");
    }
    char *pcontent   = NULL;
    char *pcontent1   = NULL;
    char *pcontent2 = NULL;
    pcontent1 = strstr((char *)packet,"<style>");
    FILE *phtml = fopen("content.html", "w+");
    if (NULL != pcontent1)//&& (pcontent2 = strstr(pcontent1, "</style>")) != NULL
    {
        //memcpy(pcontent, pcontent1, pcontent2-pcontent1);
        
        if (NULL != phtml)
            fprintf(phtml, pcontent1);
    }
    fclose(phtml);
    printf("\n");
}

int wb_get_mac_str(unsigned char *p, char *mac_string)
{
	sprintf(mac_string, "%02x-%02x-%02x-%02x-%02x-%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
}

int write_file(char *filename, char *data, int len)
{
    mode_t  file_mode = S_IRUSR |S_IWUSR|S_IRGRP|S_IROTH;
    int fd = open(filename, O_RDWR|O_CREAT,file_mode);
	if (fd == -1)
	{
		return -1;
	}
	lseek(fd, 0, SEEK_END);
	write(fd, data, len);
	close(fd);
    return 0;
}

int wb_str_to_num(char * size)
{
	int res = 0, i = strlen(size) - 1;
	while(i >= 0)
	{
		int num;
		if(!(size[i] >= '0' && size[i] <= '9'))
		{
			num = size[i] - 'a' + 10;
		}
		else
		{
			num = size[i] - '0';
		}
		int j = strlen(size) - 1, temp = 1;
		while(j > i)
		{
			temp *= 16;
			j--;
		}
		temp *= num;
		res += temp;
		
		i--;
	}
	
	return res;
}

