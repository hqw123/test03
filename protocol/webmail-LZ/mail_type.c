#include "mail_type.h"
#include "list.h"
#include "hashfn.c"
#include <malloc.h>

// stolen from netsniff-read/built-in.h
#define     CO_IN_CACHE_SHIFT 7
#define 	CO_CACHE_LINE_SIZE	(1 << CO_IN_CACHE_SHIFT)

#ifndef __cacheline_aligned
# define __cacheline_aligned	__attribute__((aligned(CO_CACHE_LINE_SIZE)))
#endif

typedef unsigned short (*validate_action_func)(unsigned short, char *);
typedef struct mail_type_map
{
	char *host;
	unsigned short type;
	validate_action_func  cb;
}mail_type_map_t;

static unsigned short validate_189_action(unsigned short mails_type, char *uri);
static unsigned short validate_sina_action(unsigned short mails_type, char *uri);
static unsigned short validate_126_action(unsigned short mails_type, char *uri);
static unsigned short validate_163_action(unsigned short mails_type, char *uri);
static unsigned short validate_163upt_action(unsigned short mails_type, char *uri);
static unsigned short validate_yeah_action(unsigned short mails_type, char *uri);
static unsigned short validate_139_action(unsigned short mails_type, char *uri);
static unsigned short validate_21cn_action(unsigned short mails_type, char *uri);
static unsigned short validate_tencent_action(unsigned short mails_type, char *uri);
static unsigned short validate_tom_action(unsigned short mails_type, char *uri);
static unsigned short validate_sohu_action(unsigned short mails_type, char *uri);
static unsigned short validate_sogou_action(unsigned short mails_type, char *uri);
static unsigned short validate_m_sohu_action(unsigned short mails_type, char *uri);//....lihan
static unsigned short validate_m_sina_action(unsigned short mails_type, char *uri);//....lihan
static unsigned short validate_m_189_action(unsigned short mails_type, char *uri);//....lihan
static unsigned short validate_2980_action(unsigned short mails_type, char *uri);
static unsigned short validate_12306_action(unsigned short mails_type, char *uri);
static unsigned short validate_hot_action(unsigned short mails_type, char *uri);

// use the magic number here is not only ugly but also boring
// i should do some maps here for some reasons, but i've no time to do that, so boring tooooooooo
static mail_type_map_t mails_map[] = 
{
	// 189 webmail, send, upload attachment
	{"webmail30.189.cn", 0x1500, validate_189_action},
	{"webmail29.189.cn", 0x1500, validate_189_action},
	{"webmail28.189.cn", 0x1500, validate_189_action},
	{"webmail27.189.cn", 0x1500, validate_189_action},
	{"webmail26.189.cn", 0x1500, validate_189_action},
	{"webmail25.189.cn", 0x1500, validate_189_action},
	{"webmail24.189.cn", 0x1500, validate_189_action},
	{"webmail23.189.cn", 0x1500, validate_189_action},
	{"webmail22.189.cn", 0x1500, validate_189_action},
	{"webmail21.189.cn", 0x1500, validate_189_action},
	{"webmail20.189.cn", 0x1500, validate_189_action},
	{"webmail19.189.cn", 0x1500, validate_189_action},
	{"webmail18.189.cn", 0x1500, validate_189_action},
	{"webmail17.189.cn", 0x1500, validate_189_action},
	{"webmail16.189.cn", 0x1500, validate_189_action},
	{"webmail15.189.cn", 0x1500, validate_189_action},
	{"webmail14.189.cn", 0x1500, validate_189_action},
	{"webmail13.189.cn", 0x1500, validate_189_action},
	{"webmail12.189.cn", 0x1500, validate_189_action},
	{"webmail11.189.cn", 0x1500, validate_189_action},
	{"webmail10.189.cn", 0x1500, validate_189_action},
	{"webmail9.189.cn",  0x1500, validate_189_action},
	{"webmail8.189.cn",  0x1500, validate_189_action},
	{"webmail7.189.cn",  0x1500, validate_189_action},
	{"webmail6.189.cn",  0x1500, validate_189_action},
	{"webmail5.189.cn",  0x1500, validate_189_action},
	{"webmail4.189.cn",  0x1500, validate_189_action},
	{"webmail3.189.cn",  0x1500, validate_189_action},
	{"webmail2.189.cn",  0x1500, validate_189_action},
	{"webmail1.189.cn",  0x1500, validate_189_action},
	// sina webmail, send, upload attachment
	{"m0.mail.sina.cn",     0x0100, validate_sina_action},
	{"m0.mail.sina.com.cn", 0x0100, validate_sina_action},
	{"m1.mail.sina.com.cn", 0x0100, validate_sina_action},
	{"m2.mail.sina.com.cn", 0x0100, validate_sina_action},
	{"m3.mail.sina.com.cn", 0x0100, validate_sina_action},
	// 163 webmail, send
	{"mail.163.com",  0x0400, validate_163_action},
    {"reg.163.com",   0x0400, validate_163_action},   
	//{"mail.yeah.net", 0x0800, validate_yeah_action},
	// 163 upload attachment server
	{"c10bj.mail.163.com", 0x0400, validate_163upt_action},
	{"c9bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c8bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c7bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c6bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c5bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c4bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c3bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c2bj.mail.163.com",  0x0400, validate_163upt_action},
	{"c1bj.mail.163.com",  0x0400, validate_163upt_action},
	// 126 mail, 126 send upload wat the same as mail.163.com
	{"mail.126.com", 0x0D00, validate_163_action},
	{"push.webmail.mail.126.com", 0x0D00, validate_126_action},
	// 126 upload, the 126 upload action was the same as 163, URI: /upxmail/upload?sid=.....
	{"c1bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c2bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c3bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c4bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c5bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c6bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c7bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c8bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c9bj.mail.126.com",  0x0D00, validate_163upt_action},
	{"c10bj.mail.126.com", 0x0D00, validate_163upt_action},
	// mail.yeah.net the same as 163
	{"mail.yeah.net", 0x0800, validate_163_action},
	// upload action of mail.yeah.net, the same as 163
	{"c1bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c2bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c3bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c4bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c5bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c6bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c7bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c8bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c9bj.mail.yeah.net",  0x0800, validate_163upt_action},
	{"c10bj.mail.yeah.net", 0x0800, validate_163upt_action},
	// 10086 webmail, send, upload attachment
	{"appmail.mail.10086.cn",     0x1300, validate_139_action},
	{"smsrebuild1.mail.10086.cn", 0x1300, validate_139_action},
	{"pushmsg.mail.10086.cn",     0x1300, validate_139_action},
    {"html5.mail.10086.cn",       0x1300, validate_139_action},
    {"mail.10086.cn",             0x1300, validate_139_action},   
    //21cn.com
	{"mail.21cn.com", 0x0200, validate_21cn_action},
    {"open.e.189.cn", 0x0200, validate_21cn_action},   
	// tom webmail, only mail1 - mail2 valid till we writing this piece
	// mail3 - mail5 is reserved
	// Fri Mar  3 22:26:47 PST 2017
	{"mail1.tom.com",    0x0700, validate_tom_action},
	{"mail2.tom.com",    0x0700, validate_tom_action},
	{"mail3.tom.com",    0x0700, validate_tom_action},
	{"mail4.tom.com",    0x0700, validate_tom_action},
	{"mail5.tom.com",    0x0700, validate_tom_action},
    {"web.mail.tom.com", 0x0700, validate_tom_action},
	// sohu webmail
	{"mail.sohu.com",  0x0300, validate_sohu_action},
	{"mail.sogou.com", 0x0C00, validate_sogou_action},
	// tencent mail
	{"mail.qq.com", 0x0B00, validate_tencent_action},
    {"www.2980.com", 0x1400, validate_2980_action},
    {"kyfw.12306.cn", 0x1600, validate_12306_action},
    {"mail.12306.cn", 0x1600, validate_12306_action},
	//sohu_m_mail
	{"m.mail.sohu.com", 0x8300, validate_m_sohu_action},//......
	//sina_m_mail
	{"api.mail.sina.com.cn", 0x8400, validate_m_sina_action},//......
	//189_m_mail
	{"api.mail.189.cn:8081", 0x8500, validate_m_189_action},//......
    {"outlook.live.com", 0x0500, validate_hot_action},   
};	

// NOTE:we search some significant strings from the uri, and, use them to 
// determin what's the action it belongs to. while the problem is that's just
// what we had implemented the basic functions here, we should move the significant strings 
// into the configurations to get more flexible

static inline
unsigned short validate_hot_action(unsigned short mails_byte, char *uri)
{
    unsigned short act_byte = 0;
    if(!strncmp(uri, "/owa/?ae=Item", 13
))
        act_byte = 0x0022;

    return mails_byte | act_byte;
}

static inline
unsigned short validate_189_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "sendMail.do"))
		act_byte = 0x0012;
	else if (strstr(uri, "upload.do"))
		act_byte = 0x0061;
    else if (strstr(uri, "/mail/readMail.do") || strstr(uri, "/mail/getMailDisplayMessage.do"))
	{
		act_byte = 0x0021;
	}
	return mails_byte | act_byte;
}

//sina_mail add sian_m_mail_upload ,modify by lihan 2017.3.18
static inline
unsigned short validate_sina_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "uploadatt.php"))	
		act_byte = 0x0042;	
	else if (strstr(uri, "send.php"))
		act_byte = 0x0012;
	//add sian_m_mail_upload  lihan 2017.3.18	
	else if (strstr(uri, "api/upload.php"))//upload
	{
		act_byte = 0x0066;
	}
    else if (strstr(uri, "classic/readmail.php"))    // PC receive mail
    {
        act_byte = 0x0031;
    }
    else if (strstr(uri, "wa.php?a=readmail"))      // Phone receive mail
    {
        act_byte = 0x0030;
    }
	
	return mails_byte | act_byte;
}

static inline
unsigned short validate_126_action(unsigned short mails_byte, char *uri)
{
    unsigned short act_byte = 0;
    if (strstr(uri, "/cometd?"))
	{
		act_byte = 0x0021;
	}

	return mails_byte | act_byte;
}

static inline
unsigned short validate_163_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if ((strstr(uri, "action=deliver") && strstr(uri, "func=mbox:compose")) ||
			strstr(uri, "func=mbox:replyMessage"))
    {
		act_byte = 0x0011;
    }
    else if (strstr(uri, "readhtml.jsp?mid=") || (strstr(uri, "func=mbox:readMessage") && strstr(uri, "action=read")))
	{
		act_byte = 0x0026;
	}
    else if(!strncmp(uri, "/entry/cgi/ntesdoor?", 20) || !strncmp(uri, "/logins.jsp HTTP", 16))
    {
        act_byte = 0x0002;
    }
    else if(!strncmp(uri, "/dl/l", 5))
    {
        return 0x0d02;
    }
        
	return mails_byte | act_byte;
}

static inline
unsigned short validate_163upt_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if ((strstr(uri, "upload")) || (strstr(uri, "flashUpload")))
		act_byte = 0x0063;// modify by lihan 2017.3.28

	return mails_byte | act_byte;
}

static inline
unsigned short validate_yeah_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if ((strstr(uri, "&action=deliver") && strstr(uri, "func=mbox:compose")) ||
			strstr(uri, "func=mbox:replyMessage"))
		act_byte = 0x0011;
	else if (strstr(uri, "func=upload"))
		act_byte = 0x0061;
	return mails_byte | act_byte;
}

static inline
unsigned short validate_139_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "func=mbox:compose"))
		act_byte = 0x0011;
	else if (strstr(uri, "func=attach:upload"))
		act_byte = 0x0061;
	else if (strstr(uri, "func=sms:sendSms"))
		act_byte = 0x0081;
    else if (strstr(uri, "/pns/poll?"))
        act_byte = 0x0024;
    else if(strstr(uri, "func=view:readMessage"))
		act_byte = 0x0025;
    else if(!strncmp(uri, "/Login/Login.ashx", 17))
        act_byte = 0x0012;
    
	return mails_byte | act_byte;
}

static inline
unsigned short validate_21cn_action(unsigned short mails_byte, char *uri)
{
    unsigned short act_byte = 0;
    if (strstr(uri, "mail/sendMail.do"))                                                       //send mail
        act_byte = 0x0011;
    else if (strstr(uri, "/mail/readMail.do") || strstr(uri, "/mail/getMailDisplayMessage.do"))    //recv mail
        act_byte = 0x0041;
    else if(!strncmp(uri, "/api/common/loginSubmit.do HTTP", 31) || !strncmp(uri, "/api/logbox/oauth2/loginSubmit.do HTTP", 38))                 //21cn mail password
        act_byte = 0x0001;
    
    return mails_byte | act_byte;
}

static inline
unsigned short validate_tencent_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "compose_send?sid="))
		act_byte = 0x0011;
	else if (strstr(uri, "upload"))
		act_byte = 0x0061;

	return mails_byte | act_byte;
}

static inline
unsigned short validate_2980_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (!strncmp(uri, "/v1/login HTTP", 14))
        act_byte = 0x0002;
    else if (strstr(uri, "/v1/mail/") && strstr(uri, "mailfolder=Inbox"))
        act_byte = 0x0022;
    else if(!strncmp(uri, "/v1/proxy/mail/send HTTP", 24))
        act_byte = 0x0011;
    
	return mails_byte | act_byte;
}

static inline
unsigned short validate_12306_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (!strncmp(uri, "/otn/login/loginAysnSuggest HTTP", 32))
        act_byte = 0x0001;
    else if (!strncmp(uri, "/app/mail/login HTTP", 20))
        act_byte = 0x0002;
    
	return mails_byte | act_byte;
}

static inline
unsigned short validate_tom_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "sendmail.action"))	
		act_byte = 0x0012;
	else if (strstr(uri, "dfsuploadAttachment.do?"))
		act_byte = 0x0062;
	else if (strstr(uri, "attachfapp"))
		act_byte = 0x0061;
    else if(strstr(uri, "readmail/show.action"))
		act_byte = 0x0022;
    else if(strstr(uri, "readmail/context.action"))
        act_byte = 0x0023;
	else if(strstr(uri, "webmail/login/loginService.action"))
        act_byte = 0x0001;
    
	return mails_byte | act_byte;
}

static inline
unsigned short validate_sohu_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	// the sohu FE mail protocol may be different than the old ones
	if (strstr(uri, "/mail HTTP/1"))
		act_byte = 0x0011;
	else if (strstr(uri, "/mail/att HTTP"))
		act_byte = 0x0041;
	else if (strstr(uri, "/mail/att?X-Progress-ID") || strstr(uri, "/mail/att/flash"))
		act_byte = 0x0061;
	else if (strstr(uri, "/mail/att/resumeUpload?xid"))
		act_byte = 0x0062;
	else if (strstr(uri, "/fe/attach"))
		act_byte = 0x0066; // this type is new type which can't be recongnized by old code
	else if (strstr(uri, "/fe/mail")) // oops, the new version of sohu mail use HTTP PUT method, this may not work here
		act_byte = 0x0012;
	
	// we return the action type for some debug reasons 
	return mails_byte | act_byte;
}

// sogou mail was discarded long time ago
static inline
unsigned short validate_sogou_action(unsigned short mails_type, char *uri)
{
	return mails_type;
}

//sohu_m_mail
static inline
unsigned short validate_m_sohu_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "app/mail HTTP"))//send mail
		act_byte = 0x0011;
	else if (strstr(uri, "app/attach"))//upload
		act_byte = 0x0066;
	else if (!strncmp(uri, "/mail/", 6))
	{
		act_byte = 0x0039;
	}
	
	return mails_byte | act_byte;
}

//sina_m_mail
static inline
unsigned short validate_m_sina_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "sendmessage"))//send mail
		act_byte = 0x0011;
	//	HOST domain same as sina mail lihan 3.18
/*	
	else if (strstr(uri, "api/upload.php"))//upload
		act_byte = 0x0066;
*/	
	return mails_byte | act_byte;
}

//189_m_mail
static inline
unsigned short validate_m_189_action(unsigned short mails_byte, char *uri)
{
	unsigned short act_byte = 0;
	if (strstr(uri, "mailApi/api/sendMail.do HTTP"))//send mail
		act_byte = 0x0011;
	else if (strstr(uri, "mailApi/api/upload.do?"))//upload
		act_byte = 0x0066;

	return mails_byte | act_byte;
}

#define     MAIL_H_SIZE		(sizeof(mails_map)/sizeof(mails_map[0]))
// this size may some times be larger than 1024, but the pows of 2
static size_t mbox_ht_size = 2048;

static struct hlist_head *mbox_hashtable;

typedef struct mailbox_gather
{
	char 	*key;
	unsigned short key_value;
	size_t hashv;
	size_t bucket_index;
	struct hlist_node mb_hash;
	validate_action_func vacb;
} mailbox_gather_t __attribute__((aligned(8)));

void init_mbox_hashtable()
{
	int i;
	mbox_hashtable = (struct hlist_head *)memalign(CO_CACHE_LINE_SIZE, sizeof(struct hlist_head) * mbox_ht_size);
	for (i = 0; i < mbox_ht_size; i++)	
		INIT_HLIST_HEAD(&mbox_hashtable[i]);

	for (i = 0; i < MAIL_H_SIZE; i++)
	{
		size_t bucket_i = 0;
		mailbox_gather_t *m = (mailbox_gather_t *)memalign(CO_CACHE_LINE_SIZE, sizeof(mailbox_gather_t));
		m->key = mails_map[i].host;
		m->key_value = mails_map[i].type;
		memset(&m->mb_hash, 0, sizeof(m->mb_hash));
		m->hashv = BKDRHash(m->key);
		bucket_i = m->hashv % mbox_ht_size;
		m->bucket_index = bucket_i;
		m->vacb = mails_map[i].cb;
		hlist_add_head(&m->mb_hash, &mbox_hashtable[bucket_i]);
	}
}

// not time to do that
int mbox_insert_value(const char *key)
{
	return -1;
}

mailbox_gather_t* mbox_lookup_value(const char *key)
{
	size_t hash = BKDRHash(key);
	struct hlist_head *h = &mbox_hashtable[hash % mbox_ht_size];
	mailbox_gather_t *retval;
	struct hlist_node *node = h->first;
	mailbox_gather_t *mb;

	hlist_for_each_entry(mb, node, h, mb_hash)
		if (mb->hashv == hash && !strcmp(mb->key, key))
			return mb;
	return NULL;
}

void destroy_mbox_hashtable()
{
	// not implement yet
}

Mail_info *find_mail_node(unsigned int source_ip, unsigned int dest_ip, unsigned short source_port, unsigned short dest_port, int *is_sent)
{
	//printf("find_mail_node ...\n");
	Mail_info *mail_info = mail_tab.head->next;
	while (mail_info != NULL) 
	{
		if (mail_info->source_ip == source_ip && mail_info->dest_ip == dest_ip && mail_info->source_port == source_port && mail_info->dest_port == dest_port && !mail_info->is_complished) 
		{
			*is_sent = 1;
			//printf("find_mail_node *is_sent = 1 ...\n");
			break;
		}
		else
		if (mail_info->source_ip == dest_ip && mail_info->dest_ip == source_ip && mail_info->source_port == dest_port && mail_info->dest_port == source_port && !mail_info->is_complished) 
		{
			*is_sent = 0;
			//printf("find_mail_node *is_sent = 0 ...\n");
			break;
		}
		else
		{
			//printf("...  do not find mail_node  ...\n");
			//printf("mail_tab.count:%d, addr:%p \n", mail_tab.count, mail_info);
			mail_info = mail_info->next;
		}
	}
	//printf("find_mail_node complete ...\n");
	return mail_info;
}

Attach_info *find_attach_node(unsigned int source_ip, unsigned int dest_ip, unsigned short source_port, unsigned short dest_port, int *is_sent, unsigned short packet_type)
{
	//printf("find_attach_node ...\n");
	Attach_info *attach_info = attach_tab.head->next;
	while (attach_info != NULL) 
	{
		if (attach_info->source_ip == source_ip && attach_info->dest_ip == dest_ip && attach_info->source_port == source_port && attach_info->dest_port == dest_port && !attach_info->is_complished && (attach_info->packet_type == packet_type||packet_type <=0)) 
		{
			*is_sent = 1;
			break;
		} 
		else 
		if (attach_info->source_ip == dest_ip && attach_info->dest_ip == source_ip && attach_info->source_port == dest_port && attach_info->dest_port == source_port && !attach_info->is_complished && (attach_info->packet_type == packet_type||packet_type <=0)) 
		{
			*is_sent = 0;
			break;
		} 
		else 
		{
			attach_info = attach_info->next;
		}
	}

	//printf("find_attach_node complete ...\n");
	if(attach_info) 
//printf("find attach-%p\n",attach_info);
	return attach_info;
}

Mail_info *insert_mail_node(char *srcMAC, struct iphdr *pip, struct tcphdr *ptcp, unsigned short type)
{
	//printf("insert_mail_node...");
	Mail_info *mail_info = (Mail_info *)malloc(sizeof(Mail_info));
	if (mail_info == NULL)
		return NULL;
	
	memset(mail_info, 0, sizeof(Mail_info));
	mail_info->source_ip = pip->saddr;
	mail_info->dest_ip = pip->daddr;
	mail_info->source_port = ptcp->source;
	mail_info->dest_port = ptcp->dest;
	memcpy(mail_info->client_mac, srcMAC, MAC_LEN);
	mail_info->is_complished = 0;
	mail_info->mail_type = type;
	mail_info->mail_length = 0;
	mail_info->ok_length = 0;//
	mail_info->mail_data = NULL;
	mail_info->is_writing = 0;
	mail_info->recive_length = 0;
	mail_info->recive_data = NULL;
	mail_info->connect_id[0]=0;
	mail_info->mail_id = (char *)malloc(MAX_ID_LEN);
	memset(mail_info->mail_id, 0, MAX_ID_LEN);
	mail_info->is_proce_mail = 0;
	mail_info->content = NULL;
	mail_info->attach = NULL;
	mail_info->num_of_attach = 0;
	mail_info->start_seq = ntohl(ptcp->seq);
	mail_info->prev = mail_tab.head;
	mail_info->next = mail_tab.head->next;
	mail_tab.head->next = mail_info;
	int tmp_type;
	tmp_type=type>>8;
	//printf("type : %d\n", tmp_type);
	switch(tmp_type)
	{
		case 1: mail_info->mail_num= 306; strcpy(mail_info->url, "mail.sina.com"); break;
		case 2: mail_info->mail_num= 307; strcpy(mail_info->url, "mail.21cn.com"); break;
		case 3: mail_info->mail_num= 305; strcpy(mail_info->url, "mail.sohu.com"); break;
		case 4: mail_info->mail_num= 301; strcpy(mail_info->url, "mail.163.com"); break;
		case 5: mail_info->mail_num= 303; strcpy(mail_info->url, "www.hotmail.com"); break;
		case 6: mail_info->mail_num= 304; strcpy(mail_info->url, "mail.yahoo.com"); break;
		case 7: mail_info->mail_num= 302; strcpy(mail_info->url, "mail.tom.com"); break;
		case 8: mail_info->mail_num= 301; strcpy(mail_info->url, "mail.yeah.net"); break;
		case 9: mail_info->mail_num= 309; strcpy(mail_info->url, "www.eyou.com"); break;
		case 10:mail_info->mail_num= 317; strcpy(mail_info->url, "mail.236.com"); break;
		case 11:mail_info->mail_num= 308; strcpy(mail_info->url, "mail.qq.com"); break;
		case 12:mail_info->mail_num= 305; strcpy(mail_info->url, "mail.sogou.com"); break;
		case 13:mail_info->mail_num= 301; strcpy(mail_info->url, "mail.126.com"); break;
		case 14:mail_info->mail_num= 301; strcpy(mail_info->url, "mail.188.com"); break;
		case 15:mail_info->mail_num= 310; strcpy(mail_info->url, "www.gmail.com"); break;
		case 16:mail_info->mail_num= 311; strcpy(mail_info->url, "www.mail.com");break;
		case 17:mail_info->mail_num= 312; strcpy(mail_info->url, "mail.aol.com");break;
		case 18:mail_info->mail_num= 313; strcpy(mail_info->url, "mail.daum.net");break;
		case 19:mail_info->mail_num= 314; strcpy(mail_info->url, "mail.139.com");break;
		case 20:mail_info->mail_num= 315; strcpy(mail_info->url, "www.2980.com");break;
		case 21:mail_info->mail_num= 316; strcpy(mail_info->url, "mail.189.cn");break;
		case 22:mail_info->mail_num= 318; strcpy(mail_info->url, "mail.12306.cn");break;
		//手机webmail
		case 129:mail_info->mail_num= 301; strcpy(mail_info->url, "mail.163.com");break;
		case 130:mail_info->mail_num= 302; strcpy(mail_info->url, "mail.qq.com");break;
		case 131:mail_info->mail_num= 305; strcpy(mail_info->url, "m.mail.sohu.com");break;//lihan add sohu_m_mail
		case 132:mail_info->mail_num= 306; strcpy(mail_info->url, "api.mail.sina.com.cn");break;//lihan add sina_m_mail
		case 133:mail_info->mail_num= 316; strcpy(mail_info->url, "api.mail.189.cn:8081");break;//lihan add 189_m_mail
	  	default: break;
	}
	mail_tab.count++;
	if (mail_info->next != NULL)
		mail_info->next->prev = mail_info;

	//printf("insert_mail_node complete ...\n");
	
	return mail_info;
}

Attach_info *insert_attach_node(struct iphdr *pip, struct tcphdr *ptcp, unsigned short type, unsigned short packet_type)
{
	//printf("insert_attach_node ...\n");
	if(attach_tab.count == 20){
		Attach_info *attach_tmp = attach_tab.tail;
		attach_tab.tail->prev->next=NULL;
		attach_tab.tail=attach_tab.tail->prev;
		delete_attach(attach_tmp);
		attach_tab.count--;
	}

	Attach_info *attach_info = (Attach_info *)malloc(sizeof(Attach_info));
	if (attach_info == NULL)
		return NULL;

	memset(attach_info,0,sizeof(Attach_info));
	attach_info->packet_type = packet_type;
	attach_info->source_ip = pip->saddr;
	attach_info->dest_ip = pip->daddr;
	attach_info->source_port = ptcp->source;
	attach_info->dest_port = ptcp->dest;
	attach_info->attach_type = type;
	attach_info->is_complished = 0;
	attach_info->is_writing = 0;
	attach_info->is_get_ok = 0;
	attach_info->ok_length = 0;
	attach_info->recive_data = NULL;
	attach_info->start_seq = ntohl(ptcp->seq);
	attach_info->ID_str[0] = 0;
	attach_info->path_of_sender = NULL;
	attach_info->ok_data = (char *)malloc(OK_DATA_LEN);
	if (attach_info->ok_data == NULL)
		return NULL;
	attach_info->ok_len = OK_DATA_LEN;
	memset(attach_info->ok_data, 0, OK_DATA_LEN);
	attach_info->bodyTotal = 0;
	attach_info->body = NULL;
	attach_info->bodyLen = 0;
	attach_info->header = NULL;
	attach_info->headerLen = 0;
	attach_info->status = 0;
	attach_info->prev = attach_tab.head;
	attach_info->next = attach_tab.head->next;
	attach_tab.head->next = attach_info;
	attach_tab.count++;
	if (attach_info->next != NULL)
		attach_info->next->prev = attach_info;
	else
		attach_tab.tail=attach_info;

	//printf("insert_attach_node complete ...\n");
	
//printf("insert attach-%p\n",attach_info);
	return attach_info;
}

int mail_type_prefetched(char *data)
{
	// mix type = mail_type | action_type
	unsigned short mixtype = 0;
	unsigned short mail_type = 0;
	char *host_p = strstr(data, "Host:");
	char *host_e;
	char host_v[128] = {0};

	if (!host_p)
		return mixtype;

	// data + 6, skip the length of "Host: " keyword
	host_p += 6;
	host_e = strstr(host_p, "\r\n");
    if (host_e - host_p < 127 && host_e - host_p > 0)
    {
        strncpy(host_v, host_p, host_e - host_p);
    }
    else
    {
        return mixtype;
    }
    
	mailbox_gather_t *mb = mbox_lookup_value(host_v);
	if (!mb) return mixtype;
	
	mail_type = mb->key_value;
	// FIXME: offset +5 , this may not work for mail sohu <HTTP PUT, not POST>
	if (!strncmp(data, "GET ", 4) || !strncmp(data, "PUT ", 4))
		mixtype = mb->vacb(mail_type, data + 4);
	else
		mixtype = mb->vacb(mail_type, data + 5);

#if 0  //for test
	char uri[80];
	strncpy(uri, data, 80-1);

	if ((mixtype & 0x00FF) && (mixtype & 0xFF00))
		printf("mixtum type = 0x%04x, mailhost= %s\nuri=%s\n", mixtype, mb->key, uri);
#endif
	return mixtype;
}

unsigned short mail_type(char *data)
{
    unsigned short type = 0;
    if(!strncmp(data, "POST /ppsecure/post.srf?", 24))
        type = 0x0501;
    else if(!strncmp(data, "POST /owa/?ae=PreFormAction", 27) && strstr(data, "a=Send"))
        type = 0x0512;
    return type;
}

#if 0
int mail_type2(char *data)
{
	unsigned short int type = 0;
	char *host_p = NULL;

	if(!strncmp(data,"POST ", 5))
	{
		host_p = strstr(data, "\r\nHost");
		
		if(!strncmp(data, "POST /classic/send.php?", 22))
		{
			type = 0X0115;  //  sina vip
			if(!strncmp(data + 23,"ts=",3)){
				type = 0x0112;}
		} 
		else 
			if(!strncmp(data,"POST /cgi-bin/login.",20))
		{
			type = 0X0101; // sina_pass
		} 
		else 
			if(!strncmp(data,"POST /hd/signin.php",19) || !strncmp(data,"POST /sso/login.",16))
		{
			type = 0x0102;
		}
		else
			if(!strncmp(data,"POST /cgi-bin/cnlogin.",22))
		{
			type = 0X0101;
		}
		else 
			//if(!strncmp(data,"POST /classic/rdMail.php",24))
			if(!strncmp(data,"POST /classic/readmail.php",26))

		//if(!strncmp(data,"POST /classic/send.php",22))
		{
			type = 0x0131;
		}
		else
			if(!strncmp(data,"POST /classic/packatt.php",25))
		{
			type = 0x0133;
		}
		//yanglei
		else
			if(!strncmp(data,"POST /uploadatt.php",19) || !strncmp(data,"POST /classic/uploadatt.php",27))
		{
			type = 0x0142;
		}
		else
			if(!strncmp(data,"POST /webmail/upload.do",23) && strstr(data, "mail.21cn.com")) 
		{
		       	//type=0x0209;      //21cn_attachment
			type = 0x0261;
		}
		else 
			if (!strncmp(data, "POST /webmail/sendMail.do", 25) && strstr(data, "mail.21cn.com"))
		{
			type = 0x0211;   // 21cn
		} 
		/*else 
			if (!strncmp(data, "POST /maillogin.jsp ",20))
		{
			type = 0x0201;  //21CN_PASS
		}*/
		else 
			if (!strncmp(data, "POST /sso/login_js.jsp HTTP/1.1", 31) && strstr(data,"mail.sohu.com")) 
		{
			type = 0x0302;    //sohu vip password
		} 
		else 
			if (!strncmp(data, "POST /login.jsp HTTP/1.1", 24) && strstr(data,"mail.sohu.com")) 
		{
			type = 0x0303;
		} 
		else 
			if (!strncmp(data, "POST /bapp", 10) &&( !strncmp(data + 13, "/mail HTTP/1", 12) || !strncmp(data + 12, "/mail HTTP/1", 12) || !strncmp(data + 14, "/mail HTTP/1", 12) || !strncmp(data + 15, "/mail HTTP/1", 12)) && strstr(data,"mail.sohu.com"))
		{
			type = 0x0311;  //new sohu
		} 
		else 
			if (!strncmp(data, "POST /bapp", 10) && (!strncmp(data + 13, "/mail HTTP/1", 12) || !strncmp(data + 12, "/mail HTTP/1", 12) || !strncmp(data + 14, "/mail HTTP/1", 12) || !strncmp(data + 15, "/mail HTTP/1", 12) )&& strstr(data,"vip.sohu.com"))
		{
			type = 0x0312;
		} 
		else 
			if (!strncmp(data, "POST /bapp", 10) && !strncmp(data + 13, "/mail/att HTTP",14) || !strncmp(data + 12, "/mail/att HTTP", 14) && strstr(data,"mail.sohu.com"))
		{
			type = 0x0341;      //new sohu delete
		} 
		/*else 
		if (!strncmp(data, "POST /bapp", 10) && (!strncmp(data + 13, "/mail/att/flash?xid=", 20) || !strncmp(data + 12, "/mail/att/flash?xid=", 20) || !strncmp(data + 14, "/mail/att/flash?xid=", 20) || !strncmp(data + 15, "/mail/att/flash?xid=", 20)) && strstr(data,".sohu.com"))
		{
		type = 0x0361;
	} */
		else if(!strncmp(data,"POST /bapp/",11) && strstr(data,"/mail/att?X-Progress-ID") && strstr(data,"mail.sohu.com"))// !strncmp(data,"POST /bapp/128/mail/att?X-Progress-ID",37) 
                {
                        type=0x0361;
                }

		else 
			if (!strncmp(data, "POST /bapp", 10) && (!strncmp(data + 13, "/mail/att/flash?", 16) || !strncmp(data + 12, "/mail/att/flash?", 16) || !strncmp(data + 14, "/mail/att/flash?", 16) || !strncmp(data + 15, "/mail/att/flash?", 16)) && strstr(data,".sohu.com"))
		{
			type = 0x0361;
		}
		else 
			if (!strncmp(data, "POST /bapp", 10) && (!strncmp(data + 13, "/mail/att/resumeUpload?xid", 25) || !strncmp(data + 12, "/mail/att/resumeUpload?xid", 25) || !strncmp(data + 14, "/mail/att/resumeUpload?xid", 25) || !strncmp(data + 15, "/mail/att/resumeUpload?xid", 25)) && strstr(data,"mail.sohu.com"))
		{  //new sohu vip
			type = 0x0362;
		} 
		else 
			if (!strncmp(data,"POST /a/s?sid=",14) && !strncmp(data+46,"&func=mbox:readMessage",22)&& memfind(host_p,"188.com",50))
		{
			type = 0x0E31;
		} 
		else 
		if ((!strncmp(data, "POST /a/s?sid=", 14) || !strncmp(data, "POST /js3/s?sid=", 16) || !strncmp(data, "POST /js4/s?sid=", 16)) && !strstr(data, "mail.yeah.net"))
		{
			if (strstr(data, "&action=deliver") && memfind(data, "&func=mbox:compose", 100) != NULL)
				type = 0x0411;  //163
			/*else
			if (memfind(data, "&func=global:sequential", 100) != NULL)
				type = 0x0411;  //163*/
			else
			if (memfind(data, "&func=mbox:replyMessage", 100) != NULL)
				type = 0x0411;  //163
			else
			if (strstr(data, "&func=upload:deleteTasks") != NULL)
				type = 0x0441;
			/*else
			if (memfind(data, "&func=global:sequential", 100) != NULL)
			type = 0x0421;*/
			else
			if (memfind(data, "&func=mbox:readMessage", 100) != NULL)
				type = 0x0422;
			else
			if (strstr(data, "&func=mbox:listMessage") != NULL)
				return 0;
		}
		else 
		if (!strncmp(data, "POST /js5/s?sid=", 16) && !strstr(data, "mail.yeah.net"))
		{
			if (strstr(data, "&action=deliver") && memfind(data, "&func=mbox:compose", 100) != NULL)
				type = 0x0411;  //163 V5.0
			else
			if (memfind(data, "&func=mbox:replyMessage", 100) != NULL)
				type = 0x0411;  //163 V5.0
			else
			if (strstr(data, "&func=upload:deleteTasks") != NULL)
				type = 0x0441;
			else
			if (memfind(data, "&func=mbox:readMessage", 100) != NULL)
				type = 0x0426;
			else
			if (strstr(data, "&func=mbox:listMessage") != NULL)
				return 0;
		}else
		if (!strncmp(data, "POST /js6/s?sid=", 16) && !strstr(data, "mail.yeah.net"))
		{
			if (strstr(data, "&action=deliver") && memfind(data, "&func=mbox:compose", 100) != NULL)
				type = 0x0411;  //163 V6.0
			else
			if (memfind(data, "&func=mbox:replyMessage", 100) != NULL)
				type = 0x0411;  //163 V6.0
			else
			if (strstr(data, "&func=upload:deleteTasks") != NULL)
				type = 0x0441;
			else
			if (memfind(data, "&func=mbox:readMessage", 100) != NULL)
				type = 0x0426;
			else
			if (strstr(data, "&func=mbox:listMessage") != NULL)
				return 0;
		}
		else
			if(!strncmp(data, "POST /js4/s?sid=", 16) && strstr(data, "mail.yeah.net") && memfind(data, "&func=mbox:readMessage", 100) != NULL)
		{
			type = 0x0821;  // yeah head
		}
		else
			if(!strncmp(data, "POST /js5/s?sid=", 16) && strstr(data, "mail.yeah.net") && memfind(data, "&func=mbox:readMessage", 100) != NULL)
		{
			type = 0x0823;  // yeah head
		}
		else 
			if (!strncmp(data, "POST /CheckUser.jsp HTTP/1.1", 28))
		{
			type = 0x0401;   //hao123 163 password
		}
		else if(!strncmp(data, "POST /login.jsp", 14) || !strncmp(data, "POST /logins.jsp", 15) || ((!strncmp(data, "POST /entry/coremail/fcg/ntesdoor2?", 35) || !strncmp(data, "POST /coremail/fcg/ntesdoor2?", 29)) && strstr(data,"funcid=loginone&")) || (!strncmp(data, "POST /entry/cgi/ntesdoor?", 25) && strstr(data,"funcid=loginone&") && strstr(data,"mail126")))
		{
			type = 0x0401;

			/* 新华网论坛的登录包 */
			if (strncmp(data, "POST /login.jsp HTTP/1.1\r\nHost: forum.home.news.cn\r\n", 52) == 0)
			{
				type = 0x0;
			}
		} 
		else 
			if (!strncmp(data, "POST /coremail/cgi/attachfapps?", 31)) 
		{
			type = 0x0412;   //163 vip 淡�???
		} 
		else
			if (!strncmp(data, "POST /a/p/upload.html?", 22)) 
		{
			type = 0x0461;
		} 
		else 
			if (!strncmp(data, "POST /a/s?func=upload:data&sid=", 31)) 
		{
			type = 0x0462;
		} 
		else 
		if (!strncmp(data, "POST /a/j/flashUpload.jsp?", 26) || !strncmp(data, "POST /js3/compose/upload.jsp?sid=", 33) || !strncmp(data, "POST /js4/compose/upload.jsp?sid=", 33) || !strncmp(data, "POST /upxmail/upload?sid=", 25))
		{
			type = 0x0463;
		} 
		else 
			if (!strncmp(data, "POST /mail/SendMessageLight.aspx?", 33))
		{ 
			type = 0x0511;  //hotmail
		} 
		else if(!strncmp(data, "POST /ppsecure/post.srf",23 ))
		{
			type = 0x0501;
		}
		else 
			if (!strncmp(data, "POST /mail/mail.fpp?cnmn=Microsoft.Msn.Hotmail.Ui.Fpp.MailBox.GetInboxData", 74) /*|| !strncmp(data, "POST /mail/mail.fpp?cnmn=Microsoft.Msn.Hotmail.Ui.Fpp.MailBox.PrefetchMessages", 78)*/)
		{
			type = 0x0521;
		} 
		else 
			//if (!strncmp(data, "POST /mail/AttachmentUploader.aspx?", 35)) 
			if(!strncmp(data, "POST /mail/SilverlightAttachmentUploader.aspx", 45))
		{
			type = 0x0561;
		} 
		else 
			//if (!strncmp(data, "POST /mail/SendPhotoHandler.aspx?", 33))
			if (!strncmp(data, "POST /richupload.ashx/", 22))
		{
			type = 0x0562;
		} 
		else 
			if (!strncmp(data, "POST /mail/mail.fpp?cnmn=Microsoft.Msn.Hotmail.Ui.Fpp.MailBox.GetSendPhotoUpload", 80)) 
		{
			type = 0x0563;
		}
		else 
			if (!strncmp(data, "POST /mail/AttachmentUploader.aspx?", 35)) 
		{
			type = 0x0565;
		}
		else
			if (!strncmp(data, "POST /mail/mail.fpp?cnmn=Microsoft.Msn.Hotmail.Ui.Fpp.MailBox.DeleteUploadedAtta", 80)) 
		{
			type = 0x0541; //hotmail delete
		}
		else if(!strncmp(data, "POST /config/login", 18))
		{
			type = 0x0601;
		} 
		else 
			//if (!strncmp(data, "POST /ws/mail/",14)&&(!strncmp(data+16,"/soap?m=SendMessage",19)||!strncmp(data+18,"/soap?m=SendMessage",19))) 
			if (!strncmp(data, "POST /ws/mail/",14)&&strstr(data,"&m=SendMessage"))
		{
			if (strstr(data, "\r\nSOAPAction: urn:yahoo:ymws#SaveMessage\r\n") != NULL) 
			{
				//printf("########yahoo save message##########\n");
				return 0;
			}
			type = 0x0611;  //yahoo
		} 
		else 
			if (!strncmp(data, "POST /ws/mail/",14)&&(!strncmp(data+16,"/soap?m=BatchExecute",20)||!strncmp(data+18,"/soap?m=BatchExecute",20))) 
		{
			if (strstr(data, "\r\nSOAPAction: urn:yahoo:ymws#SaveMessage\r\n") != NULL) 
			{
				//printf("########yahoo save message##########\n");
				return 0;
			}
			type = 0x0611;  //yahoo
		} 
		/*else 
			if (!strncmp(data+28, "/ya/upload?resulturl=http", 25)||!strncmp(data+5,"/ya/upload?resulturl=http",25)||!strncmp(data+29,"/ya/upload?resulturl=http",25)) 
		{
			type = 0x0661; //original set.
			//type=0x0609; //new setting by yu.
		} */
		else 
			if (!strncmp(data, "POST /mc/compose?&",18) && (strstr(data, "&clean&.jsrand=") || strstr(data, "&clean&hash=")))
		{
		    //if(memfind(data,"&clean&",50))
            //type=0x0615;
			char *p1;
			char id[10];
			strncpy(id,data+24,9);
			if ((p1=strstr(data+50,"&.rand="))&&!strncmp(p1+7,id,9)) 
			{
				return 0;
			}
			else 
			{
				type = 0x0615;
			}
		} 
		else 
			if ((!strncmp(data, "POST /cn.",9) || !strncmp(data, "POST /hk.",9) || !strncmp(data,"POST /us.",9)) && strstr(data,".mail.yahoo.com/ya/upload"))
		{
            		//type = 0x0671; old
			type = 0x0672; //a new one
		}
		else
			if(!strncmp(data, "POST /ws/mail/v2.0/jsonrpc?appid=YahooMailNeo&m=GetDisplayMessage",65) && strstr(data,"&wssid="))
		{
			type = 0x0635;
		}
		else
			if(!strncmp(data, "POST /ws/mail/v2.0/jsonrpc?appid=YahooMailNeo&m=VirusScanAttachments&wssid=",75))
		{
			type = 0x0638;
		}
		else 
			if (!strncmp(data, "POST /cgi/ldmmapp?", 18))
		{
			type = 0x0711; // tom 
		} 
       		else 
			if (!strncmp(data, "POST /webmail/writemail/sendmail.action HTTP/1", 46))
		{
			type = 0x0712; // tom 
		} 
        	else 
		if (!strncmp(data, "POST /webmail/readmail/show.action HTTP/1", 41)) 
		{
			type = 0x0722;//tom
		} 
		else 
			if (!strncmp(data, "POST /cgi-bin/attachfapp ", 25))
		{
			type = 0x0761;
		} 
		else
        	if (!strncmp(data, "POST /webmail/writemail/dfsuploadAttachment.do?", 47))
		{
			type = 0x0762;//tom
		}
       		else
		if (!strncmp(data, "POST /webmail/readmail/download", 31))
		{
			type = 0x0763;//tom
		} 
		else 
			if (!strncmp(data, "POST /cgi/login HTTP/1.1", 24) && (host_p != NULL) && (memfind(host_p, "tom.com", 50) != NULL || memfind(host_p, "163.net", 50) != NULL)) 
		{
			type = 0x0701;//tom
		} 
		else 
			if (!strncmp(data, "POST /webmail/login/loginService.action HTTP/1.1", 48)) 
		{
			type = 0x0703;
		} 
        	else 
			if (!strncmp(data, "POST /cgi/163/login_pro.cgi", 27)) 
		{
			type = 0x0702;
		} 
		else 
		if ((!strncmp(data, "POST /js3/s?sid=", 16) || !strncmp(data, "POST /js4/s?sid=", 16) || !strncmp(data, "POST /js5/s?sid=", 16)) && strstr(data, "&func=mbox:compose") && strstr(data, "mail.yeah.net") && strstr(data, "&action=deliver"))
		{
			type = 0x0411; //yeah send mail
		} 
		else 
			if ((!strncmp(data, "POST /login.jsp?type=", 21) || ((!strncmp(data, "POST /entry/cgi/ntesdoor?", 25)||!strncmp(data, "POST /cgi/ntesdoor?", 19))&&strstr(data,"funcid=loginone&"))) && strstr(data,"mailyeah")) 
		{
			type = 0x0801;
		} 
		else 
			if (!strncmp(data, "POST /jy3/s?sid=", 16)) 
		{
			if (strstr(data, "&func=upload:deleteTasks ") != NULL)
				type = 0x0841;
		} 
		else 
			if (!strncmp(data, "POST /jy3/compose/flashUpload.jsp?", 34) || (!strncmp(data, "POST /upxmail/upload?sid=", 25) && !strstr(data,"Mail-Upload-offset: "))) 
		{
			type = 0x0861;
		} 
		else 
			if (!strncmp(data, "POST /jy3/s?func=upload:data&sid=", 33)) 
		{
			type = 0x0862;
		} 
		else 
			if (!strncmp(data, "POST /jy3/compose/uploadDel.jsp?", 32)) 
		{
			type = 28;
		} 
		else 
			if (!strncmp(data, "POST /user/?q=compose.do", 24)&&strstr(data, "eyou.com")) 
		{
			type = 0x0911; //eyou
		} 
		else 
			if ((!strncmp(data, "POST /user/?q=login.do HTTP/1.1",31))||
						   (!strncmp(data, "POST /?q=login.do HTTP/1.1",26)) && strstr(data, "eyou.com")) 
		{
			type = 0x0901;
		} 
		else 
			if (!strncmp(data, "POST /user/?q=compose.upload.do", 31)&&strstr(data, "eyou.com")) 
		{
			return 0x0961;
		} 
		else //mail
			if ((!strncmp(data, "POST /login.html HTTP/1.1",25)) && strstr(data, "mail.com")) //login
		{
			type = 0x1001;
		} 
		else 
			if ((!strncmp(data, "POST /callgate-",15)) && strstr(data, "/mail/store?") && strstr(data, "mail.com")) 
		{
			type = 0x1011;
		} 
		else 
			if ((!strncmp(data, "POST /callgate-",15)) && strstr(data, "/attachment/upload?") && strstr(data, "mail.com")) 
		{
			type = 0x1061;
		} 
		else 
			if ((!strncmp(data, "POST /callgate-",15)) && strstr(data, "/mail/get?") && strstr(data, "mail.com")) 
		{
			type = 0x1031;
		} 
		else 
			if (!strncmp(data, "POST /attach?usr=", 17)) 
		{
			type = 0x0A01;     //263 content
		} 
		else 
			if (!strncmp(data, "POST /xmweb HTTP/", 17)) 
		{
			type = 0x0A02;  //263 Pass
		}
		else
			if ((!strncmp(data, "POST /cgi-bin/login?sid=", 24) || !strncmp(data, "POST /cgi-bin/login HTTP", 24)) && strstr(data,"mail.qq.com"))//过滤掉了手机数据
		{
			type = 0x0B02;
		}
		else 
			if ((!strncmp(data, "POST /cgi-bin/compose_send_beta?sid=", 36) || !strncmp(data, "POST /cgi-bin/compose_send?sid=", 31)) && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B11;   //qq
		} 
		else 
			if (!strncmp(data, "POST /cgi-bin/upload",20) && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			//printf("type = 0x0B61\n");
			type = 0x0B61;
		} 
		else 
			if (!strncmp(data, "POST /cgi-bin/groupmail_send?sid=", 33) && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B12;
		} 
		else 
			if (!strncmp(data, "POST /bapp/", 11) && strstr(data, "/mail HTTP/1.1") && strstr(data, "mail.sogou.com")) 
		{
			type = 0x0C11;   //old sohu and sogou
		} 
		else 
			if (!strncmp(data, "POST /bapp/", 11) && 
		(strstr(data, "/mail/att/flash?xid=") || strstr(data , "/mail/att?") )&& strstr(data, "mail.sogou.com")) 
		{
			type = 0x0C61;     //sogou and old vip sohu attach
		} 
		else 
			if (!strncmp(data, "POST /servlet/UploadAttachmentsServlet?", 39)) 
		{
			type = 0x0C62;     //old sohu attach
		}  
		else 
			if (!strncmp(data, "POST /cgi/login HTTP/1.1", 24)||
			    (!strncmp(data, "POST /login.jsp?type=", 21)&&strstr(data,"&url=http://entry.mail.126.com/")) ||
			    (!strncmp(data, "POST /cgi/ntesdoor?", 19)&&strstr(data,"&funcid=loginone")&&strstr(data,"Host: entry.mail.126.com")))
		{
			type = 0x0D01;    //126 login from hao126
		} 
		else 
			if (!strncmp(data, "POST /servlet/coremail/login?language", 37)) 
		{
			type = 0x0E01;    //188 login from hao126
		}
		else
			if (!strncmp(data, "POST /ServiceLoginAuth", 22))
		{
			type = 0x0F01;
		}
		else
			if (!strncmp(data, "POST /mail/?ui=", 15) && strstr(data, "&rid="))
		{
			if (strstr(data, "&search=inbox"))
			{
				type = 0x0F24;
			}
			else if(!strstr(data, "&search=inbox"))
			{
				type = 0x0F12;
			}
		}
		else
			//if((!strncmp(data , "POST /mail/h/", 13) || !strncmp(data , "POST /mail/u/0/h/", 17)) && !strncmp(data + 25, "/?&v=amf&", 9) || !strncmp(data + 26, "/?&v=amf&", 9) || !strncmp(data + 28, "/?&v=amf&", 9) || !strncmp(data + 29, "/?&v=amf&", 9) || !strncmp(data + 30, "/?&v=amf&", 9))
			if(!strncmp(data , "POST /mail/?ui=", 15) && strstr(data, "&attid="))
		{
			type = 0x0F13;
		}
		else
			if((!strncmp(data, "POST /mail/h/", 13) || !strncmp(data, "POST /mail/u/0/h/", 17)) && strstr(data, "&cs=c"))
		{
			type = 0x0F14;
		}
		else
			if(strstr(data, "/aol-6/en-us/common/rpc/RPC.aspx?") && strstr(data, "&transport=xmlhttp&") && strstr(data, "&a=SendMessage&") && strstr(data, "aol.com"))
		{
			type = 0x1111;
		}
		else
			if(strstr(data, "/aol-6/en-us/common/rpc/RPC.aspx?") && strstr(data, "&transport=iframe&") && strstr(data, "&a=SendMessage&") && strstr(data, "aol.com"))
		{
			type = 0x1161;
		}
		else
			if(strstr(data, "/aol-6/en-us/common/rpc/RPC.aspx?") && strstr(data, "&transport=xmlhttp&") && strstr(data, "&a=GetMessage&") && strstr(data, "aol.com"))
		{
			type = 0x1131;
		}
		
		else 
			if (strstr(data, "POST /smsmw/sms?func=sms:sendSms&sid=") )
			//if (strstr(data, "POST /sms/sms?func=sms:sendSms&sid=") )
		{
			//printf("139 send message\n");
			type = 0x1381; //139 send message
		} 
		
		
		else 
			if (!strncmp(data, "POST /c/s?func=mbox:readMessage&sid=", 36) ||!strncmp(data, "POST /RmWeb/mail?func=mbox:readMessage&comefrom=", 48))
		{
			//printf("139 read mail/ message\n");
			type = 0x1322; //139 read message
		} 
		/*else 
			if(strstr(data, "POST /s?func=mbox:listMessages&sid="))
		{
			type = 0x1323;//139 read message
		}*/
		else 
			if (!strncmp(data, "POST /c/s?func=mbox:compose&sid=", 32) || !strncmp(data, "POST /RmWeb/mail?func=mbox:compose&comefrom=", 44) )
		{
			//printf("139 send mail\n");
			type = 0x1311; //139 send mail 
		} 

		else 
			if (!strncmp(data, "POST /RmWeb/mail?func=attach:upload&sid=", 40) )
		{
			//printf("139 upload attachment\n");
			type = 0x1361; //139 upload attachment
		} 
		
//
		
//
		else if(!strncmp(data, "POST /accounts/login.do", 23) || !strncmp(data, "POST /accounts/srp.do", 21))
		{
			type = 0x1201;
		}
		else 
			if (!strncmp(data, "POST /Mail-bin/start_mailplus4/simplehtml HTTP/1.1", 50))
		{
			type = 0x1211;
		}
		else 
			if (!strncmp(data, "POST /Mail-bin/attach_mailplus.frame3.cgi?", 42))
		{
			type = 0x1261;
		} 
		else if(!strncmp(data,"POST /Login/Login.ashx HTTP/1.1",31))
		{
//printf("139 login -----------\n");
			type=0x1312;
		}
		/*--2980--*/
		else if (!strncmp(data, "POST /ashx/loginSvc.aspx?pox=",29))
		{
			type = 0x1401;//login
		}
		else if (!strncmp(data, "POST /ashx/Send.ashx HTTP/1.1\r\nHost: www.2980.com",49))
		{
			type = 0x1411;//sendmail
		}
		else if (!strncmp(data, "POST /ashx/doUploadFlash.aspx?", 30))
		{
			type = 0x1461;//upload attach
		}
		else if (!strncmp(data, "POST /index.aspx/attachments/AttachmentsFiles", 45))
		{
			type = 0x1462;// down attach
		}
		else if (!strncmp(data, "POST /ashx/doDelFile.aspx HTTP/1.1", 34))
		{
			type = 0x1413;
		}
		/*--2980 end--*/
		else if(!strncmp(data,"POST /logon/UDBForEmail/PassportLoginForEmail.aspx?",51))
		{
			type = 0x1511;
		}
		else if(!strncmp(data,"POST /webmail/sendMail.do HTTP/1.1",34) &&
			strstr(data,"189.cn"))
		{
//printf("------------234234213432--\n");
			type = 0x1512;
		}
		else if(!strncmp(data,"POST /webmail/upload.do HTTP/1.1",32) &&
			strstr(data,"189.cn"))
		{
			type = 0x1561;
		}
		//以下是阿里云邮箱的分析
// 		else if (!strncmp(data,"POST /mailview/mailWrite/do_send.htm HTTP/1.1",45) && strstr(data,"aliyun.com")) //阿里云发送邮件
// 		{
// 			//printf("\n aliyun send mail...\n");
// 			type = 0x1712;
// 		}
// 		else if (!strncmp(data,"POST /mailview/mailView/do_view.htm?inner=",42) && strstr(data,"aliyun.com")) //阿里云接收邮件
// 		{
// 			//printf("\n aliyun receive mail...\n");
// 			type = 0x1721;
// 		}
// 		else if (!strncmp(data,"POST /attachment/upload?c=",26) && strstr(data,"aliyun.com")) //阿里云上传附件
// 		{
// 			//printf("\n aliyun upload attachment...\n");
// 			type = 0x1761;
// 		}
// 		else if (!strncmp(data,"POST /attachment/download?rndtime=",34) && strstr(data,"aliyun.com")) //阿里云下载附件
// 		{
// 			//printf("\n aliyun download attachment...\n");
// 			type = 0x1762;
// 		}

		//手机webmail
		else if(IS_MOVE_WEBMAIL == 1)
		{
			if ((!strncmp(data, "POST /m/s?sid=", 14) || !strncmp(data, "POST /i/s?sid=", 14) || !strncmp(data, "POST /js5/s?sid=", 16)))
			{//type = 0x8122  163收信移动版和PC版第一个数据包无法区分，所以在analyse_163.c文件内做区分
				if (memfind(data, "&func=mbox:compose", 100) != NULL)
					type = 0x8111;
				else
				if (strstr(data, "&func=mbox:listMessage") != NULL)
					return 0;
			}
			else
				if(!strncmp(data, "POST /js5/compose/upload.jsp?sid=", 33))
			{
				type = 0x8163;
			}
			else
				if ((!strncmp(data, "POST /cgi-bin/login?sid=", 24) || !strncmp(data, "POST /cgi-bin/login HTTP", 24)) && strstr(data,"mail.qq.com"))
			{
				type = 0x8202;
			}
			else 
				if ((!strncmp(data, "POST /cgi-bin/cgi_redirect HTTP", 31) || (!strncmp(data, "POST /cgi-bin/compose_send?sid=", 31) && !strstr(data,"boundary=----"))) && strstr(data,"\r\nHost: w"))
			{
				type = 0x8211;
			} 
			else 
				if ((!strncmp(data, "POST /cgi-bin/compose_send?sid=", 31) && strstr(data,"boundary=----") || !strncmp(data,"POST /cgi-bin/upload?sid=",25)) && strstr(data,"\r\nHost: w"))
			{
				type = 0x8261;
			}
		}
	}
	else if (!strncmp(data, "GET ", 4)) 
	{
		host_p = strstr(data, "\r\nHost:");

		if (!strncmp(data, "GET /servlet/UploadAttachmentsServlet?index", 43)) 
		{
			type = 0x0C41;   //old sohu delete
		} 
		else 
			if (!strncmp(data, "GET /bapp", 9) && !strncmp(data + 12, "/mail/att/resumeUpload?xid=", 27) || !strncmp(data + 11, "/mail/att/resumeUpload?xid=", 27))
		{
			type = 0x0342;   //new sohu vip delete
		} 
		else 
			if (!strncmp(data, "GET /sso/login.jsp?userid=", 26)) 
		{
			type = 0x0301;     //sohu password
		} 
		else
			if(!strncmp(data,"GET /bapp",9) && (!strncmp(data + 12, "/download/",10) || !strncmp(data + 11, "/download/",10) || !strncmp(data + 13, "/download/",10) || !strncmp(data + 14, "/download/",10)) && strstr(data,".sohu.com"))
		{
			type = 0x0333; //sohu attach download
		}
		else 
			if (!strncmp(data, "GET /classic/getMailbody.php?",29))
		{
			type = 0x0132;
		}
		else 
			if (!strncmp(data, "GET /classic/rdMail.php?",24))
		{
			//yanglei
			type = 0x0141;
			if(!strncmp(data,"GET /classic/rdMail.php?cb=",27))
			{
				//type = 0x0131;//cn revice
				type = 0x0123;
			}
		}
		else
			if (!strncmp(data,"GET /classic/base_download_att.php",34) && strstr(data+100, "Accept: */*") == NULL)
		{
			type = 0x0134;
		}
		else 
			if (!strncmp(data, "GET /classic/readmail.php",25))
		{
			type = 0x0131;
		}
		else 
			if (!strncmp(data, "GET /mc/showMessage?sMid=",25))
		{
			type = 0x0631; //yahoo.com.cn yahoo.cn
		}
		/*else 
			if (!strncmp(data, "GET /ws/mail/v2.0/formrpc?m=GetDisplayMessage",45))
		{
			type = 0x0635;       //yahoo.com
		}*/
		else
			if((!strncmp(data,"GET /cn.",8) || !strncmp(data,"GET /hk.",8)) && strstr(data,".mail.yahoo.com/ya/securedownload?"))
		{
			type = 0x0636;
		}
		else
			if(!strncmp(data,"GET /us.",8) && !strncmp(data+13,".mail.yahoo.com/ya/securedownload?",34))
		{
			type = 0x0637;
		}
		else 
			if (!strncmp(data, "GET /freeinterface/maillogin.jsp?",20) || !strncmp(data, "GET /webmail/loginsigin.do?",27))
		{
			type = 0x0201;  //21CN_PASS
		} 
		else 
			if (!strncmp(data, "GET /webmail/readMail.do?",25) && strstr(data, "mail.21cn.com"))
		{
			type = 0x0231;
		} /*
		else
			if (!strncmp(data, "GET /webmail/getAttachment.do?messageid=", 40))
		{
			type = 0x0264;
		} */
		else
			if (!strncmp(data,"GET /webmail/getAttachment.do?",30) && strstr(data, "mail.21cn.com"))
		{
			type = 0x0232;
		}
		else 
			if (!strncmp(data, "GET /a/j/dm3/readhtml.jsp?",26) && memfind(host_p, "188.com", 50) != NULL)
		{
			type = 0x0E41;        //188
		}
		else
		if ((!strncmp(data, "GET /js3/read/readhtml.jsp?ssid=", 32) || !strncmp(data, "GET /js4/read/readhtml.jsp?ssid=", 32) || !strncmp(data, "GET /a/j/dm3/readhtml.jsp?ssid=", 31)) && !strstr(data, "mail.yeah.net"))
		{
			type = 0x0423; //126,163 recv mail content
		} 
		else
		if (!strncmp(data, "GET /js5/read/readhtml.jsp?ssid=", 32) && !strstr(data, "mail.yeah.net"))
		{
			type = 0x0426; //126,163 V5.0 recv mail content
		} 
		else if(!strncmp(data, "GET /js6/read/readhtml.jsp?mid=", 31) && !strstr(data, "mail.yeah.net"))
		{
			type = 0x0426;
		}
		else 
		if (!strncmp(data, "GET /jyen/read/read.jsp?", 24))
		{
			type = 0x0424;   //0x0424 and 0x0425 are for 163 vip english editon
		} 
		else 
		if (!strncmp(data, "GET /jyen/read/viewMailHTML.jsp?ssid=", 37))
		{
			type = 0x0425;   //0x0424 and 0x0425 are for 163 vip english editon
		}
		else 
		if (!strncmp(data, "GET /js3/down/", 14) && strstr(data, "&mode=download&l=read&action=download_attach"))
		{ // 163 down attach
			//type = 0x0426;
			type = 0x0464;
		}
		else
		if ((!strncmp(data, "GET /js4/read/readdata.jsp?sid=", 31) || !strncmp(data, "GET /js3/read/readdata.jsp?sid=", 31) || !strncmp(data, "GET /js5/read/readdata.jsp?sid=", 31)\
			|| !strncmp(data, "GET /js6/read/readdata.jsp?sid=", 31)) && strstr(data,"&action=download_attach") && (strstr(data, "mail.163.com") || strstr(data, "mail.126.com")))
		{ // 163 down attach
			type = 0x0464;//printf("\n                  jiiiiiiiiiiiiiiiiii\n");
			//type = 0x0426;
		}
		else 
		if (!strncmp(data, "GET /coremail/fcg/ldmsapp?funcid=readlett", 41)) 
		{
			type = 0x0721;
		} 
        	else 
		if (!strncmp(data, "GET /webmail/readmail/context.action?", 37)) 
		{
			type = 0x0723;//tom
		}
		else
		if (!strncmp(data, "GET /coremail/fcg/ldmsapp/", 26) && strstr(data, "mail.tom.com") && strstr(data, "&download="))
		{
			type = 0x0764;
		}
		else if(!strncmp(data,"GET /webmail/readmail/context.action?",37) && strstr(data,"Host: web.mail.tom.com"))
		{
			type=0x0723;//for tom v2.0 recv mail body
		}
		else
			if (!strncmp(data, "GET /att/GetAttachment.aspx?", 28)/* && strstr(data, "hotmail.com")*/) // hotmail down attach
		{
			type = 0x0564;
		} 
		else 
		//if (!strncmp(data, "GET /jy3/read/read.jsp?", 23))
			if (!strncmp(data, "GET /js4/read/readhtml.jsp?ssid=", 32) && strstr(data, "mail.yeah.net"))
		{
			type = 0x0822;
		} 
		else 
			if (!strncmp(data, "GET /js5/read/readhtml.jsp?ssid=", 32) && strstr(data, "mail.yeah.net"))
		{
			type = 0x0823;
		} 
		else //(data, "GET /js4/read/readdata.jsp?sid=", 31)
			if ((!strncmp(data, "GET /js4/read/readdata.jsp?sid=", 31) || !strncmp(data, "GET /js5/read/readdata.jsp?sid=", 31)) && strstr(data, "&mode=download&l=read&action=download_attach") && strstr(data, "mail.yeah.net")) //yeah down attach
		{
			type = 0x0824;
			//type = 0x0863;
		} 
		else 
			if ((!strncmp(data, "GET /cgi-bin/readmail?folderid=", 31) || !strncmp(data, "GET /cgi-bin/readmail?sid=", 26)) && !strstr(data,"&showreplyhead=") && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B21;
		}
		else
		if ((!strncmp(data,"GET /cgi-bin/download?", 22) || !strncmp(data, "GET /cgi-bin/groupattachment?", 29)) && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B29;
		} 
// 
		else
		if (( host_p && strstr(host_p , ".mail.store.qq.com") && !strstr(host_p ,"Range: bytes")) && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B29;
		} 
// 
		else
		if (strstr(data, "Referer: http://m127.mail.qq.com/cgi-bin/readmail?folderid=1&t=readmail&mailid=") && !strstr(data,"\r\nHost: w"))//过滤掉了手机数据
		{
			type = 0x0B29;
		}
		else 
		if (!strncmp(data, "GET /bapp/", 10) && strstr(data, "/mail/") && strstr(data, "HTTP/1.1") && !strstr(data, "/check?") && strstr(data, "mail.sogou.com") && !strstr(data, "att/progress?X-Progress-ID="))
		{
			type = 0x0C21; //sogou recv mail old
		}
		else 
			if (!strncmp(data, "GET /bapp/", 10) && strstr(data, "/conversation/") && strstr(data, "HTTP/1.1") && !strstr(data, "/check?") && strstr(data, "mail.sogou.com") && !strstr(data, "att/progress?X-Progress-ID=") && strstr(data, "?folder="))
		{
			//printf("old sogou recv mail\n");
			type = 0x0C21; //sogou recv mail new
		}
		else
			if (!strncmp(data, "GET /bapp/", 10)&&strstr(data, "/download/")&&strstr(data, "mail.sogou.com")) 
		{
			type = 0x0C22;
			//type = 0x0C63; // sogou down attach
		} 
		else 
			if (!strncmp(data, "GET /xmweb?func=mail",20)) 
		{
			type = 0x0A31;
		} 
		else 
			if (!strncmp(data, "GET /xmweb?sid=",15))
		{
			type = 0x0A32;       //263 receive up
		} 
		else 
			if (!strncmp(data, "GET /user/?q=compose", 20)&&strstr(data, "action=readmail")&&strstr(data, "eyou.com"))
		{
			type = 0x0931;       //eyou
		} 
		else
			if(!strncmp(data, "GET /public/?q=compose.output", 29)&&strstr(data, "action=mail.attach&")&&strstr(data, "eyou.com"))
		{
			type = 0x0932;
		}
		else//mail
			if(!strncmp(data, "GET /callgate-", 14) && strstr(data, "/mail/getBody?") && strstr(data, "mail.com"))
		{
			type = 0x1032;
		}
		else
			if(!strncmp(data, "GET /callgate-", 14) && strstr(data, "/attachment/download") && strstr(data, "mail.com"))
		{
			type = 0x1033;
		}
		else
			if(!strncmp(data,"GET /bapp/",10) && (!strncmp(data+13,"conversation/",13)||!strncmp(data+12,"conversation/",13)) && strstr(data,"mail.sohu.com"))
		{
			type = 0x0331;
		}
		else 
			if (!strncmp(data, "GET /bapp/", 10) && (!strncmp(data + 12, "/mail", 5) || !strncmp(data + 11, "/mail", 5)||!strncmp(data+13,"/mail",5)) && strstr(data, "mail.sohu.com") && !strstr(data, "/dowmload/"))
		{
			//printf("%s\n", data);
			type = 0x0339;
		}
		else 
			if (!strncmp(data, "GET /bapp/", 10) && strstr(data, "/conversation/") && strstr(data, "?folder=") && strstr(data, "mail.sohu.com") && !strstr(data, "/dowmload/"))
		{
			//printf("%s\n", data);
			type = 0x0339;
		}
		else 
			if (!strncmp(data,"GET /bapp/",10) && (!strncmp(data+13,"conversation/",13)||!strncmp(data+12,"conversation/",13)) && strstr(data,"vip.sohu.com"))
		{
			type = 0x0330;
		}
		else
			if ((!strncmp(data, "GET /mail/h/", 12) || !strncmp(data, "GET /mail/u/0/h/", 16)) && (!strncmp(data + 24, "/?&v=c&th=", 9) || !strncmp(data + 25, "/?&v=c&th=", 9) || !strncmp(data + 27, "/?&v=c&th=", 9) || !strncmp(data + 28, "/?&v=c&th=", 9) || !strncmp(data + 29, "/?&v=c&th=", 9) || !strncmp(data + 27, "/?&v=c&st=50&th=", 15) || !strncmp(data + 28, "/?&v=c&st=50&th=", 15) || !strncmp(data + 29, "/?&v=c&st=50&th=", 15) || !strncmp(data + 27, "/?&v=c&st=100&th=", 16) || !strncmp(data + 28, "/?&v=c&st=100&th=", 16) || !strncmp(data + 29, "/?&v=c&st=100&th=", 16)))
		{

			type = 0x0F22;
		}
		/*else
			if (!strncmp(data, "GET /mail/h/", 12) && (strstr(data, "/?view=att&th=")))
		{
			type = 0x0F31;
		}*/
		else
			if (!strncmp(data, "GET /mail/?ui=", 14) && (strstr(data, "&view=att&th=")))
		{
			type = 0x0F31;
		}
		else
			if (!strncmp(data, "GET /attachment?view=att&th=", 28) || !strncmp(data, "GET /attachment/?view=att&th=", 29) || !strncmp(data, "GET /attachment/u/0/?view=att&th=", 33))
		{
			type = 0x0F31;
		}
		else
			if (strstr(data, "/aol-6/en-us/mail/get-attachment.aspx?") && strstr(data, "&folder=Inbox&") && strstr(data, "aol.com"))
		{
			type = 0x1132;
		}
		else
			if(!strncmp(data, "GET /hanmailex/ViewMail.daum?", 29))
		{
			type = 0x1221;
		}
		else
			if(!strncmp(data, "GET /Mail-bin/view_submsg3.cgi?", 31))
		{
			type = 0x1231;
		}

		else 
			if (strstr(data, "GET /coremail/s?func=mbox:getMessageData&sid") ||strstr(data, "GET /RmWeb/view.do?func=attach:download&mid="))
		{ 
			//printf("139 download attachment\n");
			type = 0x1364;// 139 download attachment
		}
		/*--2980--*/
		else if(!strncmp(data, "GET /readfolder.aspx?type=Inbox&mailbox=undefined&mailid=", 57))
		{
		type = 0x1421;//2980 recvmail
		}
		/*--2980--*/
		else if(!strncmp(data,"GET /webmail/readMail.do?messageid=",35) &&
			strstr(data,"189.cn"))
		{
			type = 0x1521;
		}
		else if(!strncmp(data,"GET /webmail/getAttachment.do?messageid=",40) &&
			strstr(data,"189.cn"))
		{
			type = 0x1562;
		}
// 		else if ((!strncmp(data,"GET /uniquelogin.htm?return_url=",32)||!strncmp(data,"GET / HTTP/1.1",14))&&strstr(data,"aliyun.com")) //阿里云登陆
// 		{
// 			type = 0x1701;
// 		}

		//手机webmail
		else if(IS_MOVE_WEBMAIL == 1)
		{
			if (((!strncmp(data, "GET /m/read/readdata.jsp?sid=", 29) || !strncmp(data, "GET /i/read/readdata.jsp?sid=", 29) || !strncmp(data, "GET /js5/read/readdata.jsp?sid=", 31)) && strstr(data,"&mode=inline") && strstr(data,"&action=open_attach")) ||
			    (!strncmp(data,"GET /download.do?sid=",21) && strstr(data,"&mid=") && strstr(data,"&filename=")))
			{
				type = 0x8124;
				//type = 0x8164;
			}
			else 
				if (!strncmp(data, "GET /cgi-bin/readmail", 21) && strstr(data,"&showreplyhead=") && strstr(data,"\r\nHost: w")) 
			{
				type = 0x8221;
			}
			else
			if ((!strncmp(data,"GET /cgi-bin/download?", 22) || !strncmp(data, "GET /cgi-bin/groupattachment?", 29)) && !strstr(data,"&action=view HTTP") && strstr(data,"\r\nHost: w"))
			{
				type = 0x8229;
			}
		}
	}
	
	return type;
}
#endif

