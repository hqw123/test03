#include  "hashfn.c"
#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#ifdef __cplusplus
extern "C" {
#endif
#include  "list.h"
#ifdef __cplusplus
}
#endif

static char *mails_host[] = {
	// 189 webmail, send, upload attachment
	"webmail30.189.cn",
	"webmail29.189.cn",
	"webmail28.189.cn",
	"webmail27.189.cn",
	"webmail26.189.cn",
	"webmail25.189.cn",
	"webmail24.189.cn",
	"webmail23.189.cn",
	"webmail22.189.cn",
	"webmail21.189.cn",
	"webmail20.189.cn",
	"webmail19.189.cn",
	"webmail18.189.cn",
	"webmail17.189.cn",
	"webmail16.189.cn",
	"webmail15.189.cn",
	"webmail14.189.cn",
	"webmail13.189.cn",
	"webmail12.189.cn",
	"webmail11.189.cn",
	"webmail10.189.cn",
	"webmail9.189.cn",
	"webmail8.189.cn",
	"webmail7.189.cn",
	"webmail6.189.cn",
	"webmail5.189.cn",
	"webmail4.189.cn",
	"webmail3.189.cn",
	"webmail2.189.cn",
	"webmail1.189.cn",
	// sina webmail, send, upload attachment
	"m0.mail.sina.com.cn",
	"m1.mail.sina.com.cn",
	"m2.mail.sina.com.cn",
	"m3.mail.sina.com.cn",
	// 163 webmail, send
	"mail.163.com",
	// 163 upload attachment server
	"c10bj.mail.163.com",
	"c9bj.mail.163.com",
	"c8bj.mail.163.com",
	"c7bj.mail.163.com",
	"c6bj.mail.163.com",
	"c5bj.mail.163.com",
	"c4bj.mail.163.com",
	"c3bj.mail.163.com",
	"c2bj.mail.163.com",
	"c1bj.mail.163.com",
	// 139 webmail, send, upload attachment
	"appmail.mail.10086.cn",
};

#define     MAIL_H_SIZE		(sizeof(mails_host)/sizeof(mails_host[0]))
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
}mailbox_gather_t;

void init_mbox_hashtable2()
{
	int i;
	mbox_hashtable = (struct hlist_head *)calloc(mbox_ht_size, sizeof(struct hlist_head));
	for (i = 0; i < mbox_ht_size; i++)	
		INIT_HLIST_HEAD(&mbox_hashtable[i]);

	for (i = 0; i < MAIL_H_SIZE; i++)
	{
		size_t bucket_i = 0;
		mailbox_gather_t *m = (mailbox_gather_t *)malloc(sizeof(mailbox_gather_t));
		m->key = mails_host[i];
		m->key_value = i;
		memset(&m->mb_hash, 0, sizeof(m->mb_hash));
		m->hashv = BKDRHash(m->key);
		bucket_i = m->hashv % mbox_ht_size;
		m->bucket_index = bucket_i;
		hlist_add_head(&m->mb_hash, &mbox_hashtable[bucket_i]);
	}
}

mailbox_gather_t* mbox_lookup_value2(const char *key)
{
	size_t hash = BKDRHash(key);
	struct hlist_head *h = &mbox_hashtable[hash % mbox_ht_size];
	mailbox_gather_t *retval;
	struct hlist_node *node = h->first;
	mailbox_gather_t *mb;
	int i = 0;

	hlist_for_each_entry(mb, node, h, mb_hash)
	{
		if (mb->hashv == hash && !strcmp(mb->key, key))
		{
			return mb;
			printf("value found at %d\n", i);
		}
		i ++;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int i = 0;
	init_mbox_hashtable2();

	for (; i < MAIL_H_SIZE; i++)
	{
		mailbox_gather_t *mb = mbox_lookup_value2(mails_host[i]);
		if (!mb) {  printf("fuck\n"); exit(1); }
		printf("mbox: hashv=%lu, host:%s, type:%d, bucket_index:%d\n",
				mb->hashv, mb->key, mb->key_value, mb->bucket_index);
	}
	return 0;
}
