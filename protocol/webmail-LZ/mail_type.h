#include "common.h"

#define IS_MOVE_WEBMAIL 1

Mail_info *find_mail_node(unsigned int source_ip, unsigned int dest_ip, unsigned short source_port, unsigned short dest_port, int *is_sent);


Attach_info *find_attach_node(unsigned int source_ip, unsigned int dest_ip, unsigned short source_port, unsigned short dest_port, int *is_sent, unsigned short packet_type);


Mail_info *insert_mail_node(char *srcMAC, struct iphdr *pip, struct tcphdr *ptcp, unsigned short type);

Attach_info *insert_attach_node(struct iphdr *pip, struct tcphdr *ptcp, unsigned short type, unsigned short packet_type);

unsigned short mail_type(char *data);
//added by jacky Wed Mar  1 20:46:56 PST 2017
void init_mbox_hashtable();
int mail_type_prefetched(char *data);
