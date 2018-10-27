#ifndef LISTEN_SSL_H
#define LISTEN_SSL_H
#include<sys/socket.h>

#define LISTEN_PORT 0x01BB
#define IP_TABLE_SIZE 2

unsigned int ip[IP_TABLE_SIZE];
int startsslServer(unsigned short port,int max);
#endif

