#include "control.h"
#include <string.h>

int g_status=1;
int g_attach_size;
int g_deeply_parse;

unsigned short g_port[MAX_PORT];
static int count=0;

void  get_webmail_control(int status,int attach_size,int deeply_parse)
{
	g_status=status;
	g_attach_size=attach_size;
	g_deeply_parse=deeply_parse;
}

int get_webmail_port(int port)
{
   if(count>MAX_PORT) return 0;
   g_port[count++]=(unsigned short)port;
   return 1;
}

void clear_webmail_port()
{
	memset(g_port,'\0',sizeof(g_port));
	count=0;
}


