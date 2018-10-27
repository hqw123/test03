#ifndef  _CONTROL_H
#define  _CONTROL_H
#define MAX_PORT 10
extern  int  g_status;
extern  int  g_attach_size;
extern  int  g_deeply_parse;
extern  unsigned short  g_port[MAX_PORT];

void  get_webmail_control(int status,int attach_size,int deeply_parse);
int get_webmail_port(int port);
void clear_webmail_port();

#endif
