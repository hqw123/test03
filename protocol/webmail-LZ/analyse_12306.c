#include "common.h"

int analyse_12306_login2(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, int is_to_s)
{
    if (is_to_s)
    {
        char *p1 = NULL,*p2 = NULL;
        char tmp_pass[MAX_UN_LEN + 1] = {0};
        Mail_info *mail_info = (Mail_info *)node; 
        
        p1 = strstr(data, "&id=");
        if (!p1)
            return -1;
        
        if(p1)
        {
            p1 += strlen("&id=");
            p2 = strchr(p1, '&');
            strncpy(mail_info->username, p1, p2 - p1);
            strcat(mail_info->username, "@12306.cn");
        }

        p1 = strstr(p2, "&pwd=");
        if(!p1)
            return -1;
            
        if(p1)
        {
            p1 += strlen("&pwd=");
            p2 = strchr(p1, '&');
            memcpy(tmp_pass, p1, p2 - p1);
            htmldecode_full(tmp_pass, mail_info->passwd);
        }

        store_account_db(mail_info);
        return -1;
    }

    return 0;
}

int analyse_12306_login(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, int is_to_s)
{
    if(is_to_s)
    {
        char *p1 = NULL,*p2 = NULL;
        char tmp_pass[MAX_UN_LEN + 1] = {0};
        Mail_info *mail_info = (Mail_info *)node; 
        
        p1 = strstr(data, "user_name=");
        if(!p1)
            return -1;
        
        if(p1)
        {
            p1 += strlen("user_name=");
            p2 = strchr(p1, '&');
            strncpy(mail_info->username, p1, p2 - p1);
			strcat(mail_info->username, "@12306.cn");
        }

        p1 = strstr(p2, "password=");
        if(!p1)
            return -1;
			
        if(p1)
        {
            p1 += strlen("password=");
            p2 = strchr(p1, '&');
            memcpy(tmp_pass, p1, p2 - p1);
            htmldecode_full(tmp_pass, mail_info->passwd);
        }

        store_account_db(mail_info);
        return -1;
    }

    return 0;
}

int analyse_12306(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a)
{
    unsigned short type = 0;;
    int result = 0;
    if (!m_or_a) 
	{
		Mail_info *mail_info = (Mail_info *)node;
		type = mail_info->mail_type & 0x00FF;
		switch (type) 
		{
            case 0x01:
                result = analyse_12306_login(packetInfo, node, data, data_len, is_to_s);
                break;

            case 0x02:
                result = analyse_12306_login2(packetInfo, node, data, data_len, is_to_s);
                break;

            default:
                break;
        }

        if (result == -1)
		{
			delete_mail_info(mail_info);
		}
    }

    return 0;
}

