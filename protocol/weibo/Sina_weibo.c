#include "weibocommon.h"
//#include "XmlStorer.h" 

char *clear_nt(char *source)
{
    if (source == NULL)
        return NULL;
    
	char *str = strdup(source);
	int result;
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "\\\\n", "");
    if (result != -1)
		result = wb_cns_str_ereplace(&str, "\\\\t", "");
	return str;
}

int analyse_Sinawb_Login( WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
 
    node->is_complished = 1;
    node->wbType = Login;

    char *p1 = NULL;
    if (NULL == node->data)
        return -1;
    
    p1 = strstr(node->data, "\r\n\r\n");
    if (NULL == p1)
        return -1;
    
    p1 = wb_arrcpy(node->username, p1, "&su=", "&", 4, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    
    char *tmp = base64_decode(node->username, strlen(node->username));
    if (tmp)
    {
        int len = strlen(tmp);
        memcpy(node->username, tmp, len);
        node->username[len] = 0;
        wb_url_decode(node->username, node->username);
        free(tmp);
    }
    
    return 1;
}

int analyse_Sinawb_Upfile(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    
    if (NULL == node->data || NULL==node->body)
        return -1;
    
	node->wbType = File;
    char *p1 = NULL;
    p1 = wb_arrcpy(node->Id, node->header, "&pid=", "&", 5, MAX_ID_LEN);
    if (NULL == p1)
    {
        p1 = wb_arrcpy(node->Id, node->body, "<pid>", "</pid>", 5, MAX_ID_LEN);
        if (NULL == p1)
            return -1;
    }
    
    return analyse_file_1(node->data, node->dataLen, node->save_path, node->fileName, "sina");
}

int analyse_Sinawb_Sixinfile(WbNode *node, PacketInfo *packetInfo,int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    
    if (NULL == node->data || NULL == node->body)
        return -1;
    
    node->wbType = File;
    char *p1 = NULL;
    if (NULL == wb_arrcpy(node->to, node->data, "&tuid=", " ", 6, MAX_TO_LEN))
        return -1;
    
    wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    int fromLen = strlen(node->from);
    memcpy(node->Id, node->from, fromLen);
    node->Id[fromLen] = 0;
    
    return analyse_file_1(node->data, node->dataLen, node->save_path, node->fileName, "sina");

}

int analyse_Sinawb_Guangbo(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    if (NULL == node->data)
        return -1;
    
    unsigned short type = node->type & 0x00FF;
    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    char *pflag = strstr(node->data, "\r\n\r\n");
    if (NULL == pflag)
        return -1;
    
    pflag += 4;   
    node->wbType = Guangbo;
    
    p1 = wb_ptrcpy(&node->content, pflag, "text=", "&", 5);
    if (NULL == p1)
        return -1;
    
    wb_url_decode(node->content, node->content);
    
    char *p2 = wb_arrcpy(node->to, p1, "&screen_name=", "&", 13, MAX_TO_LEN);
    if (p2 ||type == 0x15)
    {
        node->wbType = Sixin;
        if (NULL == p2)
            wb_arrcpy(node->to, p1, "&uid=", "&", 5, MAX_TO_LEN);
        
        int fromLen = strlen(node->from);
        memcpy(node->Id, node->from, fromLen);
        node->Id[fromLen] = 0;
        attc_node(node, 0);
        
        return 1;
    }
   
    p1 = wb_arrcpy(node->Id, p1, "&pic_id=", "&", 8, MAX_ID_LEN);
    if (NULL != p1)
    {
        attc_node(node, 0);
    }
    
    return 1;
}

int analyse_Sinawb_Zhuanfa(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (!node->is_complished)
        return 0;
    
    if (NULL == node->data)
        return -1;

    node->wbType = Zhuanfa;
    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    char *pflag = strstr(node->data, "\r\n\r\n");
    if (NULL == pflag)
        return -1;
    
    pflag += 4;
    p1 = wb_ptrcpy(&node->reason, pflag, "&reason=", "&", 8);
    if (NULL == p1)
        return -1;
    
    wb_url_decode(node->reason, node->reason);
    p1 = wb_arrcpy(node->Id, p1, "&pic_id=", "&", 8, MAX_ID_LEN);
    if (NULL != p1)
    {
        attc_node(node, 0);
    }

    char *tmp = clear_nt(node->body);
    pflag = strstr(tmp, "<div class=\\\"WB_info\\\">");
    if (NULL == pflag)
        return -1;
    
    p1 += 23;
    p1 = strstr(pflag, "<a node-type='feed_list_originNick'");
    if (NULL == p1)
        return -1;
    
    p1 += 35;
    char *p2 = wb_arrcpy(node->to, p1, ">@", "<", 2, MAX_TO_LEN);
    if (NULL == p2)
        return -1;
    
    char *tmp1 = wb_deal_point(node->to, strlen(node->to));
    memcpy(node->to, tmp1, strlen(tmp1));
    node->to[strlen(tmp1)] = 0;
    
    wb_clear_u(node->to, '\\');
    wb_ptrcpy(&node->content, p1, "<div class=\\\"WB_text\\\"", "<\\/div>", 0);
    tmp1 = wb_clear_html_tag(node->content);
    wb_clear_u(tmp1, '\\');
    
    free(node->content);
    node->content = tmp1;
    free(tmp);
    
    return 1;
}

int analyse_Sinawb_Pinglun(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
        
    if (NULL == node->data)
        return -1;

    node->wbType = Pinglun;
    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    
    char *pflag = strstr(node->data, "\r\n\r\n");
    if (NULL == pflag)
        return -1;
    
    pflag += 4;
    wb_arrcpy(node->to, pflag, "&uid=", "&", 5, MAX_TO_LEN);
    p1 = wb_ptrcpy(&node->reason, pflag, "&content=", "&", 9);
    if (NULL == p1)
        return -1;
    
    wb_clear_u(node->reason, '\\');
    wb_url_decode(node->reason, node->reason);
    
    p1 = wb_arrcpy(node->Id, p1, "&pic_id=", "&", 8, MAX_ID_LEN);
    if (0 != node->Id[0])
    {
        attc_node(node, 0);
    }
    
    return 1;
}

int analyse_Sinawb_Sixin(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    if (NULL == node->data)
        return -1;

    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    
    node->wbType = Sixin;
    char *tmp = NULL;
    if (NULL == wb_ptrcpy(&tmp, node->data, "&message=", "&", 9))
        return -1;
    
    wb_url_decode(tmp, tmp);
    wb_arrcpy(node->to, tmp, "\"uid\":\"", "\"", 7, MAX_TO_LEN);
    
    p1 = wb_ptrcpy(&node->content, tmp, "\"msg\":\"", "\"", 7);
    wb_clear_u(node->content, '\\');
    free(tmp);
    if (p1)
    {
        int fromLen = strlen(node->from);
        memcpy(node->Id, node->from, fromLen);
        node->Id[fromLen] = 0;
        attc_node(node, 0);
        return 1;
    }
    else
        return -1;
}

///////////////////////////////////////////////////////////////
	//analyse_Sinawb_Sixin_new  lihan	 2017.2.15
///////////////////////////////////////////////////////////////

int analyse_Sinawb_Sixin_new(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    if (NULL == node->data)
        return -1;

    node->wbType = Sixin;
    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;
    
    char *tmp = strstr(node->data, "\r\n\r\n");
    if (NULL == tmp)
    {
        return -1; 
    }
    
	wb_arrcpy(node->to, tmp, "&uid=", "&", 5, MAX_TO_LEN);
    wb_url_decode(tmp, tmp);
    
    p1 = wb_ptrcpy(&node->content, tmp, "&text=", "&", 8);
    wb_clear_u(node->content, '\\');
    if (p1)
    {
        int fromLen = strlen(node->from);
        memcpy(node->Id, node->from, fromLen);
        node->Id[fromLen] = 0;
        attc_node(node, 0);
        return 1;
    }
    else
        return -1;
}

int analyse_Sinawb_Logout(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    if (NULL == node->data)
        return -1;

    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "un=", ";", 3, MAX_ID_LEN);
    if (NULL == p1)
        return -1;

    memcpy(node->username, node->from, strlen(node->from));
    node->username[strlen(node->from)] = 0;
    node->wbType = Logout;
    
    return 1;
}

int analyse_SinaWb(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
    unsigned short type = node->type & 0x00FF;
    int result = 0;
    switch (type)
    {
        case 0x01:
            result = analyse_Sinawb_Login(node, packetinfo, is_to_s);
            break;
        case 0x06:
            result = analyse_Sinawb_Logout(node, packetinfo, is_to_s);
            break;
       case 0x11:
       case 0x15:
	   case 0x21:
           result = analyse_Sinawb_Guangbo(node, packetinfo, is_to_s);
           break;
        case 0x12:
           result = analyse_Sinawb_Zhuanfa(node, packetinfo, is_to_s);
            break;
        case 0x13:
		case 0x23:
          result = analyse_Sinawb_Pinglun(node, packetinfo, is_to_s);
          break;
        case 0x14:
           result = analyse_Sinawb_Sixin(node, packetinfo, is_to_s);
            break;
     	case 0x22:
            result = analyse_Sinawb_Sixin_new(node, packetinfo, is_to_s);
            break;
        case 0x51:
            result = analyse_Sinawb_Upfile(node, packetinfo, is_to_s);
            break;
        case 0x52:
            result = analyse_Sinawb_Sixinfile(node, packetinfo, is_to_s);
            break;
        default:
            break;
    }
    return result;
}


