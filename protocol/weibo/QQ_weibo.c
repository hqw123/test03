
#include "weibocommon.h"
//#include "XmlStorer.h"
#include  "cJSON.h"

char *clear_id(char *source)
{
    if (source == NULL)
		return NULL;
    
	char *str = strdup(source);
    
	wb_cns_str_ereplace(&str, "\\\\/", "/");
    
	return str;
}
int analyse_QQwb_Login( WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
 
    char *p1 = NULL;
    
    node->is_complished = 1;
    node->wbType = Login;
    
    if (NULL == node->data)
        return -1;
    
    unsigned short type = node->type&0x00FF;
    if (0x02 == type)
    {
        p1 = wb_arrcpy(node->username, node->data, "&u=", "&", 3, MAX_UN_LEN);
        if (NULL == p1)
            return -1;
        p1 = wb_arrcpy(node->passwd, p1, "&p=", "&", 3, MAX_PW_LEN);
        return 1;
    }
    else
    {
        p1 = wb_arrcpy(node->username, node->data, "clientuin=", "&", 10, MAX_UN_LEN);
        if (NULL == p1)
            return -1;
        
        p1 = wb_arrcpy(node->passwd, p1, "&clientkey=", "&", 11, MAX_PW_LEN);
            return 1;
    }
    
}

int analyse_QQwb_Logout( WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    char *p1 = NULL;
    node->wbType = Logout;
    
    if (NULL == node->data)
        return -1;
    
    p1 = wb_arrcpy(node->username, node->data, "o_cookie=", ";", 9, MAX_UN_LEN);
    if (NULL == p1)
        return -1;
    
    return 1;
}

int analyse_QQwb_Sixinfile(WbNode *node, PacketInfo *packetInfo,int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    
    char *p1 = NULL;
    if (NULL == node->data || NULL == node->body)
        return -1;
    
    node->wbType = File;
    if (NULL != strstr(node->header, "Content-Encoding: gzip\r\n") && 0!=decompress_2(&node->body, (int *)&node->bodyLen))
        return -1;
    
    if (NULL == wb_arrcpy_2(node->Id, node->body, "fid : \"", "\"", 7, MAX_ID_LEN))
        return -1;

    return analyse_file_1(node->data, node->dataLen, node->save_path, node->fileName, "QQ");
}

int analyse_QQwb_Upfile(WbNode *node, PacketInfo *packetInfo,int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    
    if (NULL == node->data || NULL == node->body)
        return -1;
    
    node->wbType = File;

    if (NULL!= strstr(node->header, "Content-Encoding: gzip\r\n") && 0!=decompress_2(&node->body, (int *)&node->bodyLen))
        return -1;
    
    if (NULL == wb_arrcpy(node->Id, node->body, "\"image\":\"", "\"", 9, MAX_ID_LEN))
        return -1;
    
    char *tmp = clear_id(node->Id);
    int tmp_len = strlen(tmp);
    
    memcpy(node->Id, tmp, tmp_len);
    node->Id[tmp_len] = 0;
    free(tmp);
    
    char *pflag = strstr(node->data, "\r\n\r\n");
    if (NULL == pflag)
        return -1;
    
    pflag += 4;
    memset(node->fileName, 0, MAX_PATH_LEN+1);
    
    char *p1 = memnfind(pflag+1, 10, "\r\n", 2, NULL);
    if (p1)
        snprintf(node->fileName, MAX_PATH_LEN, "%.*s", p1-pflag-1, pflag+1);
    
    write_weibo_attach(node->save_path, "QQ", node->fileName, pflag, node->dataLen-(pflag-node->data), 0);
    
    return -2;
}

int analyse_mbwb_allinone(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
	char *uin_key = "p_uin=";
	char *http_body;
	char *puin;
	char *puin_end = NULL;
	cJSON *objectroot, *item_content, *item_qua, *item_post_type;

    if (0 == node->is_complished)
        return 0;

	if (!node->body || !node->header)
		return -1;

	http_body = strstr(node->data, "\r\n\r\n");
	puin  = strstr(node->data, uin_key);

	if (!puin || !http_body)
        return -1;
	
	// copy uin
	puin += strlen(uin_key);
	puin_end = puin;
	http_body += strlen("\r\n\r\n");

	while (!(*puin_end == '\r' || *puin_end == '\n' || *puin_end == ';')) 
        puin_end++;
    
    strncpy(node->from, puin, ((puin_end - puin) > MAX_FROM_LEN ? MAX_FROM_LEN:(puin_end - puin)));

	objectroot = cJSON_Parse(http_body);
	if (!objectroot) 
        return -1;

	item_content = cJSON_GetObjectItem(objectroot, "content");
	item_qua = cJSON_GetObjectItem(objectroot, "qua");
	item_post_type = cJSON_GetObjectItem(objectroot, "postType");

	// copy content/comment, agent
	if (item_post_type)
	{
		int post_type = atoi(item_post_type->valuestring);
		// publish article, forward article, comment article
		if (0 == post_type || 2 == post_type || 4 == post_type)
		{
			// FIXME: UTF-8 Encoding here may cause problems..
			//size_t cnt_len = strlen(item_content->valuestring)*2;
			if (item_content)
			    node->content = strdup(item_content->valuestring);
			//strncpy(node->agent, item_qua->valuestring, MAX_AGENT_LEN);
            
            if (0 == post_type)
                node->wbType= Guangbo;
            else if (2 == post_type)
                node->wbType = Zhuanfa;
            else if (4 == post_type)
                node->wbType = Pinglun;
		}
		// we should not go here...
		else
        {      
			//printf("unsupported post type(%d)\n", item_post_type->valueint);
			node->wbType = Unknow;
            cJSON_Delete(objectroot);
			return -1;
        }
	}
    else
    {
        cJSON_Delete(objectroot);
        return -1;
    }

    cJSON_Delete(objectroot);
	return 1;
}

int analyse_mbwb_private_msg(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
	char *uin_key = "p_uin=";
	char *http_body;
	char *puin;
	char *puin_end = NULL;
	cJSON *objectroot, *item_msg, *item_qua, *item_accountid;

	if (!node->is_complished)
		return 0;
	
	if (!node->header || !node->body)
		return -1;

	puin = strstr(node->data, uin_key);
	http_body = strstr(node->data, "\r\n\r\n");

	if (!puin || !http_body) 
        return -1;

	// copy uin
	puin += strlen("p_uin=");
	puin_end = puin;

	http_body += strlen("\r\n\r\n");

	while (!(*puin_end == '\r' || *puin_end == '\n' || *puin_end == ';')) 
        puin_end++;
    
    strncpy(node->from, puin, ((puin_end - puin) > MAX_FROM_LEN ? MAX_FROM_LEN:(puin_end - puin)));

	objectroot = cJSON_Parse(http_body);
	if (!objectroot) 
        return -1;

	item_accountid = cJSON_GetObjectItem(objectroot, "accountId");
	item_msg = cJSON_GetObjectItem(objectroot, "msgContent");
	item_qua = cJSON_GetObjectItem(objectroot, "qua");

	if (!item_msg || !item_accountid)
	{
        cJSON_Delete(objectroot);
        return -1;
	}

	node->content = strdup(item_msg->valuestring);
	//strncpy(node->agent, item_qua->valuestring, MAX_AGENT_LEN);
    strncpy(node->to, item_accountid->valuestring, MAX_TO_LEN);
    
    node->wbType = Sixin;
    cJSON_Delete(objectroot);
    
	return 1;
}

int analyse_mbwb_follow(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
	char *uin_key = "p_uin=";
	char *http_body;
	char *puin;
	char *puin_end = NULL;
	cJSON *objectroot, *item_accountid, *item_type, *item_qua;
	int follow_type;

	if (!node->is_complished)
		return 0;
	
	if (!node->header || !node->body)
		return -1;

	puin = strstr(node->data, uin_key);
	http_body = strstr(node->data, "\r\n\r\n");

	if (!puin || !http_body) 
        return -1;

	// copy uin
	puin += strlen("p_uin=");
	puin_end = puin;
	http_body += strlen("\r\n\r\n");

	while (!(*puin_end == '\r' || *puin_end == '\n' || *puin_end == ';')) 
        puin_end++;
    
    strncpy(node->from, puin, ((puin_end - puin) > MAX_FROM_LEN ? MAX_FROM_LEN:(puin_end - puin)));

	objectroot = cJSON_Parse(http_body);
	if (!objectroot) 
        return -1;

	item_accountid = cJSON_GetObjectItem(objectroot, "accountId");
	item_type = cJSON_GetObjectItem(objectroot, "type");
	item_qua = cJSON_GetObjectItem(objectroot, "qua");

	if (!item_type || !item_qua || !item_accountid) 
	{
        cJSON_Delete(objectroot);
        return -1;
	}

	node->follow = item_type->valueint;
	strncpy(node->agent, item_qua->valuestring, MAX_AGENT_LEN);

	printf("Follow action detected, from: %s, accountId: %s, agent: %s, follow: %d\n", 
			node->from, item_accountid->valuestring, node->agent, node->follow);

    cJSON_Delete(objectroot);
	return 1;
}

int analyse_QQwb_Send(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    
    if (NULL == node->data || NULL == node->body)
        return -1;

    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "o_cookie=", ";", 9, MAX_FROM_LEN);   
    if (NULL == p1)
        return -1;
    
    p1 = strstr(node->data, "\r\n\r\n");
    if (NULL == p1)
        return -1;
    
    p1 += 4;
    if (NULL != strstr(node->header, "Content-Encoding: gzip\r\n") && 0 != decompress_2(&node->body, (int *)&node->bodyLen))
        return -1;
    
    char *pflag = strstr(node->body, "\"source\":{");
    if (NULL != pflag)
    {
        if (strstr(p1, "&type=1"))
            node->wbType = Zhuanfa;
        else
            node->wbType = Pinglun;
        
        pflag += 10;
        wb_ptrcpy(&node->reason, p1, "content=", "&", 8);
        if (node->reason)
            wb_url_decode(node->reason, node->reason);
        
        wb_ptrcpy(&node->content, pflag, "\"content\":\"", "\",\"time\":", 11);
        if (node->content)
        {
            wb_url_decode(node->content, node->content);
            char *tmp = clear_id(node->content);
            free(node->content);
            
            node->content = wb_clear_html_tag(tmp);
            free(tmp);
            wb_clear_u(node->content, '\\');
        }
        
        wb_arrcpy(node->to, pflag, "\"name\":\"", "\"", 8, MAX_TO_LEN);
    }
    else
    {
        node->wbType = Guangbo;
        wb_ptrcpy(&node->content, p1, "content=", "&", 8);
        if (node->content)
            wb_url_decode(node->content, node->content);
    }
    
    p1 = wb_arrcpy(node->Id, p1, "&pic=", "&", 5, MAX_ID_LEN);
    if (NULL != p1)
    {
        wb_url_decode(node->Id, node->Id);
        attc_node(node, 0);
    }
    
    return 1;
}

int analyse_QQwb_Sixin(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    
    if (NULL == node->data)
        return -1;

    char *p1 = NULL;
    p1 = wb_arrcpy(node->from, node->data, "o_cookie=", ";", 9, MAX_FROM_LEN);
    if (NULL == p1)
        return -1;

    p1 = strstr(node->data, "\r\n\r\n");
    if (NULL == p1)
        return -1;
    
    p1 += 4;
    p1 = wb_ptrcpy(&node->content, p1, "content=", "&", 8);
    if (NULL == p1)
        return -1;
    
    if (node->content)
    {
        wb_url_decode(node->content, node->content);
        char *tmp = clear_id(node->content);
        free(node->content);
        
        node->content = wb_clear_html_tag(tmp);
        free(tmp);
        
        wb_clear_u(node->content, '\\');
    }
    
    wb_arrcpy(node->to, p1, "&target=", "&", 8, MAX_TO_LEN);
    node->wbType = Sixin;
    if (NULL != wb_arrcpy(node->Id, p1, "&fid=", "&", 5, MAX_ID_LEN))
    {
        wb_url_decode(node->Id, node->Id);
        attc_node(node, 0);
    }
    
    return 1;
}

int analyse_QQWb(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
    unsigned short type = node->type & 0x00FF;
    int result = 0;
    
    switch (type)
    {
        case 0x01:
        case 0x02:
            result = analyse_QQwb_Login(node, packetinfo, is_to_s);
            break;
		// mobile weibo, add this comment to make our life more easy...
		case 0x03:
			// publish, comment, forward
			result = analyse_mbwb_allinone(node, packetinfo, is_to_s);
			break;
		case 0x04:
			// private messages
			result = analyse_mbwb_private_msg(node, packetinfo, is_to_s);
			break;
		case 0x05:
			// follow/unfollow   //close temporary by zhangzm
			//result = analyse_mbwb_follow(node, packetinfo, is_to_s);
			break;
		// end mobile weibo
        case 0x06:
            result = analyse_QQwb_Logout(node, packetinfo, is_to_s);
            break;
        case 0x11:
            result = analyse_QQwb_Send(node, packetinfo, is_to_s);
            break;
        case 0x12:
            result = analyse_QQwb_Sixin(node, packetinfo, is_to_s);
            break;
        case 0x51:
            result = analyse_QQwb_Upfile(node, packetinfo, is_to_s);
            break;
        case 0x52:
            result = analyse_QQwb_Sixinfile(node, packetinfo, is_to_s);
            break;
        default:
            break;
    }
    
    return result;
}


