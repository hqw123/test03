#include "weibocommon.h"

int analyse_M163wb_Login( WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;

    char *p1 = NULL;
	
    node->wbType = Login;
    if (NULL == node->data)
        return -1;
	
    p1 = wb_arrcpy(node->username, node->data, "&username=", " ", 10, MAX_UN_LEN);
    if (NULL == p1)
        return -1;
	
    wb_url_decode(node->username, node->username);
	
    return 1;
}

int analyse_M163wb_Logout( WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
	
    char *p1 = NULL;
	
    node->is_complished = 1;
    node->wbType = Logout;
    if (NULL == node->data)
        return -1;
	
    p1 = wb_arrcpy(node->username, node->data, "P_INFO=", "|", 7, MAX_UN_LEN);
    if (NULL == p1)
        return -1;
	
    return 1;
}
extern char *clear_id(char * source);

int analyse_M163wb_textToImage(WbNode *node, PacketInfo *packetInfo,int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    char *p1 = NULL;
    if (NULL == node->data)
        return -1;
    
    node->wbType = File;
    if ((NULL != strstr(node->header, "Content-Encoding: gzip\r\n")) && (0 != decompress_2(&node->body, (int *)&node->bodyLen)))
        return -1;
    if (NULL == wb_arrcpy_2(node->Id, node->body, "\"originalURL\": \"", "\"", 16, MAX_ID_LEN))
    {
        if (NULL == wb_arrcpy_2(node->Id, node->body, "\"originalURL\":\"", "\"", 16, MAX_ID_LEN))
            return -1;
    }
    char *tmp = clear_id(node->Id);
    memcpy(node->Id, tmp, strlen(tmp));
    node->Id[strlen(tmp)] = 0;
    free(tmp);
    //LOG_DEBUG("id:%s\n", node->Id);

    p1 = strstr(node->data, "\r\n\r\n");
    if (NULL == p1)
        return -1;
    p1 += 4;
    int len = node->dataLen - (p1-node->data);
    p1 = memnfind(p1, len, "&text=", 6, NULL);
    if (NULL == p1)
        return -1;
    p1 += 6;
    node->fileLen = node->dataLen - (p1-node->data);
    memcpy(node->fileName, "1.txt", 5);
    node->fileName[5] = 0;
    tmp = (char *)malloc(node->fileLen+1);
    memcpy(tmp, p1, node->fileLen);
    tmp[node->fileLen] = 0;
    wb_url_decode(tmp, tmp);
    write_weibo_attach(node->save_path, "163", node->fileName, tmp, strlen(tmp), 0);
    free(tmp);
    return -2;
}

int analyse_M163wb_Upfile(WbNode *node, PacketInfo *packetInfo,int is_to_s)
{
    if (0 == node->is_complished)
        return 0;
    char *p1 = NULL;
    if (NULL == node->data || NULL == node->body)
        return -1;
    
    node->wbType = File;
    if ((NULL != strstr(node->header, "Content-Encoding: gzip\r\n")) && (0 != decompress_2(&node->body, (int *)&node->bodyLen)))
        return -1;
    if (NULL == wb_arrcpy_2(node->Id, node->body, "\"originalURL\": \"", "\"", 16, MAX_ID_LEN))
    {
        if (NULL == wb_arrcpy_2(node->Id, node->body, "\"originalURL\":\"", "\"", 16, MAX_ID_LEN))
            return -1;
    }
    char *tmp = clear_id(node->Id);
    memcpy(node->Id, tmp, strlen(tmp));
    node->Id[strlen(tmp)] = 0;
    free(tmp);
    //LOG_DEBUG("id:%s\n", node->Id);
        
    return analyse_file_1(node->data, node->dataLen, node->save_path, node->fileName, "163");
}

int analyse_M163wb_Send(WbNode *node, PacketInfo *packetInfo, int is_to_s)
{
    if (0 == is_to_s)
        return 0;
    char *p1 = NULL;
    if (NULL==node->data)
        return -1;
    node->is_complished = 1;
    wb_arrcpy(node->from, node->data, "P_INFO=", "|", 7, MAX_FROM_LEN);   
    char *pflag = strstr(node->data, "\r\n\r\n");
    if (NULL == pflag)
        return -1;
    pflag+= 4;
    if ((node->type&0x00FF) == 0x12)
    {
        node->wbType = Sixin;
        wb_arrcpy(node->to, pflag, "nickName=", "&", 9, MAX_TO_LEN); 
        wb_url_decode(node->to, node->to);
        p1 = strstr(pflag, "content=");
        if(NULL != p1)
        {
            p1 += 8;
            int len = node->dataLen-(p1-node->data);
            node->content = (char *)malloc(len+1);
            memcpy(node->content, p1, len);
            node->content[len] = 0;
            wb_url_decode(node->content, node->content);
        }
        return 1;
    }
    p1 = wb_arrcpy(node->Id, pflag, "&imageUrl=", "&", 10, MAX_ID_LEN);
    if (NULL != p1)
    {
        wb_url_decode(node->Id, node->Id);
        LOG_DEBUG("id:%s\n", node->Id);
        attc_node(node, 0);
    }
    p1 = strstr(pflag, "&flag=");
    if (NULL == p1)
        return -1;
    p1 += 6;
    if ('0'==*p1)
    {
        node->wbType = Guangbo;
        wb_ptrcpy(&node->content, pflag, "content=", "&", 8);
        if (node->content)
            wb_url_decode(node->content, node->content);
    }
    else if ('1'==*p1)
    {
        node->wbType = Zhuanfa;
        
        wb_ptrcpy(&node->content, pflag, "content=", "&", 8);
        if (node->content)
            wb_url_decode(node->content, node->content);
    }
    else if ('2'==*p1)
    {
        node->wbType = Pinglun;
        wb_ptrcpy(&node->reason, pflag, "content=", "&", 8);
        if (node->reason)
            wb_url_decode(node->reason, node->reason);
    }

    return 1;
}

int analyse_M163Wb(WbNode *node, PacketInfo *packetinfo, int is_to_s)
{
    unsigned short type = node->type & 0x00FF;
    int result = 0;
    switch (type)
    {
        case 0x01:
            result = analyse_M163wb_Login(node, packetinfo, is_to_s);
            break;
        case 0x06:
            result = analyse_M163wb_Logout(node, packetinfo, is_to_s);
            break;
        case 0x11:
        case 0x12:
            result = analyse_M163wb_Send(node, packetinfo, is_to_s);
            break;
        case 0x13:
            result = analyse_M163wb_textToImage(node, packetinfo, is_to_s);
            break;    
        case 0x51:
            result = analyse_M163wb_Upfile(node, packetinfo, is_to_s);
            break;
        default:
            break;
    }
    return result;
}



