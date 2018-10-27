
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/socket.h>

#include "weibocommon.h"
#include "clue_c.h"
#include "db_data.h"

extern const char * server;
extern const char * database;
extern const char * user;
extern const char * password;
extern const char * lzDataPath;

//OFOC_t ofo;
//PIRS_t rset;
struct g_weibo_entryList g_entryList;

const char *attachpath = "/home/spyData/moduleData/weibo/";

int write_wb_sql(WbNode *node)
{
	WEIBO_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));

    wb_ulong_to_ipstr(node->srcIpv4, tmp_data.p_data.clientIp);
    wb_ulong_to_ipstr(node->destIpv4, tmp_data.p_data.serverIp);

	unsigned char *p = node->srcMac;
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", p[0], p[1], p[2], p[3], p[4], p[5]);

	tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);
	tmp_data.p_data.readed = 0;

	sprintf(tmp_data.p_data.clientPort, "%d", node->srcPort);
	sprintf(tmp_data.p_data.serverPort, "%d", node->destPort);
	
	strncpy(tmp_data.username, node->username, 63);
	strncpy(tmp_data.password, node->passwd, 63);
    strncpy(tmp_data.nickname, node->from, 63);
    strncpy(tmp_data.peeraccount, node->to, 63);
    strncpy(tmp_data.datafile, node->save_path, 255);

    if (node->content)
    {
        strncpy(tmp_data.content, node->content, 2048);
    }
    else
    {
        strcpy(tmp_data.content, "");
    }

    if (node->reason)
    {
        strncpy(tmp_data.comment, node->reason, 1023);
    }
    else
    {
        strcpy(tmp_data.comment, "");
    }

    tmp_data.optype = node->wbType;
    tmp_data.p_data.captureTime = (unsigned int)time(NULL);
    tmp_data.p_data.proType = node->urltype;
    tmp_data.p_data.deleted = 0;
    
	msg_queue_send_data(WEIBO, (void *)&tmp_data, sizeof(tmp_data));

    return 0;
}


WbNode * insert_WbNode(PacketInfo * packetInfo)
{ 
    WbNode * Node= (WbNode *)malloc(sizeof(WbNode));
    memset(Node,0,sizeof(WbNode));
    Node->time                   = time(NULL);
    memset(Node->srcMac,0,6);
    memcpy(Node->srcMac,packetInfo->srcMac,6);
    memset(Node->destMac,0,6);
    memcpy(Node->destMac,packetInfo->destMac,6);
    Node->srcIpv4            = packetInfo->ip->saddr;
    Node->destIpv4           = packetInfo->ip->daddr;
    if (TCP == packetInfo->pktType)
    Node->srcPort            = packetInfo->srcPort;
    Node->destPort           = packetInfo->destPort;
    
    Node->headerLen          = 0;
    Node->header             = NULL;
    Node->body               = NULL;
    Node->bodyLen            = 0;
    Node->bodyTotal          = 0;
    Node->head_status        = STATUS_IDLE;
    Node->body_status        = STATUS_IDLE;
    Node->data               = NULL;
    Node->dataLen            = 0;
    Node->dataTotal          = 0;
    Node->type               = 0x00;
    Node->wbType             = Unknow;
    Node->urltype            = 0;
    Node->fileName[0]        = 0;
    memset(Node->save_path, 0, MAX_PATH_LEN+1);
    Node->fileLen            = 0;
    Node->fileNum            = 0;
    Node->sent_time[0]       = 0;
//    Node->from                = 0;
    memset(Node->username, 0 , MAX_UN_LEN);
    memset(Node->from,0,MAX_FROM_LEN);
  //  Node->to                    = 0;
    memset(Node->to,0,MAX_TO_LEN);
    Node->sent_time[0] = 0;
    Node->Id[0]                 = 0;
    Node->content            = NULL;
    Node->reason             = NULL;
    Node->is_complished = 0;
    
    Node->prev = g_entryList.head;
    Node->next = g_entryList.head->next;
    g_entryList.head->next = Node;
    g_entryList.count++;
    if (Node->next != NULL)
	Node->next->prev = Node;
    else
	g_entryList.tail=Node;
    return Node;
}

WbNode * find_WbNode(PacketInfo * packetInfo, int * is_cons)
{ 
    WbNode * tmp = g_entryList.head->next;
    while(NULL!=tmp)
    {
        if(0==tmp->is_complished && tmp->srcIpv4==packetInfo->ip->saddr && tmp->destIpv4==packetInfo->ip->daddr &&
                tmp->srcPort==packetInfo->srcPort && tmp->destPort==packetInfo->destPort)
        {
            *is_cons=0;
            break;
        }
        else if(0==tmp->is_complished && tmp->srcIpv4==packetInfo->ip->daddr && tmp->destIpv4==packetInfo->ip->saddr &&
                tmp->srcPort==packetInfo->destPort && tmp->destPort==packetInfo->srcPort)
        {
            *is_cons=1;
            break;
        }
        else
        {
            tmp= tmp->next;
        }
    }
    return tmp;
}

void free_node(WbNode *node)
{
    FREE(node->header);
    FREE(node->data);
    FREE(node->body);
    FREE(node->content);
    FREE(node->reason);
    node->headerLen = 0;
    node->bodyLen = 0;
    node->bodyTotal = 0;
}
void del_WbNode(WbNode * node)
{
	if (NULL == node)
            return ;
    free_node(node);
	if (node->next == NULL) 
	{
		g_entryList.tail=node->prev;
		node->prev->next = NULL;
	} 
	else 
	{
		node->prev->next = node->next;
		node->next->prev = node->prev;
	}    
	g_entryList.count--;
}

int wb_init(void)
{
     g_entryList.head = (WbNode *)malloc(sizeof(WbNode));
    if (g_entryList.head == NULL)
    {
        perror("im:init()->malloc()1");
        return -1;
    }
    //ofo=ofoCreate();
	//rset=pirsCreate();
    g_entryList.head->next = NULL;
    g_entryList.head->prev = NULL;
    g_entryList.tail             = g_entryList.head;
    g_entryList.count             = 0;
    return 0;
}


void output_wb(WbNode *node)
{
    struct tm *ptm = localtime(&(node->time));
      
    LOG_INFO("username:\t%s\n",node->username);
    LOG_INFO("passwd:\t%s\n",node->passwd);
    LOG_INFO("ID:\t\t%s\n",node->Id);
    LOG_INFO("from:\t\t%s\n",node->from);
    LOG_INFO("to:\t\t%s\n",node->to);
    LOG_INFO("reason:\t\t%s\n",node->reason);
    LOG_INFO("content:\t%s\n",node->content);
    LOG_INFO("filename:\t%s\n", node->fileName);
    LOG_INFO("savepath:\t%s\n", node->save_path);

    LOG_INFO("time:\t\t%u-%u-%u %u:%02u\n", ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,ptm->tm_hour, ptm->tm_min);
    LOG_INFO("\n");
  
}

char *clear_wbcontent_symbol(char *source)
{
	if (source == NULL)
		return NULL;
	char *str = strdup(source);
	int result;
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "\\\\n", "\n");
	if (result != -1)
		result = wb_cns_str_ereplace(&str, "\\\\t", "\t");

	return str;
}

int http_recive(WbNode * entry, char *data, int dataLen)
{
	if(entry->head_status == STATUS_IDLE)
	{
		char *p = strstr(data, "\r\n\r\n");
		if (p)
		{
			p += 4;
			if (entry->headerLen == 0)
			{
				entry->headerLen = p - data;
				entry->header = (char *)malloc(p - data + 1);
				if (!entry->header) 
				{
					return -1;
				}
				
				memcpy(entry->header, data, p-data);
				entry->header[entry->headerLen] = 0;
			}
			else
			{
				entry->header = (char *)realloc(entry->header, entry->headerLen + (p-data) + 1);
				if(!entry->header) 
				{
					return -1;
				}
				memcpy(entry->header + entry->headerLen, data, p-data);
				entry->headerLen += p-data;
				entry->header[entry->headerLen] = 0;
			}
			
			entry->head_status = FULL_HTTP_HEAD;
			char* p2 = NULL;
			if(p2 = strstr(entry->header, "\r\nContent-Length: "))
			{
				p2 += 18;
				char * p3 = strstr(p2, "\r\n");
				char * p4 = NULL;
				unsigned int len = 0;
				for (p4 = p2; p4 < p3; p4++)
				{
					if(*p4>='0' && *p4<='9')
					{
						len = len*10 + (*p4-'0');
					}
					else
					{
						break;
					}
				}
                
				entry->bodyTotal = len;
                entry->bodyLen = dataLen - (p-data);
				entry->body = (char *)malloc(entry->bodyLen + 1);
				if (!entry->body)
				{
					return -1;
				}

                if (entry->bodyLen > 0)
				    memcpy(entry->body, p, entry->bodyLen);
                
				entry->body_status = INIT_BODY_CONTENT;
				if (entry->bodyLen >= entry->bodyTotal)
				{
					entry->body[entry->bodyLen] = 0;
					entry->body_status = FULL_BODY_CONTENT;
					return 1;
				}
			}
			else
			{
				return 1;
			}
		}
		else
		{
			if(entry->headerLen == 0)
			{
				entry->headerLen = dataLen;
				entry->header = (char* )malloc(dataLen + 1);
				if(!entry->header)
				{
					return -1;
				}
				memcpy(entry->header, data, dataLen);
			}
			else
			{
				entry->header = (char *)realloc(entry->header, entry->headerLen + dataLen + 1);
				if (!entry->header)
				{
					return -1;
				}
                
				memcpy(entry->header + entry->headerLen, data, dataLen);
				entry->headerLen += dataLen;
			}
		}
	}
	
	if (entry->body_status == INIT_BODY_CONTENT)
	{
		//add by hqw
		entry->body = (char *)realloc(entry->body, entry->bodyLen + dataLen + 1);
		if (!entry->body)
		{
			return -1;
		}		
		memcpy(entry->body + entry->bodyLen, data, dataLen);
		entry->bodyLen += dataLen;
		if(entry->bodyLen >= entry->bodyTotal)
		{
			entry->body[entry->bodyLen] = 0;
			entry->body_status = FULL_BODY_CONTENT;
			return 1;
		}
	}
    
	return 0;
}

int write_weibo_attach(char path[MAX_PATH_LEN+1], char *type, char name[MAX_PATH_LEN+1], char *data, int len, int up_or_down)
{
    struct timeval tv;
	struct timezone tz;
    int fd;
    mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    
    gettimeofday(&tv, &tz);
    char makedir[MAX_PATH_LEN] = {0};
    char file_path[MAX_PATH_LEN+1] = {0};
    char tmpname[MAX_PATH_LEN+1] = {0};
    memcpy(tmpname, name, strlen(name));
    
    snprintf(path, MAX_PATH_LEN, "%s%s/file/",attachpath, type);
    //sprintf(makedir, "mkdir -p %s", path);
    //system(makedir);
    mkdir(path, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    memset(name, 0, MAX_PATH_LEN+1);
    snprintf(name, MAX_PATH_LEN, "%lu-%lu-%s",tv.tv_sec, tv.tv_usec, tmpname);
	snprintf(file_path, MAX_PATH_LEN, "%s%s",path,name);
    
    fd = open(file_path, O_RDWR|O_CREAT, file_mode);
    if (fd == -1)
	{
		LOG_ERROR("%s write err!\n", name);
		return -1;
	}
	write(fd, data, len);
	close(fd);

    return 0;
}

/*-----------------------------1045458718190
Content-Disposition: form-data; name="Filedata"; filename="test.png"
*/
int analyse_file_1(char *data, int dataLen, char save_path[MAX_PATH_LEN+1],char fileName[MAX_PATH_LEN+1], char *type)
{
    char *p1 = strstr(data, "\r\n\r\n");
    if (NULL == p1)
        return -1;
    p1 += 4;
    int fileLen = 0;
    if (*p1 != '-')
    {
        memcpy(fileName, "unknown", 7);
        fileName[7] = 0;
        fileLen = dataLen;
    }
    else
    {
        char *p2 = strstr(p1, "\r\n");
        if (NULL == p2)
            return -1;
        int len = p2-p1;
        char *endflag = (char *)malloc(len+3);
    	memcpy(endflag, "\r\n", 2);
        memcpy(endflag+2, p1, len);
        endflag[len+2] = 0;
        LOG_INFO("endflag:%s\n", endflag);
        p1 = wb_arrcpy_2(fileName, p1, "filename=\"", "\"", 10, MAX_PATH_LEN);
        if (NULL == p1)
            return -1;
        p1 = strstr(p1, "\r\n\r\n");
        if (NULL == p1)
            return -1;
        p1 += 4;
        p2 = memnfind(p1, dataLen-(p1-data), endflag, len, NULL);
        if (NULL == p2)
            return -1;
        fileLen = p2-p1;
    }
    
    write_weibo_attach(save_path, type, fileName, p1, fileLen, 0);
    return -2;
}


int attc_node(WbNode *node, int flag)
{
    WbNode *attnode = g_entryList.head->next, *tmpnode = NULL;
    while(attnode)
    {
        if (File!=attnode->wbType || NULL==strstr(node->Id, attnode->Id))
        {
            attnode = attnode->next;
            continue;
        }

        int len1 = strlen(attnode->fileName);   
        int len2 = strlen(node->fileName);
        if (len2<MAX_PATH_LEN && strlen(node->save_path)<MAX_PATH_LEN)
        {
            if (len1+len2+1> MAX_PATH_LEN)
                len1 = MAX_PATH_LEN-len2-1;
            if (len2)
            {
                memcpy(node->fileName+len2, "|", 1);
                len2 += 1;
            }
            memcpy(node->fileName+len2, attnode->fileName, len1);
            node->fileName[len1+len2] = 0;
            len1 = strlen(attnode->fileName);   
            len2 = strlen(node->save_path);
            if (len2 > MAX_PATH_LEN)
                return 0;
            if (len1+len2+1> MAX_PATH_LEN)
                len1 = MAX_PATH_LEN-len2-1;
            if (0 == node->fileNum)
            {
                len2 = strlen(attnode->save_path);
                memcpy(node->save_path, attnode->save_path, len2);
            }
            else
            {
                memcpy(node->save_path+len2, "|", 1);
                len2 += 1;
            }
            memcpy(node->save_path+len2, attnode->fileName, len1);
    		node->fileNum++;
        }
		tmpnode = attnode->next;
		del_WbNode(attnode);
        attnode = tmpnode;
    }
    return 0;
}

int del_file(char *Id)
{
    WbNode *attnode = g_entryList.head->next, *tmpnode = NULL;
    while (attnode)
    {
        if (File!=attnode->wbType || 0!=strcmp(attnode->Id, Id))
        {
            attnode = attnode->next;
            continue;
        }
        del_WbNode(attnode);
        return 0;
    }
    return 0;
}


