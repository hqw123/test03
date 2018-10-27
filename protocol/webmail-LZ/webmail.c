//#include "common.h"
#include "mail_type.h"
#include "control.h"
#include "PacketParser.h"
#include "global.h"
#include <libxml/parser.h>

int ControlC302 = 0;
char C302ServerIp[MAX_LENGTH];
int C302Serverport;

void *GetC302ServerInfo(void * block)
{
	while(1)
	{
		xmlDocPtr doc = NULL;
		xmlNodePtr curNode = NULL;
		xmlNodePtr itemNode = NULL;

		doc = xmlReadFile("/spy/config/C302Device.xml", "UTF-8", XML_PARSE_RECOVER);
		if (!doc) 
		{
			LOG_ERROR("Read C302 configure file failed!\n");
			break;
		}
		curNode = xmlDocGetRootElement(doc);
		if (!curNode)
		{
			LOG_ERROR("Empty C302 configure file!\n");
			xmlFreeDoc(doc);
			break;
		}
		if (xmlStrcmp(curNode->name, BAD_CAST "C302Device"))
		{
			LOG_ERROR("Root node error!\n");
			xmlFreeDoc(doc);
			break;
		}
		itemNode = curNode->xmlChildrenNode;
		while (itemNode)
		{
			if (itemNode->type != XML_ELEMENT_NODE)
			{
				itemNode = itemNode->next;
				continue;
			}
			if (!xmlStrcmp(itemNode->name, BAD_CAST "Control"))
			{
				ControlC302 = atoi((const char *)xmlNodeGetContent(itemNode));
			} 
			else if (!xmlStrcmp(itemNode->name, BAD_CAST "ServerIp"))
			{
				memset(C302ServerIp, 0, MAX_LENGTH);
				memcpy(C302ServerIp, (const char *)xmlNodeGetContent(itemNode), strlen((const char *)xmlNodeGetContent(itemNode)));
			} 
			else if (!xmlStrcmp(itemNode->name, BAD_CAST "ServerPort"))
			{
				C302Serverport = atoi((const char *)xmlNodeGetContent(itemNode));
			}
			itemNode = itemNode->next;
		}
		xmlFreeDoc(doc);
		
		sleep(30);
	}
}

int webmail_init(void)
{
	mail_tab.head = (Mail_info *)malloc(sizeof(Mail_info));
	if (mail_tab.head == NULL)
	{
		perror("webmail:init()->malloc()1");
		return -1;
	}
	mail_tab.head->next = NULL;
	mail_tab.head->prev = NULL;
	mail_tab.count = 0;

	attach_tab.head = (Attach_info *)malloc(sizeof(Attach_info));
	if (attach_tab.head == NULL) 
	{
		perror("webmail:init()->malloc()2");
		return -1;
	}
	attach_tab.head->next = NULL;
	attach_tab.head->prev = NULL;
	attach_tab.tail = attach_tab.head;
	attach_tab.count = 0;

	if(lzDataPath == NULL)
	{
		strcpy(mail_data_path, "/home/spyData/moduleData/webmail");   //发送接受的邮件存放路径
		strcpy(mail_temp_path, "/home/spyData/moduleData/webmail/temp");//附件上传的临时路径
		strcpy(attach_down_path, "/home/spyData/moduleData/webmail/downattach");//附件下载存放路径
		strcpy(mail_password_path,"/home/spyData/moduleData/webmail/loginpasswd");
	}
	else
	{
		strcpy(mail_data_path, lzDataPath);
		strcat(mail_data_path, "/spyData/moduleData/webmail");
		
		strcpy(mail_temp_path, lzDataPath);
		strcat(mail_temp_path, "/spyData/moduleData/webmail/temp");
		
		strcpy(attach_down_path, lzDataPath);
		strcat(attach_down_path, "/spyData/moduleData/webmail/downattach");
		
		strcpy(mail_password_path, lzDataPath);
		strcat(mail_password_path, "/spyData/moduleData/webmail/loginpasswd");
	}
	//创建目录
	mode_t dir_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	mkdir(mail_data_path, dir_mode);
	mkdir(mail_temp_path, dir_mode);
	mkdir(attach_down_path, dir_mode);
	mkdir(mail_password_path, dir_mode);

	// added by jacky Wed Mar  1 23:52:50 PST 2017
	init_mbox_hashtable();
// 	pthread_t Thread_id;
// 	pthread_create(&Thread_id, NULL, GetC302ServerInfo, NULL);

	return 0;
}

/* webmail */
int analyse_webmail(struct PacketInfo * packetinfo)//return 0:webmail not do ; return 1:webmail do
{
	Mail_info *mail_info = NULL;
	Attach_info *attach_info = NULL;
	int is_to_s, m_or_a, result;
	unsigned short type, tmp_type;
	void *node = NULL;

	if( packetinfo->pktType != TCP || (packetinfo->srcPort != 80 && packetinfo->destPort != 80 && packetinfo->srcPort != 8080 && packetinfo->destPort != 8080 && packetinfo->srcPort != 8088 && packetinfo->destPort != 8088 && packetinfo->srcPort != 8081 && packetinfo->destPort != 8081))
	{
		return 0;
	}

	if (!packetinfo->bodyLen && !packetinfo->tcp->fin && !packetinfo->tcp->rst)
	{
		return 0;
	}

	// modified by jacky Wed Mar  1 19:45:04 PST 2017
	//unsigned short packet_type = mail_type(packetinfo->body);
	unsigned short packet_type = mail_type(packetinfo->body);
    if(packet_type == 0)
    {
	    packet_type = mail_type_prefetched(packetinfo->body);
    }
	// remove the line below for code merge 

	mail_info = find_mail_node(packetinfo->ip->saddr, packetinfo->ip->daddr, packetinfo->tcp->source, packetinfo->tcp->dest, &is_to_s);
	if (mail_info != NULL)
	{
		if (packetinfo->tcp->rst == 1)
		{
			delete_mail_info(mail_info);
			return 1;
		}
		m_or_a = 0;
		node = mail_info;
		type = mail_info->mail_type;
		mail_info->count = 0;
	}
	else
	{
		attach_info = find_attach_node(packetinfo->ip->saddr, packetinfo->ip->daddr, packetinfo->tcp->source, packetinfo->tcp->dest, &is_to_s, packet_type);
		if (attach_info != NULL)
		{
			
			if (packetinfo->tcp->rst == 1) 
			{
				if (attach_info->path_of_here[0] != 0)
					unlink(attach_info->path_of_here);
				del_attach_node(attach_info);
				delete_attach(attach_info);
				return 1;
			}
			m_or_a = 1;
			node = attach_info;
			type = attach_info->attach_type;
		}
	}

	if (mail_info == NULL && attach_info == NULL) 
	{
		type = packet_type;
		if (type <= 0) 
		{
			return 0;
		}

		tmp_type = type & 0X00FF;
        if (tmp_type == 0)
            return 0;
        
		if(tmp_type <= 0x50 ||tmp_type >= 0x80)
		{
			Mail_info *mail_info = insert_mail_node((char *)packetinfo->srcMac,packetinfo->ip, packetinfo->tcp, type);
			if (mail_info == NULL)
				return 0;
			m_or_a = 0;
			is_to_s = 1;
			mail_info->cap_time = (unsigned int)packetinfo->pkt->ts.tv_sec;
			node = mail_info;
		} 
		else
		{
			Attach_info *attach_info = insert_attach_node(packetinfo->ip, packetinfo->tcp, type, packet_type);
			if (attach_info == NULL)
				return 0;
			m_or_a = 1;
			is_to_s = 1;
			attach_info->cap_time = (unsigned int)packetinfo->pkt->ts.tv_sec;
			node = attach_info;
		}
	}
	
	tmp_type = type >> 8;
	switch (tmp_type) {
	case 1:
		analyse_sina(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 2:
		analyse_21cn(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 3:
		analyse_sohu(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 4:
		analyse_163(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 5:
		analyse_hotmail(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 6:
		analyse_yahoo(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 7:
		analyse_tom(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 8:
		analyse_yeah(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 9:
		analyse_eyou(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0A:
		analyse_263(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0B:
		analyse_qq(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0C:
		analyse_sogou(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0D:
		analyse_126(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0E:
		analyse_188(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x0F:
		analyse_gmail(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x10:
		analyse_mail(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x11:
		analyse_aol(packetinfo, node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a, (char *)packetinfo->destMac);
		//analyse_aol(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a, packetinfo->destMac);
		break;
	case 0x12:
		analyse_hanmail(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x13:
		analyse_139(packetinfo, node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x14:
		analyse_2980(packetinfo, node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x15:
		analyse_189(packetinfo, node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
    case 0x16:
        analyse_12306(packetinfo, node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
// 	case 0x17:
// 		//printf("\n analyse aliyun\n");
// 		analyse_aliyun(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
// 		break;

	//webmail in phone
	case 0x81:
		analyse_m_163(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	case 0x82:
		analyse_m_qq(node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);
		break;
	
	case 0x83://lihan  sohu_m_mail
		analyse_m_sohu(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);  
		break;
	
	case 0x84://lihan  sina_m_mail
		analyse_m_sina(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);  
		break;
		
	case 0x85://lihan  189_m_mail
		analyse_m_189(packetinfo,node, packetinfo->body, packetinfo->bodyLen, packetinfo->tcp, is_to_s, m_or_a);  
		break;
	}

	return 1;
}


