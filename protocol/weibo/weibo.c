#include "weibocommon.h"
#include "weibo.h"

int analyse_webwb(void * tmp, PacketInfo * packetInfo, int is_to_s);

int ofo_func_2_2(OFOC_t tofo, PIRS_t trset, void *node, PacketInfo *packetInfo, int is_to_s, int (*callback)(void *node, PacketInfo *packetInfo, int is_to_s))
{
    int result = 0;
    unsigned int f=registerPacketInfo(tofo,trset,packetInfo);
	if(f&0x0f)
		result = callback(node, packetInfo, is_to_s);
	if(f&0xf0)
	{
		while(resultSetNext(trset,packetInfo))
		{
			result = callback(node, packetInfo, is_to_s);
		}
		clearResultSet(trset);
	}
	if(0 != result) 
        unregisterPacketInfo(tofo,packetInfo);
    return result;
}

int wb_type(PacketInfo *packetinfo)
{
    unsigned short int type = 0x00;
    char *data = packetinfo->body;

    if (TCP == packetinfo->pktType)
    {
       /*http*/
        if( packetinfo->srcPort == 80 || packetinfo->destPort == 80 || packetinfo->srcPort == 8080 || packetinfo->destPort == 8080)	
        {     
            if (0 != strncmp(data, "GET", 3) && 0!=strncmp(data, "POST", 4))
                return 0;
            /*sina weibo*/
            if (!strncmp(data, "POST /sso/login.php?client=ssologin.js", 38))
                type = 0x0101;
            else if (!strncmp(data, "GET /logout.php?backurl=/ HTTP/1.1", 34))
                type = 0x0106;
            else if (!strncmp(data, "POST /aj/mblog/add?_wv=5&__rnd=", 31))//guangbo
                type = 0x0111;
            else if (!strncmp(data, "POST /aj/mblog/forward?_wv=5&__rnd=", 35))//zhuanfa
                type = 0x0112;
            else if (!strncmp(data, "POST /aj/comment/add?_wv=5&__rnd=", 33))//pinglun
                type = 0x0113;
            else if (!strncmp(data, "GET /im?jsonp=parent.org.cometd.script._callback", 48))//sixin
                type = 0x0114;
            else if (!strncmp(data, "POST /aj/message/add?_wv=5&__rnd=",33))//sixin
                type = 0x0115;
            else if (!strncmp(data, "GET /do_not_delete/fc.html?pids=", 32))//delete pic
                type = 0x0131;
            else if (!strncmp(data, "POST /interface/pic_upload.php?", 31))
                type = 0x0151;//up_pic
            else if (!strncmp(data, "POST /2/mss/upload.json?source=", 31))
                type = 0x0152;//up_pic
            else if (!strncmp(data, "POST /aj/mblog/add?ajwvr=6&__rnd=", 33))//guangbo  lihan 2017.2.15
                type = 0x0121;
            else if (!strncmp(data, "POST /aj/message/add?ajwvr=6&__rnd=",35))//sixin  lihan 2017.2.15
                type = 0x0122;    
            else if (!strncmp(data, "POST /aj/v6/comment/add?ajwvr=6&__rnd=",38))//pinglun  lihan 2017.2.15
                type = 0x0123;
        	/*tencent weibo*/
            else if (!strncmp(data, "GET /jump?clientuin=", 20))//login
                type = 0x0201;
            else if (!strncmp(data, "GET /login?ptlang=", 18))//login
                type = 0x0202;
            else if (!strncmp(data, "GET /logout.php HTTP/1.1", 24))
                type = 0x0206;
            else if (!strncmp(data, "POST /old/publish.php HTTP/1.1", 30))
                type = 0x0211;
            else if (!strncmp(data, "POST /inbox/pm_mgr.php HTTP/1.1", 31))//sixin
                type = 0x0212;
            else if (!strncmp(data, "POST /asyn/uploadpicCommon.php", 30)||!strncmp(data, "POST /asyn/updateGrabPic.php?rand=", 34))
                type = 0x0251;
            else if (!strncmp(data, "POST /inbox/pm_uploadimg.php HTTP/1.1", 37))
                type = 0x0252;

			// added by jacky tencent weibo(mobile)
			// publish, comment, distinguish it with the  "postType" in the msg
			// postType:0, publish; 4, comment; 2, forward;
			// NOTE: all test on android 4.4.4 with the newest app client
			else if (!strncmp(data, "POST /cbdata/api/publishMessage HTTP/1.1", 40))
				type = 0x0203;
			else if (!strncmp(data, "POST /cbdata/api/publishPrivateMsg HTTP/1.1", 43))
				type = 0x0204;
			// follow type: 1, follow; 2, unfollow
			else if (!strncmp(data, "POST /cbdata/api/setFollow HTTP/1.1", 35))
				type = 0x0205;
			
			// weibo 163 no longer exists any more, remove it by jacky Fri Feb 24 23:14:04 PST 2017
#if 0
         /*163 weibo*/
            else if (!strncmp(data, "GET /httpLoginVerifyNew.jsp?", 28))
                type = 0x0301;
            else if (!strncmp(data, "GET /Logout.jsp?username=", 25))
                type = 0x0306;
            else if (!strncmp(data, "POST /tweet.do?action=addTweet HTTP/1.1", 39))
                type = 0x0311;
            else if (!strncmp(data, "POST /message.do?action=sendMessage HTTP/1.1", 44))
                type = 0x0312;
            else if (!strncmp(data, "POST /textToImage.do HTTP/1.1", 29))
                type = 0x0313;
            else if (!strncmp(data, "POST /upload HTTP/1.1", 21))
                type = 0x0351;
#endif
        }
        else
            return 0;
    }
    else
    {
        return 0;
    }
     
  //   free(data);
    return type;
 } 

int analyse_wb(PacketInfo *packetinfo)
{
    if (TCP != packetinfo->pktType || 0 == packetinfo->bodyLen)
        return -1;
	
    WbNode *wb_node = NULL;
    static int init_flag = 0;
    int is_to_s, result;
    unsigned short type, tmp_type;
    void *node = NULL;

    if (!init_flag)
    {
    	result = wb_init();
    	if (result == -1)
    		return -1;
    	init_flag = 1;
    }
          
    unsigned short packet_type = wb_type(packetinfo);

    wb_node = find_WbNode(packetinfo, &is_to_s);
    if (wb_node != NULL)
    {
    	node = wb_node;
    	type  = wb_node->type;
    }

    if (wb_node == NULL) 
    {
    	type = packet_type;
    	if (type <= 0) 
    	{
    		return -1;
    	}
    	
		WbNode *wb_node = insert_WbNode(packetinfo);
		if (wb_node == NULL)
        {     
            return -1;
        }
        is_to_s = 0;
        wb_node->type   = type;
	    node = wb_node;
    	
    }
	
    if (NULL == node)
        return -1;
	
    //return ofo_func_2_2(ofo, rset, node, packetinfo, is_to_s, analyse_webwb);
    return analyse_webwb(node, packetinfo, is_to_s);
}

void write_data(char *src, int srcLen, char **dest, int *destLen)
{
    if (NULL == src || NULL == dest)
        return ;
    
    if (NULL == *dest)
        *dest = (char *)malloc(srcLen + 1);
    else
        *dest = (char *)realloc(*dest, *destLen + srcLen + 1);
    
    memcpy(*dest+*destLen, src, srcLen);
    *destLen += srcLen;
    (*dest)[*destLen] = 0;
}

int analyse_webwb(void * tmp, PacketInfo * packetInfo, int is_to_s)
{
    if (NULL == tmp)
        return -1;
    
    WbNode *node = (WbNode *)(tmp);
    if (1 == node->is_complished)
        return -1;

    if (0 == is_to_s)
        write_data(packetInfo->body, packetInfo->bodyLen, &node->data, &node->dataLen);
    else
    {
        node->is_complished = http_recive(node, packetInfo->body, packetInfo->bodyLen);
        if (node->header && 0==node->sent_time[0])
            wb_get_time(node->header, node->sent_time);
    }

    int result = 0;  
    unsigned short  type = node->type>>8;
    switch (type) 
    {
        case 0x01:
            node->urltype = 1501;
            result = analyse_SinaWb(node, packetInfo, is_to_s);
            break;
        case 0x02:
            node->urltype = 1502;
            result = analyse_QQWb(node, packetInfo, is_to_s);
            break;
#if 0
        case 0x03:
            node->urltype = 1503;
            result = analyse_M163Wb(node, packetInfo, is_to_s);
            break;
#endif
        default:
            break;
    }

    switch (result)
    {
        case 1: 
            node->is_complished = 1;
            //output_wb(node);
            write_wb_sql(node);
            del_WbNode(node);
            break;
        case -1: 
            del_WbNode(node);
            break;
        case -2: 
            node->is_complished = 1;
            free_node(node);
            break;
        default:
            break;
    }
    
    return result;
}


