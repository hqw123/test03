/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : airline.cpp
*
* Module : libanalyzeServer.so
*
* Description:  the file for analyzing airline website
*  
* Evolution( Date | Author | Description ) 
* 2017.05.26 | zhangzm | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#include <arpa/inet.h>

#include "airline.h"
#include "db_data.h"
#include "clue_c.h"
#include "cJSON.h"

/****************************************************************************
Function Name:           airline
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
airline::airline()
{
    m_orderid = "";
    m_origin_city = "";
    m_dest_city = "";
    m_origin_airport = "";
    m_dest_airport = "";
    m_begin_time = "";
    m_end_time = "";
    m_flightNO = "";
    m_contact_name = "";
    m_contact_mail = "";
    m_contact_telephone = "";
    m_contact_mobile_phone = "";

    m_order_time = 0;
    m_passenger_count = 0;

    m_passenger = NULL;
    
    m_request_packet.header = NULL;
    m_response_packet.header = NULL;

    m_request_packet.body = NULL;
    m_response_packet.body = NULL;

    memset(&m_request_packet, 0, sizeof(struct packet_info));
    memset(&m_response_packet, 0, sizeof(struct packet_info));
}

/****************************************************************************
Function Name:           ~airline
Input Parameters:        void
Output Parameters:       void
Return Code:             void
Description:             
****************************************************************************/
airline::~airline()
{
    if (m_passenger)
    {
        delete[] m_passenger;
        m_passenger = NULL;
    }

    if (m_request_packet.header)
    {
        free(m_request_packet.header);
        m_request_packet.header = NULL;
    }

    if (m_response_packet.header)
    {
        free(m_response_packet.header);
        m_response_packet.header = NULL;
    }

    if (m_request_packet.body)
    {
        free(m_request_packet.body);
        m_request_packet.body = NULL;
    }

    if (m_response_packet.body)
    {
        free(m_response_packet.body);
        m_response_packet.body = NULL;
    }
}

/****************************************************************************
Function Name:           store_db
Input Parameters:        type
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
void airline::store_db()
{
    //printf("----print store_db.\n");

    //store data to DB
    int i = 0;
    u_int clueId = 0;
    struct in_addr addr;
    
    addr.s_addr = m_request_packet.saddr;
    clueId = get_clue_id(m_request_packet.src_mac, inet_ntoa(addr));
    
    AIRLINE_T tmp_data;
    memset(&tmp_data, 0, sizeof(tmp_data));

    tmp_data.p_data.clueid = clueId;
    tmp_data.p_data.readed = 0;
        
    strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
    strncpy(tmp_data.p_data.clientMac, m_request_packet.src_mac, 17);
    sprintf(tmp_data.p_data.clientPort, "%d", m_request_packet.sport);
    addr.s_addr = m_request_packet.daddr;
    strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
    sprintf(tmp_data.p_data.serverPort, "%d", m_request_packet.dport);
    tmp_data.p_data.captureTime = m_request_packet.capture_time;
    
    strncpy(tmp_data.origin_city, m_origin_city.c_str(), 39);
    strncpy(tmp_data.dest_city, m_dest_city.c_str(), 39);
    strncpy(tmp_data.origin_airport, m_origin_airport.c_str(), 39);
    strncpy(tmp_data.dest_airport, m_dest_airport.c_str(), 39);
    strncpy(tmp_data.begin_time, m_begin_time.c_str(), 19);
    strncpy(tmp_data.end_time, m_end_time.c_str(), 19);
    strncpy(tmp_data.flightNO, m_flightNO.c_str(), 19);
    strncpy(tmp_data.contactName, m_contact_name.c_str(), 19);
    strncpy(tmp_data.contactMobilephone, m_contact_mobile_phone.c_str(), 19);
    strncpy(tmp_data.contactTelephone, m_contact_telephone.c_str(), 19);
    strncpy(tmp_data.contactMail, m_contact_mail.c_str(), 39);
    strncpy(tmp_data.orderID, m_orderid.c_str(), 39);

    tmp_data.order_time = m_order_time;
    tmp_data.p_data.proType = m_type;
    tmp_data.p_data.deleted = 0;

    if (m_passenger_count > 0)
    {
        for (i = 0;i < m_passenger_count;i++)
        {
            strncpy(tmp_data.passengerName, m_passenger[i].name.c_str(), 19);
            strncpy(tmp_data.passengerCertNO, m_passenger[i].certNo.c_str(), 29);

            msg_queue_send_data(AIRLINE, (void *)&tmp_data, sizeof(tmp_data));
        }
    }
    else
    {
        strcpy(tmp_data.passengerName, "");
        strcpy(tmp_data.passengerCertNO, "");
        
        msg_queue_send_data(AIRLINE, (void *)&tmp_data, sizeof(tmp_data));
    }
}

/****************************************************************************
Function Name:           update_db
Input Parameters:        type
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
void airline::update_db()
{
    //printf("----print update_db.\n");

    //update db
    u_int clueId = 0;
    struct in_addr addr;

    addr.s_addr =  m_request_packet.saddr;
    clueId = get_clue_id(m_request_packet.src_mac, inet_ntoa(addr));
    
    COMMON_UPDATE_T tmp_update;
    memset(&tmp_update, 0, sizeof(COMMON_UPDATE_T));

    tmp_update.clueid = clueId;
    sprintf(tmp_update.update_sql, "update AIRLINE set ORIGINCITY='%s',DESTCITY='%s',ORIGINAIRPORT='%s',\
DESTAIRPORT='%s',BEGINTIME='%s',ENDTIME='%s',FLIGHTNO='%s' where ORDERID='%s' and TYPE=%d", 
    m_origin_city.c_str(), m_dest_city.c_str(), m_origin_airport.c_str(), m_dest_airport.c_str(),
    m_begin_time.c_str(), m_end_time.c_str(), m_flightNO.c_str(), m_orderid.c_str(), m_type);

    msg_queue_send_data(COMMON_UPDATE, (void *)&tmp_update, sizeof(tmp_update));
}

/****************************************************************************
Function Name:           get_szx_passengers_info
Input Parameters:        json_data
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             analyse all passengers info from shenzhenair
****************************************************************************/
int airline::get_szx_passengers_info(const char *json_data)
{
    cJSON *root = NULL;
    cJSON *node = NULL, *node1 = NULL, *node2 = NULL;

    if (!json_data)
        return -1;
    
    root = cJSON_Parse(json_data);
    if (!root)
        return -1;

    node = cJSON_GetObjectItem(root, "passengerList");
    if (node)
    {
        if (node->type == cJSON_Array)
        {
            m_passenger_count = cJSON_GetArraySize(node);
            if (m_passenger_count > 0)
            {
                int tmp_size = m_passenger_count;
                m_passenger = new passenger_info[m_passenger_count];

                while (tmp_size--)
                {
                    node1 = cJSON_GetArrayItem(node, tmp_size);
                    if (node1->type == cJSON_Object)
                    {
                        node2 = cJSON_GetObjectItem(node1, "psgrName");
                        if (node2)
                            m_passenger[tmp_size].name = node2->valuestring;

                        node2 = cJSON_GetObjectItem(node1, "certNo");
                        if (node2)
                            m_passenger[tmp_size].certNo = node2->valuestring;
                    }

                }
            }
            else
            {
                cJSON_Delete(root);
                return -1;
            }
        }
    }

    node = cJSON_GetObjectItem(root, "contactName");
    if (node)
        m_contact_name = node->valuestring;

    node = cJSON_GetObjectItem(root, "contactTelphone");
    if (node)
        m_contact_telephone = node->valuestring;

    node = cJSON_GetObjectItem(root, "contactEmail");
    if (node)
        m_contact_mail = node->valuestring;

    node = cJSON_GetObjectItem(root, "contactMobile");
    if (node)
        m_contact_mobile_phone = node->valuestring;

    cJSON_Delete(root);
    
    return 0;
}

/****************************************************************************
Function Name:           szx_post_process
Input Parameters:        is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             get info of all passengers and order id
****************************************************************************/
int airline::szx_post_process(bool is_from_server)
{
    char *json_data = NULL;
    unsigned int json_len = 0;

    if (false == is_from_server)
    {
        //deal POST request data, get info of all passengers 
        if (NULL == m_request_packet.body)
            return -1;

        //the length of "passengerJson=" is 14
        if (0 == strncmp(m_request_packet.body, "passengerJson=", 14))
        {
            json_len = (m_request_packet.bodyLen - 14)*2;
            json_data = (char *)calloc(1, json_len);
            if (!json_data)
                return -1;
        
            url_decode(m_request_packet.body + 14, m_request_packet.bodyLen - 14, json_data, json_len);
            get_szx_passengers_info(json_data);
            
            free(json_data);
            json_data = NULL;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        //deal POST response data, get order id, then store db
        if (!m_response_packet.body)
            return -1;
        
        cJSON *root = NULL, *node = NULL;
        root = cJSON_Parse(m_response_packet.body);
        if (!root)
            return -1;

        node = cJSON_GetObjectItem(root, "orderNo");
        if (node)
            m_orderid = node->valuestring;
        else
            m_orderid = "";

        cJSON_Delete(root);
        m_order_time = m_response_packet.capture_time;
        m_type = AIRLINE_TYPE + SZX_AIRLINE;
        store_db();
        
        return 1;
    }

    return 0;
}

/****************************************************************************
Function Name:           szx_get_process
Input Parameters:        is_from_server
Output Parameters:       void
Return Code:             -1:error, 0:success but not finish, 1:success and deal finish
Description:             deal GET request data, get info of airline
****************************************************************************/
int airline::szx_get_process(bool is_from_server)
{
    //deal GET request data, get info of airline
    char *p1 = NULL;
    char *p2 = NULL;
    unsigned int p_len = 0;

    if (false == is_from_server)
    {
        if (!m_request_packet.header)
            return -1;

        p1 = strstr(m_request_packet.header, "gsorderid=");
        if (p1)
        {
            p1 += strlen("gsorderid=");
            p2 = strstr(p1, "&");
            if (p2)
            {
                m_orderid.assign(p1, p2-p1);
            }

            p2 = strstr(p1, "HTTP/1.");
            if (p2)
            {
                unsigned int tmp_len = (p2 - p1)*2;
                char *tmp_data = (char *)calloc(1, tmp_len);
                url_decode(p1, p2 - p1, tmp_data, tmp_len);

                p1 = strstr(tmp_data, "name::");
                if (p1)
                {
                    // get origin city and airport
                    p1 += strlen("name::");
                    p2 = strstr(p1, "-");
                    if (p2)
                    {
                        m_origin_city.assign(p1, p2-p1);
                        m_origin_airport.assign(p1, p2-p1);
                    }

                    // get dest city and airport
                    p1 = p2 + 1;
                    p2 = strstr(p1, ",,");
                    if (p2)
                    {
                        m_dest_city.assign(p1, p2-p1);
                        m_dest_airport.assign(p1, p2-p1);
                    }
                }

                p1 = strstr(tmp_data, "sku::");
                if (p1)
                {
                    // get flight number
                    p1 += strlen("sku::");
                    p2 = strstr(p1, "_");
                    if (p2)
                        m_flightNO.assign(p1, p2-p1);

                    // get dest city and airport
                    p1 = p2 + 1;
                    p2 = strstr(p1, ",,");
                    if (p2)
                    {
                        m_begin_time.assign(p1, p2-p1);
                        m_end_time = "";
                    }
                }

                free(tmp_data);
                tmp_data = NULL;
            }
        }
        else
            return -1;

        m_type = AIRLINE_TYPE + SZX_AIRLINE;
        update_db();
    }

    return 1;
}

/****************************************************************************
Function Name:           get_ctrip_passengers_info
Input Parameters:        json_data
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             analyse all passengers info from ctrip
****************************************************************************/
int airline::get_ctrip_passengers_info(const char *json_data)
{
	cJSON *root = NULL;
    cJSON *node = NULL, *node1 = NULL, *node2 = NULL;

    if (!json_data)
        return -1;
    
    root = cJSON_Parse(json_data);
    if (!root)
        return -1;

    node = cJSON_GetObjectItem(root, "Passengers");
    if (node)
    {
        if (node->type == cJSON_Array)
        {
            m_passenger_count = cJSON_GetArraySize(node);
            if (m_passenger_count > 0)
            {
                int tmp_size = m_passenger_count;
                m_passenger = new passenger_info[m_passenger_count];

                while (tmp_size--)
                {
                    node1 = cJSON_GetArrayItem(node, tmp_size);
                    if (node1->type == cJSON_Object)
                    {
                        node2 = cJSON_GetObjectItem(node1, "Name");
                        if (node2)
                            m_passenger[tmp_size].name = node2->valuestring;

                        node2 = cJSON_GetObjectItem(node1, "IDCardNo");
                        if (node2)
                            m_passenger[tmp_size].certNo = node2->valuestring;
                    }

                }
            }
            else
            {
                cJSON_Delete(root);
                return -1;
            }
        }
    }

    node = cJSON_GetObjectItem(root, "Contact");
    if (node)
    {
        if (node->type == cJSON_Object)
        {
            node1 = cJSON_GetObjectItem(node, "Name");
            if (node1)
                m_contact_name = node1->valuestring;

            node1 = cJSON_GetObjectItem(node, "Mobile");
            if (node1)
                m_contact_telephone = node1->valuestring;

            node1 = cJSON_GetObjectItem(node, "Email");
            if (node1)
                m_contact_mail = node1->valuestring;

            node1 = cJSON_GetObjectItem(node, "MobilePhone");
            if (node1)
                m_contact_mobile_phone = node1->valuestring;
        }
    }

    cJSON_Delete(root);
    
    return 0;
}

/****************************************************************************
Function Name:           ctrip_post_process
Input Parameters:        is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             get info of all passengers and order id
****************************************************************************/
int airline::ctrip_post_process(bool is_from_server)
{
    char *json_data = NULL;
    unsigned int json_len = 0;

    if (false == is_from_server)
    {
        //deal POST request data, get info of all passengers 
        if (NULL == m_request_packet.body)
            return -1;
        
        //the length of "requestData=" is 12
        if (0 == strncmp(m_request_packet.body, "requestData=", 12))
        {
            json_len = (m_request_packet.bodyLen - 12)*2;
            json_data = (char *)calloc(1, json_len);
            if (!json_data)
                return -1;
        
            url_decode(m_request_packet.body + 12, m_request_packet.bodyLen - 12, json_data, json_len);
            get_ctrip_passengers_info(json_data);
            
            free(json_data);
            json_data = NULL;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        if (!m_response_packet.header || !m_response_packet.body)
            return -1;
    
        //deal POST response data, get order id, then store db
        if (strstr(m_response_packet.header, "Content-Encoding: gzip"))
        {
            char *dest = NULL;
            int result = decomp_gzip(m_response_packet.body, m_response_packet.bodyLen - 2, &dest);
            if (result == -1 || dest == NULL)
                return -1;
            
            free(m_response_packet.body);
            m_response_packet.body = dest;

            // {"OrderIDs":[3804751033],"ErrorCode":null,"ErrorMsg":"","OperationType":"","ContinuePayExpiryTime":30}
            char *p1 = strstr(m_response_packet.body, "\"OrderIDs\":[");
            char *p2 = NULL;
            if (p1)
            {
                p1 += strlen("\"OrderIDs\":[");
                p2 = strstr(p1, "]");
                if (p2)
                    m_orderid.assign(p1, p2-p1);
            }
            else
            {
                m_orderid.assign("");
            }
        }

        m_order_time = m_response_packet.capture_time;
        m_type = AIRLINE_TYPE + CTRIP_AIRLINE;
        store_db();
        
        return 1;
    }

    return 0;
}

/****************************************************************************
Function Name:           ctrip_get_process
Input Parameters:        is_from_server
Output Parameters:       void
Return Code:             -1:error, 0:success but not finish, 1:success and deal finish
Description:             deal GET request data, get info of airline
****************************************************************************/
int airline::ctrip_get_process(bool is_from_server)
{
    //deal GET request data, get info of airline
    char *p1 = NULL;
    char *p2 = NULL;
    unsigned int p_len = 0;

    if (false == is_from_server)
    {
        if (!m_request_packet.header)
            return -1;
    
        // requestData={"OrderID":3804751033,"AddressType":"PJS","FlightNo":"CZ6940","TakeoffTime":"2017-05-10 20:05:00","ShowMergeMailing":true}
        p1 = strstr(m_request_packet.header, "requestData=");
        if (p1)
        {
            p1 += 12;
            p2 = strstr(p1, "HTTP/1.");
            if (p2)
            {
                unsigned int tmp_len = (p2 - p1)*2;
                char *tmp_data = (char *)calloc(1, tmp_len);
                url_decode(p1, p2 - p1, tmp_data, tmp_len);

                // get order id
                p1 = strstr(tmp_data, "\"OrderID\":");
                if (!p1)
                    return -1;
                
                p1 += strlen("\"OrderID\":");
                p2 = strstr(p1, ",");
                m_orderid.assign(p1, p2-p1);

                // get flight number
                p1 = strstr(tmp_data, "\"FlightNo\":");
                if (!p1)
                    return -1;

                p1 += strlen("\"FlightNo\":") + 1;
                p2 = strstr(p1, "\"");
                m_flightNO.assign(p1, p2 - p1);

                // get time of takeoff
                p1 = strstr(tmp_data, "\"TakeoffTime\":");
                if (!p1)
                    return -1;

                p1 += strlen("\"TakeoffTime\":") + 1;
                p2 = strstr(p1, "\"");
                m_begin_time.assign(p1, p2 - p1);
    
                // get time of arrival
                // ............can not get it
                m_end_time = "";
                
                free(tmp_data);
                tmp_data = NULL;
            }
        }
        else
            return -1;

        // FD_SearchHistorty={"type":"S","data":"S$Îäºº(WUH)$WUH$2017-05-10$ÎÚÂ³Ä¾Æë(URC)$URC"}
        p1 = strstr(m_request_packet.header, "FD_SearchHistorty={");
        if (p1)
        {
            p1 += 19;
            p2 = strstr(p1, "}");
            if (p2)
            {
                unsigned int tmp_len = (p2 - p1)*2;
                char *tmp_buf = (char *)calloc(1, tmp_len);
                if (!tmp_buf)
                    return -1;
                    
                url_decode(p1, p2 - p1, tmp_buf, tmp_len);
                char *tmp_data = (char *)calloc(1, tmp_len);
                if (!tmp_data)
                    return -1;

                unicode_to_utf8(tmp_buf, tmp_len, tmp_data, tmp_len);

                // get origin city
                p1 = strstr(tmp_data, "$");
                if (!p1)
                    return -1;
                
                p1 += 1;
                p2 = strstr(p1, "$");
                m_origin_city.assign(p1, p2-p1);

                // get origin airport
                p1 = p2 + 1;
                p2 = strstr(p1, "$");
                m_origin_airport.assign(p1, p2-p1);

                // get dest city
                p1 = p2 + 1;
                p2 = strstr(p1, "$");
                p1 = p2 + 1;
                p2 = strstr(p1, "$");
                m_dest_city.assign(p1, p2-p1);

                // get dest airport
                p1 = p2 + 1;
                p2 = strstr(p1, "\"");
                m_dest_airport.assign(p1, p2-p1);

                free(tmp_buf);
                free(tmp_data);
                tmp_data = NULL;
            }
        }
        else
            return -1;

        m_type = AIRLINE_TYPE + CTRIP_AIRLINE;
        update_db();
    }

    return 1;
}

/****************************************************************************
Function Name:           deal_ctrip_data
Input Parameters:        action_type, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int airline::deal_ctrip_data(unsigned short action_type, bool is_from_server)
{
    int ret = -1;

    switch (action_type)
    {
        case 0x10:
            ret = ctrip_post_process(is_from_server);
            break;
            
        case 0x11:
            ret = ctrip_get_process(is_from_server);
            break;
            
        default:
            break;
    }

    return ret;
}

/****************************************************************************
Function Name:           deal_szx_data
Input Parameters:        action_type, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int airline::deal_szx_data(unsigned short action_type, bool is_from_server)
{
    int ret = -1;

    switch (action_type)
    {
        case 0x10:
            ret = szx_post_process(is_from_server);
            break;
            
        case 0x11:
            ret = szx_get_process(is_from_server);
            break;
            
        default:
            break;
    }

    return ret;
}

/****************************************************************************
Function Name:           analyse_airline_data
Input Parameters:        type, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             
****************************************************************************/
int airline::analyse_airline_data(unsigned short type, bool is_from_server)
{
    int ret = -1;
    unsigned short b_type = (type&0xff00) >> 8;
    unsigned short c_type = type&0xff;
    
    switch (b_type)
    {
        case CTRIP_AIRLINE:
            ret = deal_ctrip_data(c_type, is_from_server);
            break;

        case SZX_AIRLINE:
            ret = deal_szx_data(c_type, is_from_server);
            break;

        default:
            break;
    }

    return ret;
}

/****************************************************************************
Function Name:           deal_packet_process
Input Parameters:        type, pktinfo, is_from_server
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             main function of airline
****************************************************************************/
int airline::deal_packet_process(unsigned short type, struct PacketInfo* pktinfo, bool is_from_server)
{
    int combine_result = -1;
    int ret = -1;

    if (is_from_server)
    {
        // combine packets of server to client.
        combine_result = rebuilt_packet(&m_response_packet, pktinfo->body, pktinfo->bodyLen);
        if (1 == combine_result)
        {
            set_packet_base_info(&m_response_packet, pktinfo);
            ret = analyse_airline_data(type, is_from_server);
        }
        else
            ret = combine_result;
    }
    else
    {
        // combine packets of client to server.
        combine_result = rebuilt_packet(&m_request_packet, pktinfo->body, pktinfo->bodyLen);
        if (1 == combine_result)
        {
            set_packet_base_info(&m_request_packet, pktinfo);
            ret = analyse_airline_data(type, is_from_server);
        }
        else
            ret = combine_result;
    }

    return ret;
}


