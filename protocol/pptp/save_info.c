
#include <string.h>
#include <stdio.h>

#include "save_info.h"
#include "db_data.h"

int write_to_database(struct user_struct* user, int release);
int write_to_db(char*user_id, char*ip);
int select_to_db(char*user_id, char*ip);
int insert_to_db(char*user_id, char*ip);
int update_to_db(char*user_id, char*ip);
int update_ip(char *ip);

int save_user_info(struct user_struct* user, int type, int release)
{
	int release2 = 0;
	
	if(type == SAVE_INFO_SQL)
	{
		write_to_database(user, (!release2)&&release);
	}
	
	if(release && release2)
		free(user);
	
	return 0;
}

int write_to_database(struct user_struct* user, int release)
{
	/*write netproxy data to shared memory, by zhangzm*/
	NETPROXY_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = user->objectID;
	tmp_data.p_data.readed = 0;
	strcpy(tmp_data.p_data.clientIp, user->src_ip);
	strncpy(tmp_data.p_data.clientMac, user->src_mac, 17);
	strcpy(tmp_data.p_data.clientPort, user->src_port);
	strcpy(tmp_data.p_data.serverIp, user->dest_ip);
	strcpy(tmp_data.p_data.serverPort, user->dest_port);
	
	tmp_data.p_data.captureTime = user->time;
	strncpy(tmp_data.username, user->id, 49);
    strcpy(tmp_data.proxy_url, "");
    strcpy(tmp_data.real_url, "");
    
	tmp_data.p_data.proType = user->info_type;
	tmp_data.p_data.deleted = 0;
	msg_queue_send_data(NETPROXY, (void *)&tmp_data, sizeof(tmp_data));

	return 0; 
}

int write_to_db(char *user_id, char *ip)
{
	int ret = -1;

	update_ip(ip);
	ret = select_to_db(user_id,ip);
	if (ret < 0)
		return ret;
	
	if (ret)
		update_to_db(user_id,ip);
	else
		insert_to_db(user_id,ip);
	
	return 0; 
}

int update_ip(char *ip)
{
#if 0  //zhangzm
	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return -1;

	time_t  timeVal;
	time(&timeVal);

	char * sql = (char *)malloc(1024 * 64);
	if (!sql)
		return -1;
	memset(sql, 0, 1024 * 64);	

	sprintf(sql, "update allobject set ip = '0.0.0.0',update_time = :update_time where ip = :ip");

	sqlConn_->SetSql(sql);
	sqlConn_->SetTime(1, timeVal);
	sqlConn_->SetString(2, ip);
	sqlConn_->DoSql();
	free(sql);
#endif
	return 0;
}

int select_to_db(char*user_id,char*ip)
{
	//printf("select to db ..........\n");
	int rows = -1;
#if 0  //zhangzm
	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return -1;

	ResultSet* result = NULL;
	char * sql = (char *)malloc(1024 * 64);
	memset(sql, 0, 1024 * 64);
	sprintf(sql,"select count(*) as rowCount from object where pppoe = '%s'", user_id);

	sqlConn_->SetSql(sql);
	result = sqlConn_->DoSqlResult();
	if (result->next())
	{
		rows = result->getInt(1);
		sqlConn_->closeResult(result);
	}
	free(sql);
#endif
	return rows;
}

int insert_to_db(char *user_id,char *ip)
{
#if 0  //zhangzm
	time_t  timeVal;
	time(&timeVal);

	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return -1;

	char * sql = (char *)malloc(1024 * 64);
	if (!sql)
		return -1;
	memset(sql, 0, 1024 * 64);

	sprintf(sql, "insert into ALLOBJECT(id,object_name,pppoe,ip,update_time,all_embed) values(SEQ_ALLOBJECT_ID.nextval,:object_name,:pppoe,:ip,:update_time,:all_embed)");

	sqlConn_->SetSql(sql);
	sqlConn_->SetString(1, user_id);
	sqlConn_->SetString(2, user_id);
	sqlConn_->SetString(3, ip);
	sqlConn_->SetTime(4, timeVal);
	sqlConn_->SetInt(5, 1);
	sqlConn_->DoSql();

	free(sql);
#endif
	return 0; 
}

int update_to_db(char*user_id,char*ip)
{
#if 0  //zhanzgm
	PublicOcci *sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	if (sqlConn_ == NULL)
		return -1;

	time_t  timeVal;
	time(&timeVal);

	char * sql = (char *)malloc(1024 * 64);
	if (!sql)
		return -1;
	memset(sql, 0, 1024 * 64);	

	sprintf(sql, "update allobject set ip = :ip,update_time = :update_time where pppoe = :pppoe");

	sqlConn_->SetSql(sql);
	sqlConn_->SetString(1, user_id);
	sqlConn_->SetTime(2, timeVal);
	sqlConn_->SetString(3, user_id);
	sqlConn_->DoSql();
	free(sql);
#endif
	return 0;
}

