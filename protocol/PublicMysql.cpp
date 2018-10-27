//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BAIHONG Software CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     PublicMysql.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class PublicMysql.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101021  wu zhonghua Initial
//
//------------------------------------------------------------------------
#include "PublicMysql.h"

extern const char * server;
extern const char * database;
extern const char * user;
extern const char * password;

MySQL::MySQL()
{
	isConnected=false;
	conn = mysql_init(NULL);
	/* Connect to database */ 
	if (!mysql_real_connect(conn, server,user, password, database, 0, NULL, 0))
	{ 
		fprintf(stderr, "mysql error %d:%s\n", mysql_errno(conn),mysql_error(conn)); 
	} 
	else
	{
		isConnected=true;
	}

	mysql_query(conn,"SET NAMES utf8");

	//mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8"); 
	/* //send SQL query 
	if (mysql_query(conn, "show tables")) 
	{ 
		fprintf(stderr, "mysql error %d:%s\n", mysql_errno(conn),mysql_error(conn)); 
		//exit(1); 
	} 

	res = mysql_use_result(conn);

	//output table name 
	printf("MySQL Tables in mysql database:\n"); 
	while ((row = mysql_fetch_row(res)) != NULL)
		printf("%s \n", row[0]);

	// close connection  
	mysql_free_result(res);*/


}

MySQL::~MySQL()
{
	mysql_close(conn);
}

bool MySQL::Insert(string * sql)
{
	if(isConnected==false)
		return false;
	int res;
	res=mysql_query(conn,sql->c_str());
	if(res)
	{
		fprintf(stderr,"Insert error %d: %s\n",mysql_errno(conn),mysql_error(conn));
		return false;
	}
	
	return true;
}

MYSQL_RES * MySQL::Select(string * sql)
{
	MYSQL_RES * pRes;
	int result = mysql_query(conn, sql->c_str());
	if(result)
	{
		fprintf(stderr, "select error %d:%s\n", mysql_errno(conn), mysql_error(conn));
		pRes = NULL;
	}
	else
	{
		pRes = mysql_store_result(conn);
	}
	
	return pRes;
}

void MySQL::RelSql(MYSQL_RES * pRes)
{
	mysql_free_result(pRes);
}

// End of file
