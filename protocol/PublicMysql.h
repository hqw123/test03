//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2008 BaiHong Software CO.,
//
//------------------------------------------------------------------------
//
// Module Name      :PublicMysql.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class Mysqlcontenter 
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101022 wuzhonghua Initial
//
//------------------------------------------------------------------------

#ifndef MYSQL_OPT_H
#define MYSQL_OPT_H
#include <mysql.h>
#include <stdio.h>
#include <string>
using namespace std;

class MySQL
{
	public:
		MySQL();
		virtual ~MySQL();
		bool Insert(string *sql);
		MYSQL_RES * Select(string * sql);
		void RelSql(MYSQL_RES * pRes);
		
	private:
		MYSQL *conn;
		MYSQL_RES * res;
		MYSQL_ROW row;
		bool isConnected;
		
	//private:
};

#endif

// End of file 
