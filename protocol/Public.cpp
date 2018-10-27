//------------------------------------------------------------------------
// LZ Monitor System is a sniffer to get evidences on Internet.
//
// Copyright (C) 2010 BAIHONG Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name:     Public.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class Public.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101108 tianzhao    Initial
// $d1= -------- 1.0  001 101119 wuzhonghua  AddCheckEnvironment
// $d2= -------- 1.0  001 101202 zwj add parameters C_PROXY_ETH xproxyEth	
//
//------------------------------------------------------------------------
#include "Public.h"
#include "PublicDb.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <libxml/parser.h>
#include <iostream>
using namespace std;

//for connect mysql DB
const char * server = "127.0.0.1";
const char * database = "test";
const char * user = "root";
const char * password = "yitian@wh027";
const char * A_OUT_ETH = "eth0";
const char * B_IN_ETH = "eth0";
const char * C_PROXY_ETH= "eth0";

const char * SSL_RUN="0";
const char*  SSL_DOMAIN_NAME="server.test.com";
const char*  SSL_PROXY_MODE="local";
int	AnlyzerStatus=1;
const char * lzDataPath = "/home";
const char * lzWebCfgPath = "/usr/local/tomcat/webapps/Sword/spy";


//-----------------------------------------------------------------------
// Func Name   : Public
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
Public::Public()
{
	m_special_ip.assign("127.0.0.1");
	m_flood_ip.assign("127.0.0.1");
}


//-----------------------------------------------------------------------
// Func Name   : ~Public
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
Public::~Public()
{
	
}

/*-----------------------------------------------------------------------
Func Name   : get_special_server_ip
Description : get special server ip address.
Parameter   : NULL
Return      : m_special_ip
-----------------------------------------------------------------------*/
string Public::get_special_server_ip()
{
	return m_special_ip;
}

/*-----------------------------------------------------------------------
Func Name   : get_flood_server_ip
Description : get flood server ip address.
Parameter   : NULL
Return      : m_flood_ip
-----------------------------------------------------------------------*/
string Public::get_flood_server_ip()
{
	return m_flood_ip;
}

/*-----------------------------------------------------------------------
Func Name   : get_log_level
Description : get log output level.
Parameter   : NULL
Return      : m_log_level
-----------------------------------------------------------------------*/
int Public::get_log_level()
{
	return m_log_level;
}

/*-----------------------------------------------------------------------
Func Name   : read_config
Description : Read Config from /spy/config/capConfig.xml.
Parameter   : NULL
Return      : bool
-----------------------------------------------------------------------*/
bool Public::read_config()
{
	const char* configfile = "/spy/config/capConfig.xml";
	if(::access(configfile, F_OK) != 0)
	{
		LOG_ERROR("DeviceInfo.xml not exist!\n");
		return false;
	} 

	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if (!doc) 
	{
		LOG_ERROR("Read configure file failed!\n");
		return false;
	}
	curNode = xmlDocGetRootElement(doc);
	if (!curNode) 
	{
		LOG_ERROR("Empty configure file!\n");
		xmlFreeDoc(doc);
		return false;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST "config")) 
	{
		LOG_ERROR("Root node error!\n");
		xmlFreeDoc(doc);
		return false;
	}

	xmlChar* special_server_ip = NULL;
	xmlChar* flood_server_ip = NULL;
	itemNode = curNode->xmlChildrenNode;
	while (itemNode) 
	{
		if (itemNode->type != XML_ELEMENT_NODE) 
		{
			itemNode = itemNode->next;
			continue;
		}
		
		if (!xmlStrcmp(itemNode->name, BAD_CAST "special_ip"))
		{
			special_server_ip = xmlNodeGetContent(itemNode);
			m_special_ip.assign((const char *)special_server_ip);
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "flood_ip"))
		{
			flood_server_ip = xmlNodeGetContent(itemNode);
			m_flood_ip.assign((const char *)flood_server_ip);
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "log_level"))
		{
			xmlChar* tmp_value = xmlNodeGetContent(itemNode);
			m_log_level = atoi((const char*)tmp_value);
			xmlFree(tmp_value);
		}

		itemNode = itemNode->next;
	}	

	xmlFree(special_server_ip);
	xmlFree(flood_server_ip);
	xmlFreeDoc(doc);
	return true;
}

//-----------------------------------------------------------------------
// Func Name   : ReadConfig
// Description : Read Config form "/LzSystem/DeviceInfo.xml".
// Parameter   : NULL
// Return      : bool
//-----------------------------------------------------------------------
bool Public::ReadConfig()
{
	const char* configfile = "/spy/config/sslConfig.xml";
	if(::access(configfile, F_OK) != 0)
	{
		//cout<<"DeviceInfo.xml not exist!"<<endl;
		LOG_ERROR("DeviceInfo.xml not exist!\n");
		return false;
	} 
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if (!doc) 
	{
		LOG_ERROR("Read configure file failed!\n");
		return false;
	}
	curNode = xmlDocGetRootElement(doc);
	if (!curNode) 
	{
		LOG_ERROR("Empty configure file!\n");
		xmlFreeDoc(doc);
		return false;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST "config")) 
	{
		LOG_ERROR("Root node error!\n");
		xmlFreeDoc(doc);
		return false;
	}
// 	xmlChar* xdbServer = NULL;
// 	xmlChar* xdatabase = NULL;
// 	xmlChar* xdbUser = NULL;
// 	xmlChar* xdbPassword = NULL;
// 	xmlChar* xoutEth = NULL;
// 	xmlChar* xinEth = NULL;
	xmlChar* xproxyEth =NULL;
	xmlChar* xsslRun=NULL;
	xmlChar* xsslDname=NULL;
	xmlChar* xsslPmode=NULL;
// 	xmlChar* xanlyzerStatus = NULL;
// 	xmlChar* xlzDataPath = NULL;
// 	xmlChar* xlzWebCfgPath = NULL;
	itemNode = curNode->xmlChildrenNode;
	while (itemNode) 
	{
		if (itemNode->type != XML_ELEMENT_NODE) 
		{
			itemNode = itemNode->next;
			continue;
		}
		/*if (!xmlStrcmp(itemNode->name, BAD_CAST "dbServer")) 
		{
			xdbServer = xmlNodeGetContent(itemNode);
			server = (const char *)xdbServer;				
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "database")) 
		{
			xdatabase = xmlNodeGetContent(itemNode);
			database = (const char *)xdatabase;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbUser"))
		{
			xdbUser = xmlNodeGetContent(itemNode);
			user =  (const char *)xdbUser;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbPassword")) 
		{
			xdbPassword = xmlNodeGetContent(itemNode);			
			password = (const char *)xdbPassword;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "outEth")) 
		{
			xoutEth = xmlNodeGetContent(itemNode);
			A_OUT_ETH= (const char *)xoutEth;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "inEth")) 
		{
			xinEth = xmlNodeGetContent(itemNode);
			B_IN_ETH= (const char *)xinEth;
		}
		else */if (!xmlStrcmp (itemNode->name, BAD_CAST "sslEth"))
		{
			xproxyEth = xmlNodeGetContent(itemNode);
			C_PROXY_ETH=(const char *)xproxyEth;
		} 
		else if (!xmlStrcmp (itemNode->name, BAD_CAST "sslSwitch"))
		{
			xsslRun = xmlNodeGetContent(itemNode);
			SSL_RUN=(const char *)xsslRun;
		} 
		else if (!xmlStrcmp (itemNode->name, BAD_CAST "sslDomain"))
		{
			xsslDname = xmlNodeGetContent(itemNode);
			SSL_DOMAIN_NAME=(const char *)xsslDname;
		} 
		else if (!xmlStrcmp (itemNode->name, BAD_CAST "sslMode"))
		{
			xsslPmode = xmlNodeGetContent(itemNode);
			SSL_PROXY_MODE=(const char *)xsslPmode;
		} 
		/*else if (!xmlStrcmp(itemNode->name, BAD_CAST "anlyzerStatus")) 
		{
			xanlyzerStatus = xmlNodeGetContent(itemNode);
			const char * tmpStatus= (const char *)xanlyzerStatus;
			AnlyzerStatus= atoi(tmpStatus);
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "lzDataPath")) 
		{
			xlzDataPath = xmlNodeGetContent(itemNode);
			lzDataPath = (const char *) xlzDataPath;
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "lzWebCfgPath")) 
		{
			xlzWebCfgPath = xmlNodeGetContent(itemNode);
			lzWebCfgPath = (const char *) xlzWebCfgPath;
		}	*/	
		itemNode = itemNode->next;
	}	
	xmlFreeDoc(doc);
	return true;
}
bool Public::ReadSysConfig()
{
	const char* configfile = "/spy/config/systemConfig.xml";
	if(::access(configfile, F_OK) != 0)
	{
		//cout<<"DeviceInfo.xml not exist!"<<endl;
		LOG_ERROR("DeviceInfo.xml not exist!\n");
		return false;
	} 
	xmlDocPtr doc = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr itemNode = NULL;
	doc = xmlReadFile(configfile, "UTF-8", XML_PARSE_RECOVER);
	if (!doc) 
	{
		//fprintf(stderr, "Read configure file failed!\n");
		LOG_ERROR("Read configure file failed!\n");
		return false;
	}
	curNode = xmlDocGetRootElement(doc);
	if (!curNode) 
	{
		//fprintf(stderr, "Empty configure file!\n");
		LOG_ERROR("Empty configure file!\n");
		xmlFreeDoc(doc);
		return false;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST "config")) 
	{
		//fprintf(stderr, "Root node error!\n");
		LOG_ERROR("Root node error!\n");
		xmlFreeDoc(doc);
		return false;
	}
// 	xmlChar* xdbServer = NULL;
// 	xmlChar* xdatabase = NULL;
// 	xmlChar* xdbUser = NULL;
// 	xmlChar* xdbPassword = NULL;
	xmlChar* xoutEth = NULL;
	xmlChar* xinEth = NULL;
	xmlChar* xanlyzerStatus = NULL;
// 	xmlChar* xlzDataPath = NULL;
// 	xmlChar* xlzWebCfgPath = NULL;
// 	xmlChar* xlanguage = NULL;
	itemNode = curNode->xmlChildrenNode;
	while (itemNode) 
	{
		if (itemNode->type != XML_ELEMENT_NODE) 
		{
			itemNode = itemNode->next;
			continue;
		}
		/*if (!xmlStrcmp(itemNode->name, BAD_CAST "dbServer")) 
		{
			xdbServer = xmlNodeGetContent(itemNode);
			server = (const char *)xdbServer;				
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "database")) 
		{
			xdatabase = xmlNodeGetContent(itemNode);
			database = (const char *)xdatabase;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbUser"))
		{
			xdbUser = xmlNodeGetContent(itemNode);
			user =  (const char *)xdbUser;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "dbPassword")) 
		{
			xdbPassword = xmlNodeGetContent(itemNode);			
			password = (const char *)xdbPassword;
		} 
		else */if (!xmlStrcmp(itemNode->name, BAD_CAST "TX_ETH")) 
		{
			xoutEth = xmlNodeGetContent(itemNode);
			A_OUT_ETH= (const char *)xoutEth;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "RX_ETH")) 
		{
			xinEth = xmlNodeGetContent(itemNode);
			B_IN_ETH= (const char *)xinEth;
		} 
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "analyzeSwitch")) 
		{
			xanlyzerStatus = xmlNodeGetContent(itemNode);
			const char * tmpStatus= (const char *)xanlyzerStatus;
			AnlyzerStatus= atoi(tmpStatus);
		}
		/*else if (!xmlStrcmp(itemNode->name, BAD_CAST "lzDataPath")) 
		{
			xlzDataPath = xmlNodeGetContent(itemNode);
			lzDataPath = (const char *) xlzDataPath;
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "lzWebCfgPath")) 
		{
			xlzWebCfgPath = xmlNodeGetContent(itemNode);
			lzWebCfgPath = (const char *) xlzWebCfgPath;
		}
		else if (!xmlStrcmp(itemNode->name, BAD_CAST "language")) 
		{
			xlanguage = xmlNodeGetContent(itemNode);
			const char * tmpLanguage= (const char *)xlanguage;
			language= atoi(tmpLanguage);
		}	*/	
		itemNode = itemNode->next;
	}	
	xmlFreeDoc(doc);
	return true;
}

//-----------------------------------------------------------------------
// Func Name   : DbCanConnect
// Description : Test connect to mysql .
// Parameter   : NULL
// Return      : bool ,if sucess connect return true 
//-----------------------------------------------------------------------
bool Public::DbCanConnect()
{
#if 0  //zhangzm
	bool isConnected=false;
	MYSQL *conn;
	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, server,user, password, database, 0, NULL, 0))
	{ 
		fprintf(stderr, "mysql connect error %d:%s\n", mysql_errno(conn),mysql_error(conn)); 
	} 
	else
	{
		mysql_close(conn);
		isConnected=true;
	}
	return isConnected;
#endif

	return PublicDb::get_instance()->get_special_conn_state();
}


//-----------------------------------------------------------------------
// Func Name   : CreateDir
// Description : Create Save data dir.
// Parameter   : NULL
// Return      : bool 
//-----------------------------------------------------------------------
bool Public::CreateDir()
{
	char tmpPath[512]={0};
	if(::access(lzDataPath,F_OK)!=0)
	{		
	//	cout<<"lz DataPath error,Please reset DataPath by DeviceInfo.xml."<<endl;
		LOG_ERROR("lz DataPath error,Please reset DataPath by DeviceInfo.xml.\n");
		return false;	
	}	
	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData");
	if (::access(tmpPath, F_OK) != 0) 
	{
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}

	
	for (int i=0; i<12; i++){		
		sprintf(tmpPath,"%s%s%d",lzDataPath,"/spyData/",i);
		if (::access(tmpPath, F_OK) != 0) 
		{
				::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
		}
	}

	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData/moduleData");
	if (::access(tmpPath, F_OK) != 0) {
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}

	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData/moduleData/smtp");
	if (::access(tmpPath, F_OK) != 0) {
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}
	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData/moduleData/POP3");
	if (::access(tmpPath, F_OK) != 0) {
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}

	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData/moduleData/ftp");
	if (::access(tmpPath, F_OK) != 0) {
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}
	sprintf(tmpPath,"%s%s",lzDataPath,"/spyData/moduleData/pppoe");
	if (::access(tmpPath, F_OK) != 0) {
			::mkdir(tmpPath, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
	}
	return true;
}


//-----------------------------------------------------------------------
// Func Name   : CheckEnvironment
// Description : Public Func runed in main() ,check environment
// Parameter   : NULL
// Return      : bool
//-----------------------------------------------------------------------
bool Public::CheckEnvironment()
{
	bool isReady=false;
	if(ReadConfig())
	{
// 		cout<<"System DeviceInfo ::"<<endl;
// 		cout<<"server = "<<server<<endl;
// 		cout<<"database = "<<database<<endl;
// 		cout<<"user = "<<user<<endl;
// 		cout<<"password = "<<password<<endl;
// 		cout<<"A_OUT_ETH = "<<A_OUT_ETH<<endl;
// 		cout<<"B_IN_ETH = "<<B_IN_ETH<<endl;
// 		cout<<"C_PROXY_ETH = "<<C_PROXY_ETH<<endl;
// 		cout<<"AnlyzerStatus = "<<AnlyzerStatus<<endl;
// 		cout<<"lzDataPath = "<<lzDataPath<<endl;
// 		cout<<"lzWebCfgPath = "<<lzWebCfgPath<<endl;
		if(DbCanConnect())
		{
			if(CreateDir())
			{
				isReady=true;
			}
		}				
	}
	;
	
	return isReady;
}


// End of file


