//------------------------------------------------------------------------
// Analser
//
// Copyright (C) 2010 BAIHONG Information Security Techology CO., Ltd.
//
//------------------------------------------------------------------------
//
// Module Name  :  clue.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file define the functions of class clue.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101108 sunjinshuo  Initial
//------------------------------------------------------------------------
#include "clue.h"
#include <string.h>
#include <stdlib.h>

//-----------------------------------------------------------------------
// Func Name   : Clue
// Description : Constructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
Clue::Clue()
{
	sqlConn_ = PublicDb::get_instance()->get_sqlConn_special();
	index = 1;
	mac_index = 1;
	ip_index = 1;

	macnum = 0;
	clueMacnum = 0;
	clueIpnum = 0;
}

//-----------------------------------------------------------------------
// Func Name   : ~Clue
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
Clue::~Clue()
{
}

//-----------------------------------------------------------------------
// Func Name   : get_instance
// Description : Destructor.
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
Clue *Clue::get_instance()
{
	static Clue *public_clue = NULL;

    if (public_clue == NULL)
    {
        public_clue = new Clue();
    }
	
    return public_clue;
}

//-----------------------------------------------------------------------
// Func Name   : MakeStringUp
// Description :
// Parameter   : string& mac
// Return      : void
//-----------------------------------------------------------------------
void Clue::MakeStringUp(string& mac)
{
	char * chr = (char *)mac.c_str();
	int len = strlen(chr), i = 0;
	while(i < len)
	{
		if(chr[i] >= 'a' && chr[i] <= 'f')
		{
			chr[i] -= 32;
		}

		i++;
	}
}

//-----------------------------------------------------------------------
// Func Name   : ShowMapList
// Description :
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void Clue::ShowMapList()
{
	LOG_DEBUG("\n-------- clue info list below --------\n");
	map<int, ELEMTYPE>::iterator iter;
	for(iter = objectMacMap.begin(); iter != objectMacMap.end(); iter++)
	{
#ifdef VPDNLZ
		//cout<<"objectid : "<<iter->second.objectid<<" | mac : "<<iter->second.mac<<" | pppoe : "<<iter->second.pppoe<<endl;
		LOG_INFO("objectid : %d | mac : %s | pppoe : %s\n", iter->second.objectid, iter->second.mac.c_str(), iter->second.pppoe.c_str());
#else
		//cout<<"objectid : "<<iter->second.objectid<<" | mac : "<<iter->second.mac<<endl;
		LOG_INFO("objectid : %d | mac : %s\n", iter->second.objectid, iter->second.mac.c_str());
#endif
	}
	LOG_DEBUG("..\n.\n");
}

//-----------------------------------------------------------------------
// Func Name   : InsertInfo
// Description :
// Parameter   : int nIndex, ELEMTYPE elem
// Return      : void
//-----------------------------------------------------------------------
void Clue::InsertInfo(int nIndex, ELEMTYPE elem)
{
	objectMacMap.insert(map<int, ELEMTYPE>::value_type(nIndex, elem));
}

//-----------------------------------------------------------------------
// Func Name   : UpdateInfo
// Description : 
// Parameter   : ELEMTYPE elem, map<int, ELEMTYPE>::iterator iter
// Return      : void
//-----------------------------------------------------------------------
void Clue::UpdateInfo(ELEMTYPE elem, map<int, ELEMTYPE>::iterator iter)
{
	iter->second.objectid = elem.objectid;
}

//-----------------------------------------------------------------------
// Func Name   : FindInfoByMac
// Description : 
// Parameter   : string mac
// Return      : map<int, ELEMTYPE>::iterator
//-----------------------------------------------------------------------
map<int, ELEMTYPE>::iterator Clue::FindInfoByMac(string mac)
{
	map<int, ELEMTYPE>::iterator iter;
	for(iter = objectMacMap.begin(); iter != objectMacMap.end(); iter++)
	{
#ifdef VPDNLZ
		if(iter->second.pppoe == mac)
			break;
#else
		if(iter->second.mac == mac)
			break;
#endif
	}
	
	return iter;
}

//-----------------------------------------------------------------------
// Func Name   : UpdateObjectMacList
// Description : 
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void Clue::UpdateObjectMacList()
{
	map<int, ELEMTYPE>::iterator iter;
	for(iter = objectMacMap.begin(); iter != objectMacMap.end();)
	{
		int i = 0;
		while(i < macnum)
		{
#ifdef VPDNLZ
			if(maclist[i] == iter->second.pppoe)
				break;
#else
			if(maclist[i] == iter->second.mac)
				break;
#endif
			i++;
		}
		
		if(i == macnum)
		{
			objectMacMap.erase(iter);
			iter = objectMacMap.begin();
		}
		else
		{
			iter++;
		}
	}
}

//-----------------------------------------------------------------------
// Func Name   : GetObjectMacInfo
// Description : 
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void Clue::GetObjectMacList()
{
	ResultSet* result = NULL;
	string sql = "select id, object_mac from allobject";

	sqlConn_->SetSql(sql.c_str());
	result = sqlConn_->DoSqlResult();
	if (result)
	{
		macnum = 0;
		while(result->next())
		{
			ELEMTYPE elem;
			elem.objectid = result->getInt(1);
			string str = result->getString(2);
			MakeStringUp(str);
			elem.mac = str;
			maclist[macnum++] = str;
				
			map<int, ELEMTYPE>::iterator iter = FindInfoByMac(elem.mac);
			if(iter != objectMacMap.end())
			{
				UpdateInfo(elem, iter);
			}
			else
			{
				InsertInfo(index, elem);
				index++;
			}
		}

		sqlConn_->closeResult(result);
	}
}

//-----------------------------------------------------------------------
// Func Name   : GetObjectId
// Description :
// Parameter   : string
// Return      : int
//-----------------------------------------------------------------------
int Clue::GetObjectId(string mac)
{
	MakeStringUp(mac);
	
	//printf("\nmac:%s:::len:%d\n", mac.c_str(), strlen(mac.c_str()));
	
	map<int, ELEMTYPE>::iterator iter;
	for(iter = objectMacMap.begin(); iter != objectMacMap.end(); iter++)
	{
		//printf("::::%s:::::::%d\n", iter->second.mac.c_str(), strlen(iter->second.mac.c_str()));
		//if(iter->second.mac == mac)
		if(!strcmp(iter->second.mac.c_str(), mac.c_str()))
			return iter->second.objectid;
		
	}
	return 0;
}

#ifdef VPDNLZ
int Clue::GetObjectId2(unsigned int Ip,char* pppoe)
{
//	MakeStringUp(mac);
	
	//printf("\nmac:%s:::len:%d\n", mac.c_str(), strlen(mac.c_str()));
	struct in_addr addr;
	addr.s_addr=Ip;
	char ip[16];
	memcpy(ip,inet_ntoa(addr),16);
	//cout<<"IP: "<<ip<<endl;
	map<int, ELEMTYPE>::iterator iter;
	for(iter = objectMacMap.begin(); iter != objectMacMap.end(); iter++)
	{
		//printf("::::%d:::::::%d\n", iter->second.pppoe.length(), iter->second.ip.length());

		if(iter->second.pppoe.length() !=0 && iter->second.ip.length() !=0 && !strcmp(iter->second.ip.c_str(), ip))
		{
			memcpy(pppoe,iter->second.pppoe.c_str(),iter->second.pppoe.length());
			pppoe[iter->second.pppoe.length()] = 0;//printf("pppoe = %s\n",pppoe);
			return iter->second.objectid;
		}
		
	}
	return 0;
}
#endif

void Clue::AddObjectId(u_int clueId,string mac)
{
	if(clueId == 0)
	{
		string sql = "insert into ALLOBJECT(id,object_name,object_mac,all_embed) ";
		sql += "values(SEQ_ALLOBJECT_ID.nextval,:object_name,:object_mac,:all_embed)";

		sqlConn_->SetSql(sql.c_str());
		sqlConn_->SetString(1, mac.c_str());
		sqlConn_->SetString(2, mac.c_str());
		sqlConn_->SetInt(3, 0);
		sqlConn_->DoSql();

#if 0 //zhangzm MYSQL insert solved
		char * str_mac = new char[18];
		memset(str_mac,0,18);
		memcpy(str_mac,mac.c_str(),17);
		char * sql = (char *)malloc(1024 * 64);
		memset(sql, 0, 1024 * 64);

		sprintf(sql,"insert into allobject(object_name,object_mac,all_embed) values ('%s','%s',%d)",str_mac,str_mac,0);
		//printf("%s\n", sql);
		int res = mysql_query(conn, sql);
		if(res)
		{
			fprintf(stderr,"Insert error %d: %s\n",mysql_errno(conn),mysql_error(conn));
		}
		free(sql);
		str_mac = NULL;
#endif
		
		GetObjectMacList();
		UpdateObjectMacList();
		ShowMapList();
	}
}

//-----------------------------------------------------------------------
// Func Name   : InsertClueInfo
// Description :
// Parameter   : CLUETABLE
// Return      : void
//-----------------------------------------------------------------------
void Clue::InsertClueInfo(CLUETABLE elem)
{
	if (elem.clue_type == CLUE_MAC)
	{
		clueMacMap.insert(map<int, CLUETABLE>::value_type(mac_index, elem));
		mac_index++;
	}
	else if (elem.clue_type == CLUE_IP)
	{
		clueIpMap.insert(map<int, CLUETABLE>::value_type(ip_index, elem));
		ip_index++;
	}
}

//-----------------------------------------------------------------------
// Func Name   : UpdateClueInfo
// Description :
// Parameter   : CLUETABLE, map
// Return      : void
//-----------------------------------------------------------------------
void Clue::UpdateClueInfo(CLUETABLE elem, map<int, CLUETABLE>::iterator iter)
{
	iter->second.clue_id = elem.clue_id;
}

//-----------------------------------------------------------------------
// Func Name   : FindClueInfo
// Description :
// Parameter   : CLUETABLE
// Return      : map
//-----------------------------------------------------------------------
map<int, CLUETABLE>::iterator Clue::FindClueInfo(CLUETABLE *clue_table)
{
	map<int, CLUETABLE>::iterator iter;

	if (clue_table->clue_type == CLUE_MAC)
	{
		for(iter = clueMacMap.begin(); iter != clueMacMap.end(); iter++)
		{
			if(iter->second.clue_cnt == clue_table->clue_cnt)
				break;
		}
	}
	else if (clue_table->clue_type == CLUE_IP)
	{
		for(iter = clueIpMap.begin(); iter != clueIpMap.end(); iter++)
		{
			if(iter->second.clue_cnt == clue_table->clue_cnt)
				break;
		}
	}

	return iter;
}

//-----------------------------------------------------------------------
// Func Name   : UpdateClueList
// Description :
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void Clue::UpdateClueList()
{
	map<int, CLUETABLE>::iterator iter;
	for (iter = clueMacMap.begin(); iter != clueMacMap.end();)
	{
		int i = 0;
		while (i < clueMacnum)
		{
			if(clueMaclist[i] == iter->second.clue_cnt)
				break;
			i++;
		}
		
		if(i == clueMacnum)
		{
			clueMacMap.erase(iter);
			iter = clueMacMap.begin();
		}
		else
		{
			iter++;
		}
	}

	for (iter = clueIpMap.begin(); iter != clueIpMap.end();)
	{
		int i = 0;
		while (i < clueIpnum)
		{
			if(clueIplist[i] == iter->second.clue_cnt)
				break;
			i++;
		}
		
		if(i == clueIpnum)
		{
			clueIpMap.erase(iter);
			iter = clueIpMap.begin();
		}
		else
		{
			iter++;
		}
	}
}

//-----------------------------------------------------------------------
// Func Name   : GetClueList
// Description :
// Parameter   : void
// Return      : void
//-----------------------------------------------------------------------
void Clue::GetClueList()
{
	CLUETABLE c_elem;
	ResultSet* result = NULL;
	string sql = "select id, cluecnt, cluetype from clues where deleted=0";
	
	sqlConn_->SetSql(sql.c_str());
	result = sqlConn_->DoSqlResult();
	if (result)
	{
		clueMacnum = 0;
		clueIpnum = 0;
		while(result->next())
		{
			c_elem.clue_id = result->getInt(1);
			c_elem.clue_cnt = result->getString(2);
			c_elem.clue_type = result->getInt(3);
	
			if (c_elem.clue_type == CLUE_MAC)
			{
				clueMaclist[clueMacnum++] = c_elem.clue_cnt;
			}
			else if (c_elem.clue_type == CLUE_IP)
			{
				clueIplist[clueIpnum++] = c_elem.clue_cnt;
			}
			else
			{
				continue;
			}
			
			map<int, CLUETABLE>::iterator iter = FindClueInfo(&c_elem);
			if(iter != clueMacMap.end() && iter != clueIpMap.end())
			{
				UpdateClueInfo(c_elem, iter);
			}
			else
			{
				InsertClueInfo(c_elem);
			}
		}

		sqlConn_->closeResult(result);
	}
}

//-----------------------------------------------------------------------
// Func Name   : GetClueId
// Description :
// Parameter   : CLUE_TYPE_T
// Return      : int
//-----------------------------------------------------------------------
int Clue::GetClueId(CLUE_TYPE_T *clue_t)
{	
	map<int, CLUETABLE>::iterator iter;
	for(iter = clueMacMap.begin(); iter != clueMacMap.end(); iter++)
	{
		//printf("::clue_table::%s:::::::%d\n", iter->second.clue_cnt.c_str(), strlen(iter->second.clue_cnt.c_str()));
		if (!strcasecmp(iter->second.clue_cnt.c_str(), clue_t->mac.c_str()))
			return iter->second.clue_id;
	}

	for(iter = clueIpMap.begin(); iter != clueIpMap.end(); iter++)
	{
		//printf("::clue_table::%s:::::::%d\n", iter->second.clue_cnt.c_str(), strlen(iter->second.clue_cnt.c_str()));
		if (!strcasecmp(iter->second.clue_cnt.c_str(), clue_t->ip.c_str()))
			return iter->second.clue_id;
	}
	
	return 0;
}

//end file
