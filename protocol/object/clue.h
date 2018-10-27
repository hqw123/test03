//------------------------------------------------------------------------
// Anaylzer
//
// Copyright (C) 2010 BAIHONG Information Security Techology CO.,
//
//------------------------------------------------------------------------
//
// Module Name  :  clue.h
//
//------------------------------------------------------------------------
// Notes:
//      This file declares the class clue
//
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.0  001 101108 sunjinshuo  Initial
//------------------------------------------------------------------------
//#include <mysql.h>
//#include <occi.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <string>
#include <arpa/inet.h>

#include "../Public.h"
#include "../PublicDb.h"
#include "Analyzer_log.h"

using namespace std;

//-----------------------------------------------------------------------
// Class Name  : clue
// Interface   : 
// Description : 
//-----------------------------------------------------------------------
class Clue
{
	public:
		Clue();
		virtual ~Clue();
		void ShowMapList();
		void GetObjectMacList();
		void UpdateObjectMacList();
		int GetObjectId(string mac);
		#ifdef VPDNLZ
		int GetObjectId2(unsigned int Ip,char* pppoe);
		#endif
		void AddObjectId(unsigned int clueId,string mac);
		static Clue *get_instance();

		void UpdateClueList();
		void GetClueList();
		int GetClueId(CLUE_TYPE_T *clue_t);
	
	public:
		std::map<int, ELEMTYPE> objectMacMap;
		std::map<int, CLUETABLE> clueMacMap;
		std::map<int, CLUETABLE> clueIpMap;
		
	private:
		PublicOcci *sqlConn_;
		bool isConnected;
		
		//string maclist[1024];
		string maclist[10240];//for LZ_B
		int macnum;
		int index;

		string clueMaclist[5120];//for LZ_B
		int clueMacnum;
		int mac_index;

		string clueIplist[5120];//for LZ_B
		int clueIpnum;
		int ip_index;
	
	private:
		map<int, ELEMTYPE>::iterator FindInfoByMac(string mac);
		void UpdateInfo(ELEMTYPE elem, map<int, ELEMTYPE>::iterator iter);
		void InsertInfo(int nIndex, ELEMTYPE elem);
		void MakeStringUp(string& mac);

		void InsertClueInfo(CLUETABLE elem);
		void UpdateClueInfo(CLUETABLE elem, map<int, CLUETABLE>::iterator iter);
		map<int, CLUETABLE>::iterator FindClueInfo(CLUETABLE *clue_table);
};


//end of file
