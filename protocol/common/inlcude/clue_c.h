#ifndef __CLUE_C__
#define __CLUE_C__

#include "../../object/clue.h"

extern "C"
{
	int get_clue_id(const char *mac, const char *ip);
	void GetClueList();
	void UpdateClueList();
	int GetObjectId(const char * mac);
	#ifdef VPDNLZ
	int GetObjectId2(unsigned int Ip,char* pppoe);
	#endif
	void GetObjectMacList();
	void UpdateObjectMacList();
	void ShowMapList();
	void ReadConfig();
	void AddObjectId(u_int clueId,const char * mac);
}

#endif

//End of file.

