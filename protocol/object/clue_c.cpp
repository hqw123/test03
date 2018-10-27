
#include <boost/thread/mutex.hpp>
#include "clue_c.h"

boost::mutex clueMut;

int get_clue_id(const char *mac, const char *ip)
{
	CLUE_TYPE_T clue_t;
	
	clue_t.mac.assign(mac);
	clue_t.ip.assign(ip);

	//boost::mutex::scoped_lock lock(clueMut);
	return Clue::get_instance()->GetClueId(&clue_t);
}

void GetClueList()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->GetClueList();
}

void UpdateClueList()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->UpdateClueList();
}

int GetObjectId(const char * mac)
{
	//boost::mutex::scoped_lock lock(clueMut);
	return Clue::get_instance()->GetObjectId(mac);
}

#ifdef VPDNLZ
int GetObjectId2(unsigned int Ip,char* pppoe)
{
	//boost::mutex::scoped_lock lock(clueMut);
	return Clue::get_instance()->GetObjectId2(Ip,pppoe);
}
#endif

void GetObjectMacList()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->GetObjectMacList();
}

void UpdateObjectMacList()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->UpdateObjectMacList();
}

void ShowMapList()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->ShowMapList();
}

void ReadConfig()
{
	//boost::mutex::scoped_lock lock(clueMut);
	Public pub;
	pub.ReadConfig();
}

void AddObjectId(u_int clueId,const char * mac)
{
	//boost::mutex::scoped_lock lock(clueMut);
	Clue::get_instance()->AddObjectId(clueId,mac);
}

//End of file.
