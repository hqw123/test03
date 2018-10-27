#ifndef _PUBLIC_DB_
#define _PUBLIC_DB_

#include "PublicOcci.h"
using namespace std;

class PublicDb
{
public:
	virtual ~PublicDb();
	
	static PublicDb *get_instance();
	static PublicDb *get_instance(string f_addr, string s_addr);
	
	PublicOcci *get_sqlConn_flood();
	PublicOcci *get_sqlConn_special();

	bool get_flood_conn_state();
	bool get_special_conn_state();

private:
    PublicDb();
	PublicDb(string f_addr, string s_addr);

	string m_flood_conn_string;
	string m_special_conn_string;

	bool m_flood_conn_state;
	bool m_special_conn_state;

	PublicOcci *m_sqlConn_flood;
	PublicOcci *m_sqlConn_special;

};

#endif  //_PUBLIC_DB_