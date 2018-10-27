
#include "PublicDb.h"
//#include "Analyzer_log.h"

static PublicDb *g_public_db = NULL;

PublicDb::PublicDb()
{
	m_sqlConn_flood = NULL;
	//m_sqlConn_flood = new PublicOcci();
	//m_flood_conn_state = m_sqlConn_flood->Init("YTJ_mtu01", "MTU01_ytj_20161201", "127.0.0.1:1521/mtu01");
	
	m_sqlConn_special = new PublicOcci();
	m_special_conn_state = m_sqlConn_special->Init("YTJ_mtu01", "MTU01_ytj_20161201", "127.0.0.1:1521/mtu01");
}

PublicDb::PublicDb(string f_addr, string s_addr)
{
	m_sqlConn_flood = NULL;
	//m_sqlConn_flood = new PublicOcci();
	//m_flood_conn_string = f_addr + ":1521/mtu01";
	//m_flood_conn_state = m_sqlConn_flood->Init("YTJ_mtu01", "MTU01_ytj_20161201", m_flood_conn_string.c_str());
	
	m_sqlConn_special = new PublicOcci();
	m_special_conn_string = s_addr + ":1521/mtu01";
	m_special_conn_state = m_sqlConn_special->Init("YTJ_mtu01", "MTU01_ytj_20161201", m_special_conn_string.c_str());
}

PublicDb::~PublicDb()
{
	//delete m_sqlConn_flood;
	delete m_sqlConn_special;
}

PublicDb *PublicDb::get_instance()
{   
    if (g_public_db == NULL)
    {
        g_public_db = new PublicDb();
    }
	
    return g_public_db;
}

PublicDb *PublicDb::get_instance(string f_addr, string s_addr)
{
//printf("flood_ip:%s\nspecial_ip:%s\n", f_addr.c_str(), s_addr.c_str());

	cout << "flood_ip:" << f_addr << endl;
	cout << "special_ip:" << s_addr << endl;

    if (g_public_db == NULL)
    {
        g_public_db = new PublicDb(f_addr, s_addr);
    }
	
    return g_public_db;
}

PublicOcci *PublicDb::get_sqlConn_flood()
{
	return m_sqlConn_flood;
}

PublicOcci *PublicDb::get_sqlConn_special()
{
	return m_sqlConn_special;
}

bool PublicDb::get_flood_conn_state()
{
	return m_flood_conn_state;
}

bool PublicDb::get_special_conn_state()
{
	return m_special_conn_state;
}


