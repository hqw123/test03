#ifndef _PUBLIC_OCCI_
#define _PUBLIC_OCCI_

#include <occi.h>
#include <boost/thread/mutex.hpp>

using namespace oracle::occi;

class PublicOcci
{
public:
    PublicOcci();
    virtual ~PublicOcci();
	static PublicOcci *get_instance();
	bool get_oracle_conn_state();
	bool get_data_count();
    bool Init(const char* userName, const char* password, const char* connectString);
    bool SetSql(const char* sql);
	bool DoUpdate();
	bool DoCommit();
    bool DoSql();
	ResultSet* DoSqlResult();
	void closeResult(ResultSet *rset);
    void SetInt(u_int parameter, int num);
    void SetUInt(u_int parameter, u_int num);
    void SetFloat(u_int parameter, float num);
    void SetString(u_int parameter, const char* str);
    void SetTime(u_int parameter, time_t timeVal);
    void SetClobForUTF8(u_int parameter);
    u_int UpdateClob(u_int parameter, u_char* str, u_int strLen);
private:
    oracle::occi::Environment* env_;
    oracle::occi::Connection* conn_;
    oracle::occi::Statement* stmt_;
    boost::mutex stmtMut_;

	bool connect_state;
	int data_count;
};

#endif
// End of file.
