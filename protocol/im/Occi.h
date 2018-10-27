#ifndef _OCCI_
#define _OCCI_

#include <occi.h>
#include <boost/thread/mutex.hpp>

class Occi
{
public:
    Occi();
    virtual ~Occi();
    bool Init(const char* userName, const char* password, const char* connectString);
    oracle::occi::Statement* CreateStmt();
    void TerminateStmt(oracle::occi::Statement* stmt);
    bool SetSql(oracle::occi::Statement* stmt, const char* sql);
   
    bool DoSql(oracle::occi::Statement* stmt);
    const char* DoSqlRetString(oracle::occi::Statement* stmt);
    unsigned int DoSqlRetInt(oracle::occi::Statement* stmt);
    void SetInt(oracle::occi::Statement* stmt, unsigned int parameter, int num);
    void SetUInt(oracle::occi::Statement* stmt, unsigned int parameter, int num);
    void SetFloat(oracle::occi::Statement* stmt, unsigned int parameter, float num);
    void SetString(oracle::occi::Statement* stmt, unsigned int parameter, const char* str);
    void SetTime(oracle::occi::Statement* stmt, unsigned int parameter, time_t timeVal);
    void SetClobForUTF8(oracle::occi::Statement* stmt, unsigned int parameter);
    unsigned int UpdateClob(oracle::occi::Statement* stmt, unsigned int parameter, u_char* str, unsigned int strLen);
private:
    oracle::occi::Environment* env_;
    oracle::occi::Connection* conn_;
    boost::mutex stmtMut_;
};

#endif
// End of file.
