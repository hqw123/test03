#include <iostream>
#include <exception>
#include <assert.h>
#include <string>

#include "Occi.h"

using namespace std;
using namespace oracle::occi;

Occi::Occi()
{
    env_ = NULL;
    conn_ = NULL;
}

bool Occi::Init(const char* userName, const char* password, const char* connectString)
{
    bool initOkay = false;
    if (!env_) {
        env_ = Environment::createEnvironment("UTF8", "UTF8", Environment::THREADED_MUTEXED);
    }
    if (!env_) {
        cout << "Create environment failed!" << endl;
        return false;
    }
    try {
        conn_ = env_->createConnection(userName, password, connectString);
    } catch (SQLException& ex) {
        conn_ = NULL;
        cout << "Connect DB failed: " << ex.getMessage() << endl;
        exit(0);
    }

    return initOkay;
}

Occi::~Occi()
{
    if (env_) {
        try {
            if (conn_) {
                env_->terminateConnection(conn_);
            }
            Environment::terminateEnvironment(env_);
        } catch (SQLException& ex) {
            cout << "Terminate failed: " << ex.getMessage() << endl;
            exit(0);
        }
    }
}

oracle::occi::Statement* Occi::CreateStmt()
{
    assert(conn_ != NULL);
    oracle::occi::Statement* stmt = NULL;
    try {
        stmt = conn_->createStatement();
    } catch (SQLException& ex) {
        stmt = NULL;
        cout << "Connect DB failed: " << ex.getMessage() << endl;
        exit(0);
    }

    return stmt;
}

void Occi::TerminateStmt(oracle::occi::Statement* stmt)
{
    assert(conn_ != NULL);
    assert(stmt != NULL);
    try {
        conn_->terminateStatement(stmt);
    } catch (SQLException& ex) {
        cout << "Terminate failed: " << ex.getMessage() << endl;
        exit(0);
    }
}

bool Occi::SetSql(oracle::occi::Statement* stmt, const char* sql)
{
    assert(sql != NULL);
    assert(stmt != NULL);
    bool okay = true;
    try {
        stmt->setSQL(sql);
    } catch (SQLException& ex) {
        cout << "Set SQL failed!" << endl;
        cout << "Error number: " << ex.getErrorCode() << endl;
        cout << ex.getMessage() << endl;
        okay = false;
        exit(0);
    }

    return okay;
}


bool Occi::DoSql(oracle::occi::Statement* stmt)
{
    assert(stmt != NULL);
    bool okay = true;
    try {
        stmt->executeUpdate();
        conn_->commit();
    } catch (SQLException& ex) {
        cout << "SQL excute failed!" << endl;
        cout << "Error number: " << ex.getErrorCode() << endl;
        cout << ex.getMessage() << endl;
        okay = false;
    }

    return okay;
}

const char* Occi::DoSqlRetString(oracle::occi::Statement* stmt)
{
    assert(stmt != NULL);
    const char* ret=NULL;
    ResultSet* rset;
    try {
        rset = stmt->executeQuery();
        if (rset->next()) {
            ret=rset->getString(1).c_str();
        }
        stmt->closeResultSet(rset);
    } catch (SQLException& ex) {
        cout << "SQL excute failed!" << endl;
        cout << "Error number: " << ex.getErrorCode() << endl;
        cout << ex.getMessage() << endl;
    }

    return ret;
}


u_int Occi::DoSqlRetInt(oracle::occi::Statement* stmt)
{
    assert(stmt != NULL);
    u_int ret = 0;
    ResultSet* rset;
    try {
        rset = stmt->executeQuery();
        if (rset->next()) {
            ret = rset->getInt(1);
        }
        stmt->closeResultSet(rset);
    } catch (SQLException& ex) {
        cout << "SQL excute failed!" << endl;
        cout << "Error number: " << ex.getErrorCode() << endl;
        cout << ex.getMessage() << endl;
    }

    return ret;
}


void Occi::SetInt(oracle::occi::Statement* stmt, unsigned int parameter, int num)
{
    assert(stmt != NULL);
    stmt->setInt(parameter, num);
}

void Occi::SetUInt(oracle::occi::Statement* stmt, unsigned int parameter, int num)
{
    assert(stmt != NULL);
    stmt->setUInt(parameter, num);
}

void Occi::SetFloat(oracle::occi::Statement* stmt, unsigned int parameter, float num)
{
    assert(stmt != NULL);
    stmt->setFloat(parameter, num);
}

void Occi::SetString(oracle::occi::Statement* stmt, unsigned int parameter, const char* str)
{
    assert(stmt != NULL);
    assert(str != NULL);
    string buf(str);
    stmt->setString(parameter, buf);
}

void Occi::SetTime(oracle::occi::Statement* stmt, unsigned int parameter, time_t timeVal)
{
    assert(env_ != NULL);
    assert(stmt != NULL);
    tm* timeStruct = localtime(&timeVal);
    Date date(env_,
              timeStruct->tm_year + 1900,
              timeStruct->tm_mon + 1,
              timeStruct->tm_mday,
              timeStruct->tm_hour,
              timeStruct->tm_min,
              (timeStruct->tm_sec == 60) ? 0 : timeStruct->tm_sec);
    stmt->setDate(parameter, date);
}

void Occi::SetClobForUTF8(oracle::occi::Statement* stmt, u_int parameter)
{
    assert(conn_ != NULL);
    assert(stmt != NULL);
    Clob clob(conn_);
    clob.setEmpty();
    stmt->setClob(parameter, clob);
}

u_int Occi::UpdateClob(oracle::occi::Statement* stmt, u_int parameter, u_char* str, u_int strLen)
{
    assert(str != NULL);
    assert(stmt != NULL);
    
    u_int bytesWrite = 0;
    ResultSet* rset = stmt->executeQuery();
    if (rset->next()) {
        Clob clob = rset->getClob(parameter);
        bytesWrite = clob.write(strLen, str, strLen);
    }
    stmt->executeUpdate();
    stmt->closeResultSet(rset);

    return bytesWrite;
}
