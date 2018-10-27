
#include <iostream>
#include <exception>
#include <assert.h>
#include <string>

#include "PublicOcci.h"
#include "Analyzer_log.h"

using namespace std;

PublicOcci::PublicOcci()
{
    env_ = NULL;
    stmt_ = NULL;
    conn_ = NULL;
	connect_state = false;
	data_count = 0;

	/*old test account:mtu01/mtu01, 127.0.0.1<-->localhost*/
	//Init("mtu01", "mtu01", "192.168.2.230:1521/mtu02");
	//Init("YTJ_mtu01", "MTU01_ytj_20161201", "127.0.0.1:1521/mtu01");
}

bool PublicOcci::Init(const char* userName, const char* password, const char* connectString)
{
    bool initOkay = false;
    if (!env_) {
        env_ = Environment::createEnvironment("UTF8", "UTF8", Environment::THREADED_MUTEXED);
    }
    if (!env_) {
        //cout << "Create environment failed!" << endl;
        LOG_ERROR("Create environment failed!\n");
        return false;
    }
    try {
        conn_ = env_->createConnection(userName, password, connectString);
        boost::mutex::scoped_lock lock(stmtMut_);
        stmt_ = conn_->createStatement();
    } catch (SQLException& ex) {
        stmt_ = NULL;
        conn_ = NULL;
        //cout << "Connect to DB failed: " << ex.getMessage() << endl;
        LOG_ERROR("Connect to DB failed: \n%s\n", ex.getMessage().c_str());
    }
    if (stmt_) {
        initOkay = true;
		connect_state = true;
    }

    return initOkay;
}

PublicOcci::~PublicOcci()
{
    if (env_) {
        try {
            boost::mutex::scoped_lock lock(stmtMut_);
            if (stmt_) {
                conn_->terminateStatement(stmt_);
            }
            if (conn_) {
                env_->terminateConnection(conn_);
            }
            Environment::terminateEnvironment(env_);
        } catch (SQLException& ex) {
            //cout << "Terminate failed: " << ex.getMessage() << endl;
            LOG_ERROR("Terminate failed: \n%s\n", ex.getMessage().c_str());
        }
    }
}

PublicOcci *PublicOcci::get_instance()
{
    static PublicOcci *public_occi = NULL;
    
    if (public_occi == NULL)
    {
        public_occi = new PublicOcci();
    }
    return public_occi;
}

bool PublicOcci::get_oracle_conn_state()
{
	return connect_state;
}

bool PublicOcci::get_data_count()
{
	return data_count;
}

bool PublicOcci::SetSql(const char* sql)
{
    //assert(sql != NULL);
	if (sql == NULL)
		return false;
	
    bool okay = true;
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return false;
    }
    try {
        boost::mutex::scoped_lock lock(stmtMut_);
        stmt_->setSQL(sql);
    } catch (SQLException& ex) {
        //cout << "Set SQL failed!" << endl;
        //cout << "Error number: " << ex.getErrorCode() << endl;
        //cout << ex.getMessage() << endl;
		LOG_ERROR("Set SQL failed!\n");
		LOG_ERROR("Error number: %d\n", ex.getErrorCode());
		LOG_ERROR("%s\n", ex.getMessage().c_str());
        okay = false;
    }

    return okay;
}

bool PublicOcci::DoUpdate()
{
    bool okay = true;
    if (!stmt_) {
		LOG_ERROR("Statement is invalid!\n");
        return false;
    }
    try {
        boost::mutex::scoped_lock lock(stmtMut_);
        stmt_->executeUpdate();
		data_count++;
    } catch (SQLException& ex) {
		LOG_ERROR("DoUpdate excute failed!\n");
		LOG_ERROR("Error number: %d\n", ex.getErrorCode());
		LOG_ERROR("%s\n", ex.getMessage().c_str());
        okay = false;
    }

    return okay;
}

bool PublicOcci::DoCommit()
{
    bool okay = true;
    if (!conn_) {
		LOG_ERROR("Connection is invalid!\n");
        return false;
    }

    try {
        boost::mutex::scoped_lock lock(stmtMut_);
        conn_->commit();
		data_count = 0;
    } catch (SQLException& ex) {
		LOG_ERROR("DoCommit excute failed!\n");
		LOG_ERROR("Error number: %d\n", ex.getErrorCode());
		LOG_ERROR("%s\n", ex.getMessage().c_str());
        okay = false;
    }

    return okay;
}

bool PublicOcci::DoSql()
{
    bool okay = true;
    if (!conn_) {
        //cout << "Connection is invalid!" << endl;
		LOG_ERROR("Connection is invalid!\n");
        return false;
    }
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
		LOG_ERROR("Statement is invalid!\n");
        return false;
    }
    try {
        boost::mutex::scoped_lock lock(stmtMut_);
        stmt_->executeUpdate();
		data_count++;
		if (data_count >= 500)
		{
			conn_->commit();
			data_count = 0;
		}
		
        //conn_->commit();
    } catch (SQLException& ex) {
        //cout << "DoSql excute failed!" << endl;
        //cout << "Error number: " << ex.getErrorCode() << endl;
        //cout << ex.getMessage() << endl;
		LOG_ERROR("DoSql excute failed!\n");
		LOG_ERROR("Error number: %d\n", ex.getErrorCode());
		LOG_ERROR("%s\n", ex.getMessage().c_str());
        okay = false;
    }

    return okay;
}

ResultSet* PublicOcci::DoSqlResult()
{
    ResultSet* rset = NULL;

    if (!conn_) {
        //cout << "Connection is invalid!" << endl;
        LOG_ERROR("Connection is invalid!\n");
        return NULL;
    }
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return NULL;
    }

    try {
		boost::mutex::scoped_lock lock(stmtMut_);
        rset = stmt_->executeQuery();
    } catch (SQLException& ex) {
        //cout << "DoSqlResult excute failed!" << endl;
        //cout << "Error number: " << ex.getErrorCode() << endl;
        //cout << ex.getMessage() << endl;
		LOG_ERROR("DoSqlResult excute failed!\n");
		LOG_ERROR("Error number: %d\n", ex.getErrorCode());
		LOG_ERROR("%s\n", ex.getMessage().c_str());
		return NULL;
    }

    return rset;
}

void PublicOcci::closeResult(ResultSet *rset)
{
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
	stmt_->closeResultSet(rset);
}

void PublicOcci::SetInt(u_int parameter, int num)
{
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
    stmt_->setInt(parameter, num);
}

void PublicOcci::SetUInt(u_int parameter, u_int num)
{
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
    stmt_->setUInt(parameter, num);
}

void PublicOcci::SetFloat(u_int parameter, float num)
{
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
    stmt_->setFloat(parameter, num);
}

void PublicOcci::SetString(u_int parameter, const char* str)
{
    //assert(str != NULL);
	if (str == NULL)
		return;

    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
    string buf(str);
    stmt_->setString(parameter, buf);
}

void PublicOcci::SetTime(u_int parameter, time_t timeVal)
{
    if (!env_) {
        //cout << "Environment is invalid!" << endl;
		LOG_ERROR("Environment is invalid!\n");
        return;
    }
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
        LOG_ERROR("Statement is invalid!\n");
        return;
    }
    tm* timeStruct = localtime(&timeVal);
    Date date(env_,
              timeStruct->tm_year + 1900,
              timeStruct->tm_mon + 1,
              timeStruct->tm_mday,
              timeStruct->tm_hour,
              timeStruct->tm_min,
              (timeStruct->tm_sec == 60) ? 0 : timeStruct->tm_sec);
    stmt_->setDate(parameter, date);
}

void PublicOcci::SetClobForUTF8(u_int parameter)
{
    if (!conn_) {
        //cout << "Connection is invalid!" << endl;
		LOG_ERROR("Connection is invalid!\n");
        return;
    }
    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
		LOG_ERROR("Statement is invalid!\n");
        return;
    }
    Clob clob(conn_);
    clob.setEmpty();
    stmt_->setClob(parameter, clob);
}

u_int PublicOcci::UpdateClob(u_int parameter, u_char* str, u_int strLen)
{
    //assert(str != NULL);
	if (str == NULL)
		return 0;

    if (!stmt_) {
        //cout << "Statement is invalid!" << endl;
		LOG_ERROR("Statement is invalid!\n");
        return 0;
    }
    u_int bytesWrite = 0;
    ResultSet* rset = stmt_->executeQuery();
    if (rset->next()) {
        Clob clob = rset->getClob(parameter);
        bytesWrite = clob.write(strLen, str, strLen);
    }
    stmt_->executeUpdate();
    stmt_->closeResultSet(rset);

    return bytesWrite;
}
