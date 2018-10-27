#include <iostream>
#include "PublicOcci.h"
#include "oracle.h"


OracleConnection CreateConnect(const char* userName, const char* password, const char* connectString)
{
    PublicOcci* occi = NULL;
    occi = new PublicOcci;
    if (!occi->Init(userName, password, connectString)) {
        std::cout << "Connect to DB failed!" << std::endl;
        delete occi;
        occi = NULL;
    }

    return reinterpret_cast<OracleConnection>(occi);
}

int SetSql(OracleConnection oc, const char* sql)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        ret = occi->SetSql(sql);
    } else {
        std::cout << "SetSql::No connection!" << std::endl;
    }

    return ret;
}

int DoSql(OracleConnection oc)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        ret = occi->DoSql();
    } else {
        std::cout << "DoSql::No connection!" << std::endl;
    }

    return ret;
}

int SetInt(OracleConnection oc, unsigned int parameter, int num)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetInt(parameter, num);
        ret = 1;
    } else {
        std::cout << "SetInt::No connection!" << std::endl;
    }

    return ret;
}

int SetUInt(OracleConnection oc, unsigned int parameter, unsigned int num)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetUInt(parameter, num);
        ret = 1;
    } else {
        std::cout << "SetUInt::No connection!" << std::endl;
    }

    return ret;
}

int SetFloat(OracleConnection oc, unsigned int parameter, float num)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetFloat(parameter, num);
        ret = 1;
    } else {
        std::cout << "SetFloat::No connection!" << std::endl;
    }

    return ret;
}

int SetString(OracleConnection oc, unsigned int parameter, const char* str)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetString(parameter, str);
        ret = 1;
    } else {
        std::cout << "SetString::No connection!" << std::endl;
    }

    return ret;
}

int SetTime(OracleConnection oc, unsigned int parameter, time_t timeVal)
{
    int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetTime(parameter, timeVal);
        ret = 1;
    } else {
        std::cout << "SetTime::No connection!" << std::endl;
    }

    return ret;
}

int SetClobForUTF8(OracleConnection oc, unsigned int parameter)
{
    unsigned int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        occi->SetClobForUTF8(parameter);
        ret = 1;
    } else {
        std::cout << "No connect!" << std::endl;
    }

    return ret;
}

unsigned int UpdateClob(OracleConnection oc, unsigned int parameter, u_char* str, unsigned int strLen)
{
    unsigned int ret = 0;
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        ret = occi->UpdateClob(parameter, str, strLen);
    } else {
        std::cout << "No connect!" << std::endl;
    }

    return ret;
}

void FreeConnect(OracleConnection oc)
{
    PublicOcci* occi = reinterpret_cast<PublicOcci*>(oc);
    if (occi) {
        delete occi;
    }
}

