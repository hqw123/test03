#ifndef _ORACLE_
#define _ORACLE_

typedef unsigned int OracleConnection; 
extern "C" {
    OracleConnection CreateConnect(const char* userName, const char* password, const char* connectString);
    int SetSql(OracleConnection oc, const char* sql);
    int DoSql(OracleConnection oc);
    int SetInt(OracleConnection oc, unsigned int parameter, int num);
    int SetUInt(OracleConnection oc, unsigned int parameter, unsigned int num);
    int SetFloat(OracleConnection oc, unsigned int parameter, float num);
    int SetString(OracleConnection oc, unsigned int parameter, const char* str);
    int SetTime(OracleConnection oc, unsigned int parameter, time_t timeVal);
    int SetClobForUTF8(OracleConnection oc, unsigned int parameter);
    unsigned int UpdateClob(OracleConnection oc, unsigned int parameter, u_char* str, unsigned int strLen);
    void FreeConnect(OracleConnection oc);
}
#endif
