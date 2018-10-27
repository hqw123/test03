#ifndef _ORACLE_
#define _ORACLE_

typedef unsigned int OracleConnection; 

extern OracleConnection CreateConnect(const char* userName, const char* password, const char* connectString);
extern int SetSql(OracleConnection oc, const char* sql);
extern int DoSql(OracleConnection oc);
extern int SetInt(OracleConnection oc, unsigned int parameter, int num);
extern int SetUInt(OracleConnection oc, unsigned int parameter, unsigned int num);
extern int SetFloat(OracleConnection oc, unsigned int parameter, float num);
extern int SetString(OracleConnection oc, unsigned int parameter, const char* str);
extern int SetTime(OracleConnection oc, unsigned int parameter, time_t timeVal);
extern int SetClobForUTF8(OracleConnection oc, unsigned int parameter);
extern unsigned int UpdateClob(OracleConnection oc, unsigned int parameter, unsigned char* str, unsigned int strLen);
extern void FreeConnect(OracleConnection oc);

#endif
