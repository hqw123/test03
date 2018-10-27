#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "test.h"
#include "oracle_c.h"
/*
void* Insert1(void* arg)
{
    OracleConnection oc = (OracleConnection) arg;
    SetSql(oc, "insert into UC \
           (devicenum, clueid, cluetimes, readflag, status, checkintime, clientip, clientport, serverip, serverport, capturetime, ucid) \
           values (:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10, :p11, :p12)");
    SetInt(oc, 4, 1); //readflag
    SetInt(oc, 5, 0); //status
    const char* rec = "hh磔磔";
    SetString(oc, 7, rec); //clientip
    SetInt(oc, 8, 1025); //clientport
    SetString(oc, 9, "1.0.0.0"); //serverip
    SetInt(oc, 10, 80); //serverport
    SetTime(oc, 11, 123633347); //capturetime
    time_t timeVal;
    int i;
    for (i = 300030; i < 300130; ++i) {
        SetInt(oc, 1, i); //devicenum
        SetInt(oc, 2, i); //clueid
        SetInt(oc, 3, i); //clutimes
        time(&timeVal);
        SetTime(oc, 6, timeVal); //checkintime
        SetInt(oc, 12, i); //ucid
        DoSql(oc);
        printf("Insert [2] -%d\n", i);
    }

    SetSql("insert into INFO_UC (sender, receiver, sip, dip, sport, dport, message, id) values (:v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8)");
    SetString(1, "sender"); //sender
    const char* rec = "receiver";
    SetString(2, rec); //receiver
    SetInt(3, 3333333); //sip
    unsigned int dip = 444444;
    SetInt(4, dip); //dip
    SetInt(5, 24); //sport
    SetInt(6, 80); //dport
    SetClobForUTF8(7); //message
    int i;
//    for (i = 0; i < 1000; ++i) {
    SetInt(8, 1003); //id
    DoSql();
    //unsigned char* str = "1234567890";
    //unsigned int len = strlen(str);
    //SetSql("select message from INFO_UC for update");
    //SetInt(1, 7); //id
//    }

    return (void*) 0;
}
*/
/*
void* Insert2(void* arg)
{
    OracleConnection oc = (OracleConnection) arg;
    SetSql(oc, "insert into UC \
           (devicenum, clueid, cluetimes, readflag, status, checkintime, clientip, clientport, serverip, serverport, capturetime, ucid) \
           values (:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10, :p11, :p12)");
    SetInt(oc, 4, 1); //readflag
    SetInt(oc, 5, 0); //status
    const char* rec = "hh磔磔";
    SetString(oc, 7, rec); //clientip
    SetInt(oc, 8, 1025); //clientport
    SetString(oc, 9, "211.39.78.33"); //serverip
    SetInt(oc, 10, 80); //serverport
    SetTime(oc, 11, 1236331817); //capturetime
    time_t timeVal;
    int i;
    for (i = 200030; i < 200130; ++i) {
        SetInt(oc, 1, i); //devicenum
        SetInt(oc, 2, i); //clueid
        SetInt(oc, 3, i); //clutimes
        time(&timeVal);
        SetTime(oc, 6, timeVal); //checkintime
        SetInt(oc, 12, i); //ucid
        DoSql(oc);
        printf("Insert [1] -%d\n", i);
    }
    
    SetSql(oc, "insert into INFO_UC (sender, receiver, sip, dip, sport, dport) values (:v1, :v2, :v3, :v4, :v5, :v6)");
    SetString(oc, 1, "sender"); //sender
    const char* rec = "hhh磔磔";
    //const char* rec = "receiver";
    SetString(oc, 2, rec); //receiver
    SetInt(oc, 3, 1111111111); //sip
    unsigned int dip = 222222222;
    SetInt(oc, 4, dip); //dip
    SetInt(oc, 5, 80); //sport
    SetInt(oc, 6, 33); //dport
    int i;
    for (i = 0; i < 1000; ++i) {
        DoSql(oc);
        printf("Insert [2] -%d\n", i);
    }

    return (void*) 0;
}
*/

//typedef unsigned int (*OracleConn)(const char*, const char*, const char*);
//typedef void (*FreeConn)(unsigned int);

//static OracleConn conn;
//static FreeConn freeconn;

int test()
{
    /*
    void* dllPtr;
    dllPtr = dlopen("liboracle.so", RTLD_LAZY);
    conn = dlsym(dllPtr, "CreateConnect");
    freeconn = dlsym(dllPtr, "FreeConnect");
    */
    const char* userName = "zk10"; // User name
    const char* password = "zk10"; // Password
    const char* connectString = "172.16.0.230:1521/casedb";  // DB address : Port / SID
    unsigned int oc = 0;
    /*
    oc = CreateConnect(userName, password, connectString);
    oc2 = CreateConnect(userName, password, connectString);
    */
    //oc = conn(userName, password, connectString);
    oc = CreateConnect(userName, password, connectString);
    /*
    pthread_t tid1;
    pthread_t tid2;
    void* tret;
    pthread_create(&tid1, NULL, Insert1, (void*) oc);
    pthread_create(&tid2, NULL, Insert2, (void*) oc2);
    pthread_join(tid1, &tret);
    pthread_join(tid2, &tret);
    FreeConnect(oc);
    FreeConnect(oc2);
    */
    FreeConnect(oc);
    //freeconn(oc);
    //dlclose(dllPtr);
    printf("Finished!\n");

    return 0;
}
