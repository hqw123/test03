/****************************************************************************
storedproc.cpp - OCCI sample demonstrating calling PL/SQL stored procedures
and functions from OCCI.

Check attached README.txt for more details.

Report any errors and suggestions in OCCI Discussion forum in OTN.
*****************************************************************************/
#include <iostream>
extern "C" {
#include "test.h"
#include "oracle_c.h"
}
#include "../threadpool/include/threadpool.hpp"

using namespace std;
/*
void Insert1()
{
    SetSql("insert into UC \
           (devicenum, clueid, cluetimes, readflag, status, checkintime, clientip, clientport, serverip, serverport, capturetime, ucid) \
           values (:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10, :p11, :p12)");
    
    SetInt(4, 1); //readflag
    SetInt(5, 0); //status
    SetString(7, "172.16.0.204"); //clientip
    SetInt(8, 1025); //clientport
    SetString(9, "211.39.78.33"); //serverip
    SetInt(10, 80); //serverport
    SetTime(11, 1236331817); //capturetime
    time_t timeVal;
    for (int i = 200030; i < 200130; ++i) {
        SetInt(1, i); //devicenum
        SetInt(2, i); //clueid
        SetInt(3, i); //clutimes
        time(&timeVal);
        SetTime(6, timeVal); //checkintime
        SetInt(12, i); //ucid
        DoSql();
        cout << "Insert [1] -" << i << endl;
    }
}

void Insert2()
{
    SetSql("insert into UC \
           (devicenum, clueid, cluetimes, readflag, status, checkintime, clientip, clientport, serverip, serverport, capturetime, ucid) \
           values (:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10, :p11, :p12)");
    SetInt(4, 8); //readflag
    SetInt(5, 1); //status
    SetString(7, "172.16.0.230"); //clientip
    SetInt(8, 225); //clientport
    SetString(9, "202.103.44.39"); //serverip
    SetInt(10, 8080); //serverport
    SetTime(11, 1236361744); //capturetime
    time_t timeVal;
    for (int i = 100030; i < 100130; ++i) {
        SetInt(1, i); //devicenum
        SetInt(2, i); //clueid
        SetInt(3, i); //clutimes
        time(&timeVal);
        SetTime(6, timeVal); //checkintime
        SetInt(12, i); //ucid
        DoSql();
        cout << "Insert [2] -" << i << endl;
    }
}
*/
int main()
{
    test();
    //const char* userName = "testnode"; // User name
    //const char* password = "admin"; // Password
    //const char* connectString = "172.16.0.230:1521/nodedb";  // DB address : Port / SID
    const char* userName = "node2010"; // User name
    const char* password = "node2010"; // Password
    const char* connectString = "192.168.1.206:1521/node";  // DB address : Port / SID
    unsigned int oc = CreateConnect(userName, password, connectString);
    /*
    boost::threadpool::pool threadPool;
    threadPool.size_controller().resize(2);
    threadPool.schedule(boost::bind(&Insert1));
    threadPool.schedule(boost::bind(&Insert2));
    threadPool.wait();
    */
    FreeConnect(oc);
    cout << "Finished!" << endl;

    return 0;
}
