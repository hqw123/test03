//-------------------------------------------------------
//** ** System is a proxy server on internet
//
// Copyright @ 2008--2010 Baihong soft Techology CO.. Ltd.
//
//-------------------------------------------------------
//
// Module Name: Tmain.c
//
//-------------------------------------------------------
//Note:
//		this file contain the main function
//-------------------------------------------------------

#include "fakeServerB.h"
#include "serverInfo.h"
#include "listenSSL.h"
//#include "DeviceInfo.h"
//#include "macIpTab.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define LZ_HTTPS_SLEEP_TIME 5
#define LZ_HTTPS_NEED_SLEEP
//modified on 6.23 to change the listen port from 80 to 2012 to avoid the limit of port 80 set by china telecom
#define LZ_HTTPS_SERVER_PORT 80
#define LZ_HTTPS_CONNECT_LIMIT 50
#include "SentinelKeysLicense.h"
#include "Analyzer_log.h"

#define HTTPS_ENCRYPTION


void* listen443(void* data);

#ifdef HTTPS_ENCRYPTION
int Check(){
    SP_HANDLE license;
    SP_STATUS status = SP_FAIL;
    status = SFNTGetLicense(DEVELOPERID,
                            SOFTWARE_KEY,
                            LICENSEID,
                            SP_STANDALONE_MODE | SP_ENABLE_TERMINAL_CLIENT,
                            &license);
	if(status == SP_SUCCESS) {
        return 1;
	}
	else{
        LOG_ERROR("%s","Fail to verify the license, please make sure you got \
					the licence from !\n System will exit ....\n");
	}
   return 0;
}
#endif



//DeviceInfo* devinfo;
//MacIpPair* array=NULL;
int main(int argc,char** argv){

#ifdef HTTPS_ENCRYPTION
//   if (!Check()) {
//		exit(1);
//	}
#endif
#ifdef LZ_HTTPS_NEED_SLEEP
//sleep(LZ_HTTPS_SLEEP_TIME);
#endif
pthread_t tid;
if(!pthread_create(&tid,0,listen443,NULL))
	LOG_INFO("sslServer run ok\n");
else 
	LOG_ERROR("sslServer run fail\n");


initServerInfo(NULL);
startServer(LZ_HTTPS_SERVER_PORT,LZ_HTTPS_CONNECT_LIMIT);

LOG_INFO("sslServer exit\n");
} 



void* listen443(void* data){
	startsslServer(443,200);
	//startServerB(200,0xBB11);
}





