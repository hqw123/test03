/*
******************************************************************************
*
* (C) Copyright [2012-2099] WUHAN YITIANJIAN. All Rights Reserved.   
* 
******************************************************************************
*/
/*****************************************************************************
* File Name : analyse_md5.h
*
* Module : libanalyzeServer.so
*
* Description:  the file for analysing md5
*
* Evolution( Date | Author | Description ) 
* 2017.12.06 | huqiwang | v2.0 delivery based on T01.
* 
******************************************************************************
*/

#ifndef FILEMD5_H
#define FILEMD5_H

#include <iostream>

typedef int (*common_md5) (char* body, unsigned short bodylen);

typedef struct host_md5
{
    int num;
    common_md5 function;
}Host_md5;

typedef struct host_md5node
{
    std::string host;
    Host_md5 node;
}Host_md5node;

int analyse_filemd5(struct PacketInfo* packet);
void md5_fun_init();
#endif