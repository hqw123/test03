//------------------------------------------------------------------------
// Nodes Monitor System is a sniffer to get evidences on Internet.      
//                                                                       
// Copyright (C) 2008 RYing Information Security Techology CO., Ltd.
// This program belongs to RYing ISTC, which shall not be reproduced,   
// copied, or used in other ways without permission. Otherwise RYing    
// ISTC will have the right to pursue legal responsibilities.            
//
//------------------------------------------------------------------------
//
// Module Name:     Public.cpp
//
//------------------------------------------------------------------------
// Notes:
//      This file defines some public functions.
//------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date   Origin      Description
// ---- -------- ---- --- ------ ----------- -----------------------------
// $d0= -------- 1.00 001 081126 Zhao Junzhe Initial
//
//------------------------------------------------------------------------
#include "Public.h"
#include <iostream>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <iconv.h>
#include <libxml/parser.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

using namespace std;
#define TIME_STR_SIZE 22
//-----------------------------------------------------------------------
// Func Name   : GetCurrentTime
// Description : Get the current time in standard format.
// Parameter   : void
// Return      : string*
//-----------------------------------------------------------------------

int g_deviceNumber;
const char* LzDataPath="/home";

void SetDeviceNum(int devNum)
{
    g_deviceNumber = devNum;
}

int GetDeviceNum()
{
    return g_deviceNumber;
}

string* GetCurrentTime()
{
    // The time information stores in this static string.
    // So the returned string* will be updated after the function each calling.
    static std::string currentTime;
    time_t timeVal;
    time(&timeVal);
    currentTime = ctime(&timeVal);
    return &currentTime;
}

const char* GetTimeStr()
{
    timeval currentTime;
    gettimeofday(&currentTime, NULL);
    char* strTime = new char[TIME_STR_SIZE];
    sprintf(strTime, "%lu_%lu\0", currentTime.tv_sec, currentTime.tv_usec);
    return strTime;
}

size_t GetUTF8LenFromUCS4(const u_int* ucs4, size_t len)
{
    //assert(ucs4 != NULL);
    if (ucs4 == NULL)
		return 0;

    size_t utf8Len = 0;
    if (len == 0) {
        size_t i = 0;
        while(ucs4[i] != 0x0000) {
            if (ucs4[i] < 0x80) {
                ++utf8Len;
            } else if (ucs4[i] < 0x800) {
                utf8Len += 2;
            } else if (ucs4[i] < 0x10000) {
                utf8Len += 3;
            } else if (ucs4[i] < 0x200000) {
                utf8Len += 4;
            } else if (ucs4[i] < 0x4000000) {
                utf8Len += 5;
            } else {
                utf8Len += 6;
            }
            ++i;
        }
    } else {
        for (size_t i = 0; i < len; ++i) {
            if (ucs4[i] == 0x00) {
                break;
            } else if (ucs4[i] < 0x80) {
                ++utf8Len;
            } else if (ucs4[i] < 0x800) {
                utf8Len += 2;
            } else if (ucs4[i] < 0x10000) {
                utf8Len += 3;
            } else if (ucs4[i] < 0x200000) {
                utf8Len += 4;
            } else if (ucs4[i] < 0x4000000) {
                utf8Len += 5;
            } else {
                utf8Len += 6;
            }
        }
    }

    return utf8Len;
}

size_t GetUTF8LenFromUCS2(const u_short* ucs2, size_t len)
{
    //assert(ucs2 != NULL);
    if (ucs2 == NULL)
		return 0;

    size_t utf8Len = 0;
    if (len == 0) {
        size_t i = 0;
        while(ucs2[i] != 0x0000) {
            if (ucs2[i] < 0x80) {
                ++utf8Len;
            } else if (ucs2[i] < 0x800) {
                utf8Len += 2;
            } else {
                utf8Len += 3;
            }
            ++i;
        }
    } else {
        for (size_t i = 0; i < len; ++i) {
            if (ucs2[i] == 0x00) {
                break;
            } else if (ucs2[i] < 0x80) {
                ++utf8Len;
            } else if (ucs2[i] < 0x800) {
                utf8Len += 2;
            } else {
                utf8Len += 3;
            }
        }
    }

    return utf8Len;
}

char* UCS4ToUTF8(const u_int* ucs4, size_t len)
{
    //assert(ucs4 != NULL);
    if (ucs4 == NULL)
		return NULL;
	
    size_t utf8Len = GetUTF8LenFromUCS4(ucs4, len);
    char* utf8 = new char[utf8Len + 1];
    char* utf8start = utf8;
    if (len == 0) {
        size_t i = 0;
        while(ucs4[i] != 0x0000) {
            if (ucs4[i] < 0x80) {
                *utf8++ = ucs4[i];
            } else if (ucs4[i] < 0x800) {
                *utf8++ = ((ucs4[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x10000) {
                *utf8++ = ((ucs4[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x200000) {
                *utf8++ = ((ucs4[i] >> 18) & 0x07) | 0xf0;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x4000000) {
                *utf8++ = ((ucs4[i] >> 24) & 0x03) | 0xf8;
                *utf8++ = ((ucs4[i] >> 18) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs4[i] >> 30) & 0x01) | 0xfc;
                *utf8++ = ((ucs4[i] >> 24) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 18) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            }
            ++i;
        }
        *utf8 = 0x00;
    } else {
        for (size_t i = 0; i < len; ++i) {
            if (ucs4[i] == 0x00) {
                break;
            } else if (ucs4[i] < 0x80) {
                *utf8++ = ucs4[i];
            } else if (ucs4[i] < 0x800) {
                *utf8++ = ((ucs4[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x10000) {
                *utf8++ = ((ucs4[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x200000) {
                *utf8++ = ((ucs4[i] >> 18) & 0x07) | 0xf0;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else if (ucs4[i] < 0x4000000) {
                *utf8++ = ((ucs4[i] >> 24) & 0x03) | 0xf8;
                *utf8++ = ((ucs4[i] >> 18) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs4[i] >> 30) & 0x01) | 0xfc;
                *utf8++ = ((ucs4[i] >> 24) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 18) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 12) & 0x3f) | 0x80;
                *utf8++ = ((ucs4[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs4[i] & 0x3f) | 0x80;
            }
        }
        *utf8 = 0x00;
    }

    return utf8start;
}

char* UCS2ToUTF8(const u_short* ucs2, size_t len)
{
    //assert(ucs2 != NULL);
    if (ucs2 == NULL)
		return NULL;
	
    size_t utf8Len = GetUTF8LenFromUCS2(ucs2, len);
    char* utf8 = new char[utf8Len + 1];
    char* utf8start = utf8;
    if (len == 0) {
        size_t i = 0;
        while(ucs2[i] != 0x0000) {
            if (ucs2[i] < 0x80) {
                *utf8++ = ucs2[i];
            } else if (ucs2[i] < 0x800) {
                *utf8++ = ((ucs2[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs2[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs2[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            }
            ++i;
        }
        *utf8 = 0x00;
    } else {
        for (size_t i = 0; i < len; ++i) {
            if (ucs2[i] == 0x00) {
                break;
            } else if (ucs2[i] < 0x80) {
                *utf8++ = ucs2[i];
            } else if (ucs2[i] < 0x800) {
                *utf8++ = ((ucs2[i] >> 6) & 0x1f) | 0xc0;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            } else {
                *utf8++ = ((ucs2[i] >> 12) & 0x0f) | 0xe0;
                *utf8++ = ((ucs2[i] >> 6) & 0x3f) | 0x80;
                *utf8++ = (ucs2[i] & 0x3f) | 0x80;
            }
        }
        *utf8 = 0x00;
    }

    return utf8start;
}

char* GBK2UTF8(char* gbk, size_t len)
{
    //assert(gbk != NULL);
    if (gbk == NULL)
		return NULL;
	
    iconv_t cd;
    if ((cd  = iconv_open("UTF-8", "GB18030")) < 0) {
        //cout << "Get iconv handle failed!" << endl;
        LOG_ERROR("Get iconv handle failed!\n");
        return NULL;
    }
    size_t gbkLen;
    if (len == 0) {
        gbkLen = strlen(gbk);
    } else {
        gbkLen = len;
    }
    char** gbkPtr = &gbk;
    size_t utf8Len = gbkLen * 2;
    char* utf8 = new char[utf8Len];
    memset(utf8, 0, utf8Len);
    char* utf8Ptr  = utf8;
    size_t res = iconv(cd, gbkPtr, &gbkLen, &utf8Ptr, &utf8Len);
    if (res < 0) {
       // cout << "Convert failed!" << endl;
       LOG_ERROR("Convert failed!\n");
        delete utf8;
        utf8 = NULL;
    }
    iconv_close(cd);

    return utf8;
}

int DecodeQuoted(unsigned char* pDst, const char* pSrc, int nSrcLen)
{
    int nDstLen = 0;
    while (nSrcLen > 0) {
        if (strncmp(pSrc, "=\r\n", 3) == 0) {
            pSrc += 3;
            nSrcLen -= 3;
        } else if (*pSrc == '=') {
            sscanf(pSrc, "=%02X", pDst++);
            pSrc += 3;
            nSrcLen -= 3;
            ++nDstLen;
        } else {
            *pDst++ = (unsigned char)*pSrc++;
            --nSrcLen;
            ++nDstLen;
        }
    }
    *pDst = '\0';

    return nDstLen;
}

char* GBK_B2UTF8(const char* base64, size_t len)
{
    //assert(base64 != NULL);
    if (base64 == NULL)
		return NULL;

    u_char gbk[len];
    char* utf = NULL;
    int gbkLen = EVP_DecodeBlock(gbk, (const u_char*)base64, len);
    if (gbkLen <= 0 ) {
        return NULL;
    } else {
        utf = GBK2UTF8((char*)gbk, gbkLen);
    }

    return utf;
}

char* GBK_Q2UTF8(const char* qp, size_t len)
{
    //assert(qp != NULL);
    if (qp == NULL)
		return NULL;

    u_char gbk[len];
    char* utf = NULL;
    int gbkLen = DecodeQuoted(gbk, qp, len);
    if (gbkLen <= 0 ) {
        return NULL;
    } else {
        utf = GBK2UTF8((char*)gbk, gbkLen);
    }

    return utf;
}

char* QP2UTF8(const char* qp, size_t len)
{
    //assert(qp != NULL);
    if (qp == NULL)
		return NULL;

    char* utf = new char[len];
    int utfLen = DecodeQuoted((u_char*)utf, qp, len);
    if (utfLen <= 0 ) {
        delete utf;
        return NULL;
    }

    return utf;
}


char* Base2UTF8(const char* base64, size_t len)
{
    //assert(base64 != NULL);
    if (base64 == NULL)
		return NULL;
	
    char* utf = new char[len];
    int utfLen = EVP_DecodeBlock((u_char*)utf, (const u_char*)base64, len);
    if (utfLen <= 0 ) {
        delete utf;
        return NULL;
    }

    return utf;
}

// end of file

