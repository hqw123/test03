#include <iostream>
#include <string.h>

/****************************************************************************
Function Name:           tianyiyunpan_upload
Input Parameters:        data, len
    data:                �������ݵ��׵�ַ
    len:                 �������ݵĳ���
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             ���������ϴ���Ϊ
****************************************************************************/
int tianyiyunpan_upload(char* data, unsigned short len)
{
    if(!data || len == 0)
        return -1;

    if(!strncmp(data, "PUT /putDCIUpload.action?", 25))
        return 0;
    else
        return -1;
}

/****************************************************************************
Function Name:           tianyiyunpan_download
Input Parameters:        data, len
    data:                �������ݵ��׵�ַ
    len:                 �������ݵĳ���
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             ��������������Ϊ
****************************************************************************/
int tianyiyunpan_download(char* data, unsigned short len)
{
    if(!data || len == 0)
        return -1;

    if(!strncmp(data, "GET /", 5) && strstr(data, "filename"))
        return 0;
    else
        return -1;
}

/****************************************************************************
Function Name:           wangyiyun
Input Parameters:        data, len
    data:                �������ݵ��׵�ַ
    len:                 �������ݵĳ���
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             ����������Ϊ
****************************************************************************/
int wangyiyun(char* data, unsigned short len)
{
    if(!data || len == 0)
        return -1;

    if(!strncmp(data, "GET /filehub/nf/dir?", 20))
        return 0;
    else
        return -1;
}

int tencent_video_upload(char* data, unsigned short len)
{
    if(!data || len == 0)
        return -1;

    if(!strncmp(data, "POST /fvupready?", 16))
        return 0;
    else
        return -1;
}

