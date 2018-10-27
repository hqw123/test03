#include <iostream>
#include <string.h>

/****************************************************************************
Function Name:           tianyiyunpan_upload
Input Parameters:        data, len
    data:                传入数据的首地址
    len:                 传入数据的长度
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             天翼云盘上传行为
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
    data:                传入数据的首地址
    len:                 传入数据的长度
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             天翼云盘下载行为
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
    data:                传入数据的首地址
    len:                 传入数据的长度
Output Parameters:       void
Return Code:             -1:fail, 0:success
Description:             网易云盘行为
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

