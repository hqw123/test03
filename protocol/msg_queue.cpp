
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <sys/msg.h> 
#include <errno.h> 

#include "db_data.h"

static int msg_id = -1;
static long send_count = 0;
static long drop_count = 0;

/******************************************************************************************
Function name:  msg_queue_init
Describe :      create message queue
******************************************************************************************/
int msg_queue_init(int num)
{
    int share_memory_key = (int)MSG_KEY + num;
    
    msg_id = msgget((key_t)share_memory_key, 0666 | IPC_CREAT);
    if (msg_id == -1)
    {
        printf("msgget failed with error: %d\n", errno);
        return -1;
    }

	return msg_id;
}

/******************************************************************************************
Function name:  msg_queue_cleanup
Describe :      delete message queue
******************************************************************************************/
void msg_queue_cleanup(void)
{
    if (msgctl(msg_id, IPC_RMID, 0) == -1)
    {          
        printf("msgctl(IPC_RMID) failed\n");
    }
}

/******************************************************************************************
Function name:  msg_queue_recv_data
Describe :      receive data from message queue
******************************************************************************************/
int msg_queue_recv_data(struct msg_t *data)
{
    if (msgrcv(msg_id, (void*)data, BUFF_SIZE, 0, 0) == -1)
    {
        printf("msgrcv failed with errno: %d\n", errno);
        return -1;
    }          
   
    return 0;
}

/******************************************************************************************
Function name:  msg_queue_send_data
Describe :      send data into message queue
******************************************************************************************/
int msg_queue_send_data(DB_DATA_TYPE type, void *data, size_t len)
{
    MSG_T db_data;
    size_t cp_len = len;

	/*type*/
	db_data.msg_type = type;

	/*data*/
    if (cp_len >= BUFF_SIZE)
        cp_len = BUFF_SIZE-1;
    
	memcpy(db_data.data, data, cp_len);

    if (msgsnd(msg_id, (void*)&db_data, BUFF_SIZE, IPC_NOWAIT) == -1)
    {
        drop_count++;
        //printf("msgsnd failed, error: %d\n", errno);
        return -1;
    }

    send_count++;

    return 0;
}


