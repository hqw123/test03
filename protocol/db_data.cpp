
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <boost/thread/mutex.hpp>

#include "db_data.h"

static boost::mutex g_mutex;
static void *g_shmaddr = NULL;
static int g_shmid = 0;
static sem_t *g_prsem;
//static sem_t *g_pwsem;
static long send_count = 0;

/******************************************************************************************
Function name:  share_memory_init
Describe :      create shared memory
******************************************************************************************/
int share_memory_init(int num)
{
    char rsem[5] = "rsem";
	int share_memory_key = (int)SHM_KEY + num;

    //���������ڴ�
    if((g_shmid = shmget((key_t)share_memory_key, BUFF_SIZE+2, 0666 | IPC_CREAT)) < 0)
    {
        printf("Fail to shmget.\n");
        return -1;
    }

    rsem[4] = num + '0';
    if((g_prsem = sem_open(rsem, O_CREAT, 0666, 0)) == SEM_FAILED)
    {
        printf("Fail to rsem open.\n");
        return -1;
    }
#if 0
    if((g_pwsem = sem_open("wsem", O_CREAT, 0666, 1)) == SEM_FAILED)
    {
        printf("Fail to wsem open.\n");
        return -1;
    }
#endif
    //ӳ�乲���ڴ�
    if((g_shmaddr = shmat(g_shmid, NULL, 0)) == (void *)-1)
    {
        printf("Fail to shmat.\n");
        return -1;
    }

	return 0;
}

/******************************************************************************************
Function name:  share_memory_cleanup
Describe :      release shared memory
******************************************************************************************/
void share_memory_cleanup(void)
{
    //�ѹ����ڴ�ӵ�ǰ�����з���
    if(shmdt(g_shmaddr) < 0)
    {  
        printf("shmdt failed.\n");  
        exit(EXIT_FAILURE);
    }
	
    //ɾ�������ڴ�
    if(shmctl(g_shmid, IPC_RMID, 0) == -1)
    {  
        printf("shmctl(IPC_RMID) failed.\n");  
        exit(EXIT_FAILURE);  
    }

    //�ر������źŵ�
    if (sem_close(g_prsem) == -1)
    {  
        printf("sem_close failed.\n");
        exit(EXIT_FAILURE);
    }    
}

/******************************************************************************************
Function name:  db_write_data
Describe :      write data to shared memory, only for inserting operation
******************************************************************************************/
int db_write_data(DB_DATA_TYPE type, void *data, size_t len)
{
    boost::mutex::scoped_lock lock(g_mutex);

	DB_DATA_T *db_data = (struct db_data_t *)g_shmaddr;

	/*type*/
	db_data->type = type;

	/*data*/
	memcpy(db_data+2, data, len);
	send_count++;
	//printf("send num=%d.\n", send_count);

	if (sem_post(g_prsem) < 0)
	{
		printf("Fail to sem_post prsem.\n");
		return -1;
	}

	return 0;
}


