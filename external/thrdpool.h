#ifndef _THRDPOOL_H_
#define _THRDPOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define THRDPOOL_INVALID 1
#define THRDPOOL_LOCK_FAIL 2
#define THRDPOOL_THREAD_FAIL 2
#define THRDPOOL_SHUTDOWN 3
#define THRDPOOL_RUNNING 4
#define THRDPOOL_NOMEM 5 

#define THRDPOOL_SHUT_GRACEFUL 0
#define THRDPOOL_SHUT_IMMEDIATE 1

/*
 * Thread run function example
 *
void *process(void *thrdpool)
{
	thrdpool_t *pool = (thrdpool_t *) thrdpool;
	while (1)
	{
		//Wait on condition variable
		pthread_mutex_lock(&(pool->lock));
		pthread_cond_wait(&(pool->notify), &(pool->lock));
	
		if (pool->shutdown)
			break;

		//Do blocked part of task, for example read from queue


		//Unlock
		pthread_mutex_unlock(&(pool->lock));

		//Do a task

	}
	pthread_mutex_unlock(&(pool->lock));
	return NULL;
}
*/

const char * const thrdpool_error[] =
{
	"invalid pool",
	"pool lock failure",
	"pool worker failure",
	"pool was shutdown",
	"pool is running",
	"pool memory alloc failed"
};

/**
 * @struct thrdpool
 * @brief	     Pthread worker pool struct
 * @var lock         Mutex variable fo notify
 * @var notify       Condition variable to notify worker threads.
 * @var workers	     Workers
 * @var count	     Number of workkers;
 */
struct thrdpool_t
{
	pthread_mutex_t lock;
	pthread_cond_t notify;
	pthread_t *workers; /* workers */
	size_t count; /* number of workers */
	//size_t tasks; /* number of running tasks */
	short shutdown;
};

typedef struct thrdpool_t thrdpool_t;


int thrdpool_init(thrdpool_t *pool, size_t workers, pthread_attr_t attr, void *(*function)(void *));
int thrdpool_destroy(thrdpool_t *pool, int flags);
int thrdpool_free(thrdpool_t *pool);
int thrdpool_notify(thrdpool_t *pool);
	
#ifdef __cplusplus
}
#endif

#endif /* _THRDPOOL_H_ */
