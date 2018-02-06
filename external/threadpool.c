#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "threadpool.h"

typedef struct
{
	void (*function)(void *);
	void *argument;
	int status; /* NONE, RUNNING, ENDED */
	int res; /* result */
}
thread_task_t; 

struct threadpool_t
{
	pthread_mutex_t lock;
	pthread_cond_t notify;
	pthread_t *threads;
	thread_task_t *queue; /* queue */
	size_t queue_size; /*  queue size */
	size_t tasks; /* running tasks */
	size_t pend; /* pending tasks */
	size_t thread_count; /* current threads */
	size_t thread_c_init; /* initial threads */
	//size_t thread_c_max; /* max threads */
	short shutdown; /* pool shutdown flag */
};

/**
 * @function void *threadpool_thread(void *threadpool)
 * @brief the worker thread
 * @param threadpool the pool which own the thread
 */
static void *threadpool_thread(void *threadpool); 

int threadpool_destroy( threadpool_t *pool, int flags );
int threadpool_free( threadpool_t *pool );

int threadpool_create( threadpool_t *pool, size_t thread_count, size_t queue_size, int flags )
{
	size_t i;

	if(thread_count == 0  || queue_size == 0)
		return -1;

	pool->thread_count = 0;
	pool->queue_size = (queue_size > thread_count ? queue_size : thread_count);

	/* Initialize */
	pool->shutdown = 0; 
	pool->queue = NULL;

	/* Allocate thread and task queue */
	if ( (pool->threads = malloc( sizeof(pthread_t) * pool->thread_count )) == NULL)
		goto ERR;
	if ( (pool->queue = malloc( sizeof(thread_task_t) * pool->queue_size )) == NULL)
		goto ERR;

	/* Initialize mutex and conditional variable first */
	if ( pthread_mutex_init(&(pool->lock), NULL) != 0 ||
	     pthread_cond_init(&(pool->notify), NULL) != 0 )
		goto ERR;

	/* Start worker threads */
	for ( i = 0; i < thread_count; i++ )
	{
		if ( pthread_create( &(pool->threads[i]), NULL,
			threadpool_thread, (void*)pool ) != 0 )
		{	
			threadpool_destroy(pool, 0);
			return -1;
		}
		pool->thread_count++;
	}

	return 0;

ERR:
	threadpool_free(pool);
	return -1;
} 

int threadpool_destroy(threadpool_t *pool, int flags)
{
	size_t i;
	int err = 0;

	if ( pool == NULL )
		return THR_P_INVALID;

	if ( pthread_mutex_lock(&(pool->lock) ) != 0 )
		return THR_P_LOCK_FAIL;

	do
	{
		/* Already shutting down */
		if( pool->shutdown )
			return THR_P_SHUTDOWN;

		pool->shutdown = (flags & THR_P_SHUT_GRACEFUL) ?
			THR_P_SHUT_GRACEFUL : THR_P_SHUT_IMMEDIATE;

	        /* Wake up all worker threads */
		if( pthread_cond_broadcast( &(pool->notify) ) != 0 ||
		    pthread_mutex_unlock( &(pool->lock) ) != 0 )
		{
			return THR_P_LOCK_FAIL;
			break;
		}

		/* Join all worker thread */
		for ( i = 0; i < pool->thread_count; i++ )
		{
			if ( pthread_join(pool->threads[i], NULL) != 0 )
				err = THR_P_THREAD_FAIL;
		}
	}
	while (0);

	/* If all done, deallocate the pool */
	if ( ! err )
		threadpool_free( pool );
	return err;
}

int threadpool_free( threadpool_t *pool )
{
	if ( pool == NULL || pool->tasks > 0 )
		return -1;

	if ( pool->threads || pool->queue )
	{
		pthread_mutex_lock( &(pool->lock) );
	        pthread_mutex_destroy( &(pool->lock) );
        	pthread_cond_destroy( &(pool->notify) );
	}

	free(pool->queue);
	free(pool->threads);
	return 0;
}

static void *threadpool_thread(void *threadpool)
{
    threadpool_t *pool = (threadpool_t *) threadpool;
    threadpool_task_t task;

    while ( ! poll->shutdown )
    {
        /* Lock must be taken to wait on conditional variable */
        if ( pthread_mutex_lock( &(pool->lock) ) != 0)
		break;	

        /* Wait on condition variable, check for spurious wakeups.
           When returning from pthread_cond_wait(), we own the lock. */
        while((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if((pool->shutdown == immediate_shutdown) ||
           ((pool->shutdown == graceful_shutdown) &&
            (pool->count == 0))) {
            break;
        }

        /* Grab our task */
        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count -= 1;

        /* Unlock */
        pthread_mutex_unlock(&(pool->lock));

        /* Get to work */
        (*(task.function))(task.argument);
    }

    pool->started--;

    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
    return(NULL);
}  

