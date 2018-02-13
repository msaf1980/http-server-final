#include <stdlib.h>
#include "pthread.h"

#include "thrdpool.h"


int thrdpool_init(thrdpool_t *pool, size_t workers, pthread_attr_t attr, void *(*function)(void *))
{
	int ec = 0;
	size_t i;
	if ( pool == NULL || workers == 0) return THRDPOOL_INVALID;

	if ( (pool->workers = malloc(sizeof(pthread_t) * workers)) == NULL )
		return THRDPOOL_NOMEM;

	//pool->tasks = 0;
	pool->shutdown = 0;

	/* Initialize mutex and conditional variable first */ 
	ec = pthread_mutex_init(&(pool->lock), NULL);
	if (! ec)  ec = pthread_cond_init(&(pool->notify), NULL);
	if (ec)
	{
		thrdpool_free(pool);
		return ec;
	}

	/* Create workers thread */	
	for (i = 0; i < workers; i++)
	{
		if ( (ec = pthread_create(pool->workers + i, &attr, *function, (void*) pool)) != 0 )
		{
			thrdpool_destroy(pool, 0);
			return ec;
		}
		pool->count++;
	}

	return 0;
}

int thrdpool_destroy(thrdpool_t *pool, int immediate)
{
	int i, ec = 0;
	if (pool == NULL) return THRDPOOL_INVALID;
	if ( pthread_mutex_lock(&(pool->lock)) != 0 )
		return THRDPOOL_LOCK_FAIL;
	do
	{
		if (pool->shutdown)
		{
			ec = THRDPOOL_SHUTDOWN;
			break;
		}
		pool->shutdown = (immediate) ? THRDPOOL_SHUT_IMMEDIATE : THRDPOOL_SHUT_GRACEFUL ;

		/* Wake up all worker threads */
		if ( (pthread_cond_broadcast(&(pool->notify)) != 0) ||
		     (pthread_mutex_unlock(&(pool->lock)) != 0) )
		{
			ec = THRDPOOL_LOCK_FAIL;
			break;
		}

		/* Join all worker thread */ 
		for (i = 0; i < pool->count; i++)
		{
			if ( pthread_join(pool->workers[i], NULL) == 0 )
				pool->workers[i] = -1;
			else
				ec = THRDPOOL_THREAD_FAIL;

		}

	} while (0);

	/* Only if everything went well do we deallocate the pool */
	if (! ec) 
		return thrdpool_free(pool);
	else
		return ec;
}

int thrdpool_free(thrdpool_t *pool)
{
	if (pool == NULL) return THRDPOOL_INVALID;
	//if (pool->tasks > 0) return THRDPOOL_RUNNING;
	if (pool->workers)
	{
		free(pool->workers);
	        pthread_mutex_lock(&(pool->lock));
		pthread_mutex_destroy(&(pool->lock));
		pthread_cond_destroy(&(pool->notify));
	}
	return 0;
}

int thrdpool_notify(thrdpool_t *pool)
{
	if (pool->shutdown)
		return THRDPOOL_SHUTDOWN;
	if ( (pthread_mutex_lock(&(pool->lock)) != 0) ||
	     (pthread_cond_signal(&(pool->notify)) != 0) ||
	     (pthread_mutex_unlock(&pool->lock) != 0) )
		return THRDPOOL_LOCK_FAIL;
	return 0;
}

