#ifndef _THREADPOOL_H_
#define _THREADPOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* task status */
#define NONE 0
#define RUNNING 1
#define ENDED 2

/* thread pool error */
#define THR_P_INVALID -1
#define THR_P_LOCK_FAIL -2
#define THR_P_QUEUE_FULL -3
#define THR_P_SHUTDOWN -4
#define THR_P_THREAD_FAIL -5

/* thread pool shutdown */
#define THR_P_SHUT_IMMEDIATE 1
#define THR_P_SHUT_GRACEFUL 2

typedef struct threadpool_t threadpool_t;

#ifdef __cplusplus
}
#endif

#endif /* _THREADPOOL_H_ */

