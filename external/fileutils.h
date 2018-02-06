#ifndef __FILEUTILS_H__
#define __FILEUTILS_H__

#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Set NONBLOCK flag on file descriptor
 */
int set_nonblock(int fd);
/*
 * Reset NONBLOCK flag on file descriptor
 */
int set_block(int fd);

/*
 * Set CLOEXEC flag on file descriptor
 */
int set_cloexec(int fd);

/* 
 * create and lock pid file
 * @param pid_file Path to pid file
 * @param pid Pid of process
 * @return fd of pid file or -1 on error
 * check errno for additional error info
 * EAGAIN returned on locked file
 */
int create_pid_file(const char *pid_file, const pid_t pid);

#ifdef __cplusplus
}
#endif  

#endif /* __FILEUTILS__ */

