#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileutils.h"

int set_nonblock(int fd)
{
	int flags;
#if defined(O_NONBLOCK)
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int set_block(int fd)
{
	int flags;
#if defined(O_NONBLOCK)
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	return -1;
#endif
}


int set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD); /* Fetch flags */
	if (flags == -1)
		return -1;

	flags |= FD_CLOEXEC;  /* Turn on FD_CLOEXEC */

	if (fcntl(fd, F_SETFD, flags) == -1)  /* Update flags */
		return -1;
	
	return 0;
}

int create_pid_file(const char *pid_file, const pid_t pid)
{
	int save_errno;
	char buf[20];
	int fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) return -1;
	if (set_cloexec(fd) == -1)
		return -1;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1)
		goto ERR;
	snprintf(buf, sizeof(buf), "%ld\n", (long) pid);
	if (write(fd, buf, strlen(buf)) != strlen(buf))
		goto ERR;
	return fd;
ERR:
	save_errno = errno;
	close(fd);
	errno = save_errno;
	return -1;
}

