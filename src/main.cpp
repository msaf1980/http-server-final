#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>

#include <arpa/inet.h>

#if defined(__linux)
#include <linux/limits.h>
#include <sys/sendfile.h>
#define __EPOLL__
#include <sys/epoll.h>
#elif defined(__FreeBSD__)
#include <sys/limits.h>
#include <sys/uio.h>
#define __KQUEUE__
#include <sys/event.h>
#endif

#include <getopt.h>

#include <queue>

#ifdef _GNU_SOURCE
#ifdef __cplusplus
extern "C"
{
#endif

/* force switch to posix-compliant strerror_r instead of GNU for portability */
extern int __xpg_strerror_r(int errcode, char* buffer, size_t length);
#define strerror_r __xpg_strerror_r

#ifdef __cplusplus
}
#endif
#endif


#include "errorhandle.h"
#include "fileutils.h"
#include "strutils.h"
#include "netutils.h"
#include "httpcodes.h"
#include "mimetypes.h"
#include "httputils.hpp"
#include "httpsrvutils.h"
#include "thrdpool.h"

#define WORKERS 4
#define WORKQUEUE  256 

#ifdef __EPOLL__
#include "epollutils.h"
#define EPOLL_TOUT -1 /* epoll timeout */

int epoll_fd;
#endif

#ifdef __KQUEUE__
int kq;
#endif

/* #define BACKLOG 20 */
#define BACKLOG SOMAXCONN
#define QUEUE 32 /* events queue for epoll or kqueue, also max workers */

#define LOG_FACILITY LOG_LOCAL1

#define BUFSIZE 65536

#include "datastruct.hpp"

extern short running;

short running = 1;
short verbose = 0;
short noclose = 0;
short use_sendfile = 0;
const char *name = "http_server"; 

sock_s cli_socks;
ssize_t bsize = BUFSIZE;

#define TASK_CLOSE 0
#define TASK_SHUTDOWN 1
#define TASK_READ 2
#define TASK_WRITE 3

#define READ 0
#define SEND 1

typedef struct
{
	int sock_fd;
	short event;
} task_t;


typedef struct
{
	char *ip;

	int port;
	char *root_dir;
} param_t;

param_t srv_param;

std::queue<task_t> queue;
thrdpool_t pool;


int log_init(const char *name)
{
	openlog(name, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_FACILITY);
	return 0;
}

void log_print_v(const int pri, const char *fmt, va_list ap)
{
	vsyslog(pri, fmt, ap);
}

void log_print(const int pri, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_print_v(pri, fmt, ap);
	va_end(ap);
}

void log_debug_v(const char *fmt, va_list ap)
{
	log_print_v(LOG_DEBUG, fmt, ap);
}

void log_debug(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_debug_v(fmt, ap);
	va_end(ap);
}

#define LOG_DEBUG_IF(cond, level, dlevel, fmt, ...) \
	if ( level >= dlevel && (cond) ) log_debug(fmt, __VA_ARGS__)

void log_print_errno(const int pri, int err, const char *descr1, const char *descr2)
{
	char err_buf[1024];
	strerror_r(err, err_buf, sizeof(err_buf));
	if (descr1 != NULL && descr2 != NULL)
		log_print(pri, "%s %s: %s (%d)", descr1, descr2, err_buf, err);
	else if (descr1 != NULL) 
		log_print(pri, "%s: %s (%d)", descr1, err_buf, err);
	else if (descr2 != NULL) 
		log_print(pri, "%s: %s (%d)", descr2, err_buf, err);
	else
		log_print(pri, "%s (%d)", err_buf, err);
}

/*
void log_request(const char *ip, 
		 const std::string & type, const std::string & version, 
		 const std::string & path, ssize_t size,
		 int status)
{
	char nbuf[30];
	size_t len = strlen(ip) + 1 + (type.size() + version.size() + path.size() + 5) + 15;
	std::string buf;
	buf.reserve(len);
	buf.append(ip).append(" ");
	buf.append("\"").append(type).append(" ").
		append(path).append(" ").
		append(version).append("\"");
	snprintf(nbuf, sizeof(nbuf), " %d %ld", status, size);

	buf.append(nbuf);
	log_print(LOG_INFO, "%s", buf.c_str());
}
*/

void log_request(const char *ip, 
		 const char *type, const char *version, 
		 const char *path, ssize_t size,
		 int status)
{
	log_print(LOG_INFO, "%s \"%s %s %s\" %d %ld", ip, type, path, version, status, size);
}

void app_shutdown(int sleep_time)
{
	running = 0;
	if (sleep_time > 0)
		sleep(sleep_time);
	log_print(LOG_INFO, "%s", "shutdown initiate");
	//exit(0);
}

void sig_handler(int sig)
{
	switch(sig) {
		case SIGHUP:
			log_print(LOG_INFO, "%s", "received SIGHUP signal");
			break;
		case SIGUSR1:
			log_print(LOG_INFO, "%s", "received SIGUSR1 signal");
			break;
		case SIGINT:
		case SIGTERM:
            app_shutdown(1);
			break;
	}
} 

int sig_handlers_init()
{
	int ec = 0;
	/* Handle signals */
	struct sigaction sa;

	/* Setup the signal handler */
	sa.sa_handler = &sig_handler;

	/* Restart the system call, if at all possible */
	sa.sa_flags = SA_RESTART;

	/* Block every signal during the handler */
	sigfillset(&sa.sa_mask);

	/* SIGTERM is intended to gracefull kill your process */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("Cannot handle SIGTERM");
		ec = 1;
	}

	/* Intercept SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGINT");
		ec = 1;
	}

	// Intercept SIGHUP
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGHUP");
		ec = 1;
	}

	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGUSR1");
		ec = 1;
	}

	return ec;
}

/*
 * Fork and init daemon child process
 */
int daemon_init(const int nochdir, const int noclose, const char *name)
{
	int fd0, fd1, fd2;
	int pid, i;
	struct rlimit rl;

	if ( (pid = fork()) == -1) {
		perror("fork");
		return(pid);
	} else if (pid > 0)
		return(pid);
	
	if (! nochdir) {
		if (chdir("/") == -1) {
			perror("can't chdir to root dir");
			return -1;
		}
	}

	umask(027); /* Set file permissions 750 */

	/* Get a new process group */
	if (setsid() == -1) {
		perror("can't setsid");
		return -1;
	}

	/* Init signal handler */
	if (sig_handlers_init())
		return -1;

	/* Close all descriptors */
	if (! noclose) {
		if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
			fprintf(stderr, "unable get max file descriptor\n");

		/* close all open file descriptors */
		if (rl.rlim_max == RLIM_INFINITY)
			rl.rlim_max = 1024;
		for (i = rl.rlim_max - 1; i >= 0; i--)
			close(i);

		/* Set file descriptors 0, 1 и 2 to /dev/null */
		 /* 'fd0' should be 0 */
		fd0 = open("/dev/null", O_RDWR);
		fd1 = dup(STDIN_FILENO);
		fd2 = dup(STDIN_FILENO);
	}
	
	/* Init log handler */
	if (log_init(name))
		return -1;
	
	if (! noclose && 
	    (fd0 != STDIN_FILENO || fd1 != STDOUT_FILENO || fd2 != STDERR_FILENO))
	{
		log_print(LOG_ERR, "%s", "incorrect standart file descriptors");
		return -1;
	}	

	return 0;
}

void close_socket(int sock_fd, int err)
{
	if (verbose) log_print(LOG_DEBUG, "%d: %s", sock_fd, "close");
	if (err != ECONNRESET)
		shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
	delete_socket(&cli_socks, sock_fd);
}

/*
 * On connection close (send return 0, errno set to ECONNRESET
 */
ssize_t send_to_socket(int sock_fd, char *buf, size_t size)
{
	size_t maxsize = BUFSIZE;
	size_t sendsize;
	size_t ssize = size;
	ssize_t s;
	char *p = buf;

	//int save_errno;

	while (ssize > 0)
	{
		sendsize = (ssize > maxsize ? maxsize : ssize);
		s = send(sock_fd, p, sendsize, MSG_NOSIGNAL);
		if (s == 0) /* connection closed, rewrite errno */
		{
			errno = ECONNRESET;
			/* close_socket(sock_fd, s, errno); */
			break;
		} else if (s == -1)
		{
			if (errno == EINTR) /* Interrupted by signal - retry read */
			{
				errno = 0;
			 	continue;
			}
			/* Close socket on error */
			/*
			else if (errno != EAGAIN && errno != EWOULDBLOCK) 
			{
				
				save_errno = errno;
				close_socket(sock_fd, s, errno);
				errno = save_errno;
				break;
			}
			*/
			else
				break; /* Non-block I/O */
		} else
		{
			if ( errno != 0 ) errno = 0;
			ssize -= s;
			if (ssize == 0)
				return size;	
			p += s;
		}
	}
	return size - ssize;
}

/*
 * On connection close (send return 0), errno set to ECONNRESET
 */
ssize_t send_file(int sock_fd, int fd,
                  char *buf, size_t size, size_t bsize, size_t *readed, size_t *sended)
{
        size_t ssize = size, readsize;
       	ssize_t r, s;

	/* buffer state, all 0 on success */
	*sended  = 0;
	*readed = 0;

        while (ssize > 0)
        {
		readsize = (ssize > bsize) ? bsize : ssize;
		if ( (r = read(fd, buf, readsize)) == -1)
		{
			if (errno == EINTR) /* Interrupted by signal - retry read */
			{
				errno = 0;
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) /* Block IO */
			{
				errno = 0;
				continue;
			}
			else
				return -1;
		} else if (r == 0)
		{
			if ( errno != 0 ) errno = 0;
			break;
		}

		s = send_to_socket(sock_fd, buf, r);
		if ( verbose > 1 )
		{
			int saveerrno = errno;
			log_print(LOG_INFO, "%d: read %lu, send %lu, file pos %lu, errno %d", sock_fd, r, s, lseek( fd, 0, SEEK_CUR ), saveerrno);
			errno = saveerrno;
		}
		if ( s >= 0 )
		{
			if (s > 0)
				ssize -= s;
		}
		if ( errno != 0 )
			break;
        }
	if ( s >= 0) 
	{
		*readed = r;
		*sended = s;
	}
        return size - ssize;
}

int send_header_file(int sock_fd, const char *path, const char *version, 
			 sock_item *si, int *status)
{
	struct stat fd_stat;
	ssize_t s;
	*status = 0;
	si->r = 0; si->s = 0;
	sprintf(si->buf, "%s%s", srv_param.root_dir, path);
	if ( (si->fd = open(si->buf, O_RDONLY)) == -1 )
	{
		snprintf(si->buf, si->bsize, not_found_resp_tmpl, version);
		*status = HTTP_NOT_FOUND;
	} else
	{
		if ( fstat(si->fd, &fd_stat) == -1 || (fd_stat.st_mode & S_IFMT) != S_IFREG )
		{
			snprintf(si->buf, si->bsize, not_found_resp_tmpl, version);
			close(si->fd); si->fd = -1;
			*status = HTTP_NOT_FOUND;
		} else
		{
			const char *mime_type = mime_type_by_file_ext(si->buf);
			si->fsize = fd_stat.st_size;
			snprintf(si->buf, si->bsize, "%s %s\r\nContent-Type: %s\r\n"
				 "Content-Length: %lu\r\n"
				 "\r\n", 
				 version,
				 ok_resp_tmpl_s,
				 mime_type,
				 si->fsize);
		}
	}
	si->r = strlen(si->buf);
	s = send_to_socket(sock_fd, si->buf, si->r);
	if ( s > 0 )
		si->s = s;
	return errno;
}

int send_file_to_socket(int sock_fd, sock_item *si)
{
	ssize_t s;

	if (! use_sendfile)
		s = send_file(sock_fd, si->fd, si->buf, si->fsize - si->sended, si->bsize, &si->r, &si->s);
	else
	{
#if defined(__linux)
		s = sendfile(sock_fd, si->fd, &si->sended, si->fsize - si->sended);
//#elif defined(__FreeBSD__)
#else
		s = send_file(sock_fd, si->fd, si->buf, si->fsize - si->sended, si->bsize, &si->r, &si->s);
#endif
	}
	if (s > 0)
		si->sended += s;
	/*
	 if ( s == si->fsize )
		return 0;
	else if ( errno != 0 ) return errno;	
	*/

	return errno;
}

int complete_send(int sock_fd, sock_item *si)
{
	int res  = 0;
	size_t s = 0;
	if ( si->r > si->s )
	{
		s = send_to_socket( sock_fd, si->buf + si->s, si->r - si->s );
		res = errno;
		if (s > 0)
		{
			si->s += s;
			if (si->sended >= 0)
			{
				si->sended += s;
				if (verbose > 1) log_print(LOG_INFO, "%d: resend %lu, read %lu, send %lu, errno %d", sock_fd, s, si->r, si->s, res);
			}
		}
		if (res != 0)
			return res;
	}
	if ( si->sended >= 0 )
	{
		res = send_file_to_socket( sock_fd, si );
		if (verbose) log_print(LOG_INFO, "%d: sended %lu, fsize %lu, errno %d", sock_fd, si->sended, si->fsize, res);
	}
	return res;
}

int process_request(int sock_fd, const char *ip, sock_item *si)
{
	header_map header;
	//ssize_t respsize = 0; /* responce size without header */
	int status = HTTP_UNSUPPORTED;
	int res = 0;
	ssize_t s;

	if ( si->r == 0 )
		return EINVAL;
	std::string type = "-", version = "-", path = "-";

	const char *header_end = parse_http_req_header(si->buf, si->buf + si->r, header);
	auto h_type = header.find("Type");
	auto h_version = header.find("Version");
	if (h_version != header.end()) version = h_version->second;
	auto h_path = header.find("Path");
	if (h_path != header.end()) path = h_path->second;

	/* Incomplete header */
	
	if (header_end == si->buf)
		status = HTTP_BAD_REQ;
	else if (header_end > si->buf)	
	{
		if (h_type == header.end() || h_version == header.end())
			status = HTTP_BAD_REQ;
		else
		{
			type = h_type->second;

			if ( type == "HEAD" )
				return send_header_file(sock_fd, path.c_str(), version.c_str(), si, &status);
			else if ( type == "GET" )
			{
				res = send_header_file(sock_fd, path.c_str(), version.c_str(), si, &status);
				if ( res != 0 )
					return res;
				/* set_nonblock(si->fd); */
				si->sended = 0;
				if ( si->fsize == 0 )
					return 0;
				errno = 0;
				return send_file_to_socket(sock_fd, si);
			} /* GET */
		}
	}
	else /* incorrect header */
		status = HTTP_BAD_REQ;

	if (status == HTTP_BAD_REQ)
		snprintf(si->buf, si->bsize, bad_req_resp_tmpl, HTTP_v1_0);
	else /* status == HTTP_UNSUPPORTED */
	{
		snprintf(si->buf, si->bsize, unsup_req_resp_tmpl, HTTP_v1_0);
		status = HTTP_BAD_REQ;
	}
	si->r = strlen(si->buf);
	s = send_to_socket(sock_fd, si->buf, si->r);
	if ( s > 0 )
		si->s = s;
	return errno;
}

int read_socket(int sock_fd, sock_item *si)
{
	char ip[INET_ADDRSTRLEN];
	SA_IN cli_addr;
	socklen_t cli_addr_len;

	/* buffer and buffer size */
	int res = 0;
	ssize_t n, read;
	
	cli_addr_len = sizeof(cli_addr);
	getsockname(sock_fd, (struct sockaddr *) &cli_addr, &cli_addr_len);
	inet_ntop(AF_INET, &(cli_addr.sin_addr), ip, INET_ADDRSTRLEN);

	if ( si->r == si->s )
	{
		si->r = 0;
		si->s = 0;
	}
	if (si->s) return EINVAL;
	
	if (si->buf == NULL)
	{
		if ( (si->buf = (char *) malloc(bsize)) == NULL )
		{
			log_print(LOG_ERR, "%s", "buf alloc");
			return ENOMEM;
		}
		si->bsize = bsize;
	}
	read = si->bsize - si->r;
	while (1)
	{
		n = recv(sock_fd, si->buf + si->r, read, MSG_NOSIGNAL);
		if (n == 0)
		{
			res = ECONNRESET;
			break;
		}
		else if (n == -1)
		{
			if (errno == EINTR) /* Interrupted by signal - retry read */
			{
				errno = 0;
				continue;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK) /* No more data on nonblocking socket */
			{
				res = process_request(sock_fd, ip, si);
				if (verbose) log_print(LOG_INFO, "%d: sended %lu, fsize %lu, errno %d", sock_fd, si->sended, si->fsize, res);
				break;		
			}
			else /* Close socket on error */
			{
				res = errno;
				break;
			}
		}
		else
		{
			si->r += n;
			if (si->r == si->bsize)
			{
				res = process_request(sock_fd, ip, si);
				//p = rwbuf; read = rwbsize;
				//r = 0;
				if (verbose) log_print(LOG_INFO, "%d: sended %lu, fsize %lu, errno %d", sock_fd, si->sended, si->fsize, res);
				break;
			}
		}
	}
	/*
	if ( res == EAGAIN || res == EWOULDBLOCK ) 
		return res;
	*/
	//close_socket(sock_fd, res); 
	return res;
}

void client_register(int sock_fd, SA_IN *cli_addr)
{
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(cli_addr->sin_addr), ip, INET_ADDRSTRLEN);
	if (verbose) log_print(LOG_INFO, "%d: connect from %s", sock_fd, ip);
	add_socket(&cli_socks, sock_fd, NULL);
}

void do_task(task_t *task)
{
	sock_item *si;
	int res = 0;
	if ( (si = find_socket(&cli_socks, task->sock_fd)) == NULL )
	{
		log_print(LOG_ERR, "%s", "socket descriptor not in table");
		close_socket(task->sock_fd, -1); 
	} else if ( si->process == 0 )
	{
		si->process = 1;
		if (task->event == READ)
		{
			res = read_socket(task->sock_fd, si);
			if ( res == EAGAIN || res == EWOULDBLOCK )
			{
				if ( si->block == 0 )
				{
					if (verbose) log_print( LOG_INFO, "%d: %s", task->sock_fd, "async" );
#if defined(__EPOLL__)
					struct epoll_event event;
					EPOLL_EVENT_SET( event, task->sock_fd, EPOLLET | EPOLLOUT | EPOLLIN | EPOLLRDHUP );
					if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->sock_fd, &event) == -1)
						log_print_errno(LOG_ERR, errno, "epoll mod", NULL);
#elif defined(__KQUEUE__)
					struct kevent event;
					memset(&event, 0, sizeof(event));
					EV_SET(&event, task->sock_fd, EVFILT_WRITE, EV_ADD|EV_ENABLE, 0, 0, NULL);
					if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
						log_print_errno(LOG_ERR, errno, "kevent set", NULL);
#endif
					else
                        		        si->block = 1;
				}
				si->process = 0;
			}
			else
				close_socket(task->sock_fd, 0); 
		} else if (task->event == SEND)
		{
			res = complete_send(task->sock_fd, si);
			if ( res != EAGAIN && res != EWOULDBLOCK )
				close_socket(task->sock_fd, -1);
			else
				si->process = 0;
		}

	}
}

void *process(void *thrdpool)
{
	thrdpool_t *pool = (thrdpool_t *) thrdpool;
	while (! pool->shutdown)
	{
		/* Wait on condition variable */
		pthread_mutex_lock(&(pool->lock));
		pthread_cond_wait(&(pool->notify), &(pool->lock));
	
		if (pool->shutdown)
			break;
		while (! pool->shutdown)
		{
			/* Do blocked part of task, for example read from queue */
			if (queue.size() == 0)
			{
				pthread_mutex_unlock(&(pool->lock));
				break;
			}
			task_t task = queue.front();
			queue.pop();
			/* Unlock */
			pthread_mutex_unlock(&(pool->lock));

			/* Do a task */
			do_task(&task);

			/* Lock and try get task from queue */
			pthread_mutex_lock(&(pool->lock));
		}
	}
	pthread_mutex_unlock(&(pool->lock));
	return NULL;
}

int queue_io(int sock_fd, short event)
{
	int ec = 0;
	task_t task;
	task.sock_fd = sock_fd;
	task.event = event;
	if (queue.size() > WORKQUEUE)
	{
		if (verbose) log_print(LOG_DEBUG, "%s", "queue full");
		return 1;
	}
       	queue.push(task);
	if ( (ec = thrdpool_notify(&pool)) )
		log_print(LOG_ERR, "%s", thrdpool_error[ec]);
	return ec;
}

#ifdef __EPOLL__
int loop_epoll(int srv_fd) 
{
	int ec = 0;

	int cli_fd;

	socklen_t cli_addrlen;
	SA_IN cli_addr;

	int n_events, i; /* for epoll */
	struct epoll_event event, events[QUEUE];

	//ssize_t r;
	//char buf[BUFSIZE];

	EC_ERRNO( (epoll_fd = epoll_create1(0)) == -1, EXIT,
		  log_print_errno(LOG_ERR, ec, "epoll_create", NULL) );

	/* EPOLL_EVENT_SET(event, srv_fd, EPOLLIN | EPOLLET); */
	EPOLL_EVENT_SET( event, srv_fd, EPOLLIN );
	EC_ERRNO( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, srv_fd, &event) == -1, EXIT,
		  log_print_errno(LOG_ERR, ec, "epoll add listen socket", NULL) );
	
	//event.events |= EPOLLRDHUP;

	while (running)
	{
		/* epoll */
		n_events = epoll_wait(epoll_fd, events, QUEUE, EPOLL_TOUT);
		if ( n_events == -1 )
		{
			if ( errno != EINTR ) log_print_errno(LOG_ERR, ec, "epoll_wait", NULL);
			goto CLEAN;
		}

		for (i = 0; i < n_events; i++)
		{
			if (events[i].data.fd == srv_fd)
			{
				EC( events[i].events & (EPOLLHUP | EPOLLERR), CLEAN, 1, 
				    log_print(LOG_ERR, "%s", "epoll_wait error on listen socket") );

				cli_addrlen = sizeof(cli_addr);
				cli_fd = accept(srv_fd, (SA *) &cli_addr, &cli_addrlen);
				if (cli_fd < 0)
					log_print_errno(LOG_ERR, errno, "accept", NULL);
				{
					set_nonblock(cli_fd);
					client_register(cli_fd, &cli_addr);
					EPOLL_EVENT_SET( event, cli_fd, EPOLLET | EPOLLIN | EPOLLRDHUP );
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cli_fd, &event) == -1)
						log_print_errno(LOG_ERR, ec, "epoll add", NULL);
				}
			}
			else
			{
				if (events[i].events & (EPOLLHUP | EPOLLERR))
					close_socket(events[i].data.fd, errno);
				else if (events[i].events & EPOLLRDHUP)
					close_socket(events[i].data.fd, errno);
				else if (events[i].events & EPOLLIN)
				{
					if (queue_io(events[i].data.fd, READ))
						close_socket(events[i].data.fd, 0); 
				}
				else if (events[i].events & EPOLLOUT)
				{
					if (queue_io(events[i].data.fd, SEND))
						close_socket(events[i].data.fd, 0); 
				}
			}
		}
	}
CLEAN:

EXIT:
	return ec;
}
#endif /* epoll */ 

#ifdef __KQUEUE__
int loop_kqueue(int srv_fd)
{
	int ec = 0;
	int res = 0;
	int i;
	
	int cli_fd;

	socklen_t cli_addrlen;
	SA_IN cli_addr;

	struct kevent event, events[QUEUE];

	ssize_t r;

	EC_ERRNO( (kq = kqueue()) == -1, EXIT,
			log_print_errno(LOG_ERR, ec, "kqueue", NULL) ); 

	memset(&event, 0, sizeof(event));
	EV_SET(&event, srv_fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	EC(  kevent(kq, &event, 1, NULL, 0, NULL) == -1, EXIT, 1,
			log_print_errno(LOG_ERR, ec, "kevent set register listen socket", NULL) );
	EC( (event.flags & EV_ERROR), EXIT, 1,
			log_print_errno(LOG_ERR, event.data, "event error", NULL) );
	
	while(running)
	{
		EC_ERRNO( (r = kevent(kq, NULL, 0, events, QUEUE, NULL)) == -1, CLEAN,
				log_print_errno(LOG_ERR, ec, "kevent read", NULL) );

		for (i = 0; i < r; i++) /* event process loop */
		{
			if (events[i].ident == srv_fd)
			{
				cli_addrlen = sizeof(cli_addr);
				cli_fd = accept(srv_fd, (SA *) &cli_addr, &cli_addrlen);
				if (cli_fd < 0)
					log_print_errno(LOG_ERR, errno, "accept", NULL);
				else
				{
					set_nonblock(cli_fd);
					client_register(cli_fd, &cli_addr);
					memset(&event, 0, sizeof(event));
					EV_SET(&event, cli_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
					if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
						log_print_errno(LOG_ERR, errno, "kevent set", NULL);
				}
			}
			else
			{
				if (events[i].flags & EV_EOF)
				{
					close_socket(events[i].ident, 0);
				}
				else if (events[i].filter == EVFILT_READ)
				{
					if (queue_io(events[i].ident, READ))
						close_socket(events[i].ident, 1); 
				}
				else if (events[i].filter == EVFILT_WRITE)
				{
					sock_item *si;
					if ( (si = find_socket(&cli_socks, events[i].ident)) == NULL )
					{
						log_print(LOG_ERR, "%s", "socket descriptor not in table");
						close_socket(events[i].ident, -1); 
					}
					else if ( si->process == 0 )
					{
						if (queue_io(events[i].ident, SEND))
							close_socket(events[i].ident, 1); 
					}
				}
			}
		} /* event process loop */
	}

CLEAN: 

EXIT: 
	return ec;
}
#endif /* kqueue */

int start_server()
{
	int ec = 0;
	int srv_fd; /* server socket */
	SA_IN srv_addr;

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
        EC_ERRNO( srv_fd == -1, EXIT, log_print_errno(LOG_ERR, ec, "socket", NULL) );
	set_reuseaddr(srv_fd);

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(srv_param.port);
	if (srv_param.ip == NULL)
		srv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* List on any IP */
	else EC( inet_aton(srv_param.ip, &srv_addr.sin_addr) == 0, EXIT, 1,
		log_print(LOG_ERR, "invalid address: %s", srv_param.ip) );
	EC_ERRNO( bind(srv_fd, (SA *) &srv_addr, sizeof(srv_addr)) == -1, EXIT, 
		log_print_errno(LOG_ERR, ec, "bind", NULL) );
	set_nonblock(srv_fd);
		
	EC_ERRNO( listen(srv_fd, BACKLOG) == -1, EXIT,
		log_print_errno(LOG_ERR, ec, "listen", NULL) );

	log_print(LOG_INFO, "%s", "startup");

#ifdef __EPOLL__
	ec = loop_epoll(srv_fd);
#endif
#ifdef __KQUEUE__
	ec = loop_kqueue(srv_fd);
#endif 

	for ( auto it = cli_socks.begin(); it != cli_socks.end(); )
	{
		close_socket(it->first, 0);
		delete_socket_iter( &cli_socks, it++);
	}

	log_print(LOG_INFO, "%s", "shutdown");

EXIT:
	return ec;
}

int main(int argc, char *argv[])
{
	int pid;

	srv_param.ip = NULL;
	srv_param.port = 12345;
	srv_param.root_dir = NULL;

	int opt = 0;
	int opt_idx = 0;
	
	const char *opts = "h:p:d:sv:";
	const struct option long_opts[] = {
		{ "ip",   required_argument, 0,  'h' },
		{ "port", required_argument, 0,  'p' },
		{ "dir",  required_argument, 0,  'd' },
		{ "sendfile", no_argument, 0,  's' },
		{ "verbose", required_argument,  0,  'v' },
		{ 0, 0, 0, 0 }
	};
	
	while( (opt = getopt_long(argc, argv, opts, long_opts, &opt_idx)) != -1 ) 
	{
		switch( opt )
		{
			case '?': /* unknown command */
				return EXIT_FAILURE;
			case 0: /* binded option, set by getopt */
				break;
			case 'h':
				srv_param.ip = optarg;
				if (is_valid_ipv4(srv_param.ip) == 0)
				{
					fprintf(stderr, "wrong ip adderss: %s\n", optarg);
					exit(1);
				}
				break;
			case 'p':
				srv_param.port = atoi(optarg);
				if (srv_param.port < 1)
				{
					fprintf(stderr, "port must be a number: %s\n", optarg);
					return EXIT_FAILURE;
				}
				break;
			case 'd':
				srv_param.root_dir = optarg;
				break;
			case 's':
				use_sendfile = 1;
				break;
			case 'v':
				if ( is_num( optarg ) )
					verbose = atoi( optarg );
				else
				{
					fprintf(stderr, "verbose must be a number\n");
					return EXIT_FAILURE;
				}
				break;
			default:
				fprintf(stderr, "unhadled option: %u\n", (unsigned char) opt);
				return EXIT_FAILURE;
		}
	}
	if (optind < argc)
	{
		fprintf (stderr, "Non-option arguments: ");
		while (optind < argc)
		        fprintf (stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
		exit(1);
	}

	if (srv_param.root_dir == NULL)
	{
	       fprintf (stderr, "root dir not set\n");
	       exit(1);
	}
	
	if ((pid = daemon_init(0, 0, name)) == -1)
		exit(1);
	else if (pid == 0) /* child */
	{	
		int ec = 0;
		pthread_attr_t t_attr;
		ECN( (ec = pthread_attr_init(&t_attr)) != 0, EXIT, PERROR("pthread_attr", ec) ) ;
		if ( (ec = thrdpool_init(&pool, WORKERS, t_attr, process)) )
		     log_print(LOG_ERR, "%s", thrdpool_error[ec]);
		else
			start_server();
EXIT:
		exit(0);
	}
	return 0;
}

