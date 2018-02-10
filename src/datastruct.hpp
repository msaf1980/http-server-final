#ifndef _DATASTRUCT_H_
#define _DATASTRUCT_H_

#include <unistd.h>

//#include "sparsepp/spp.h"
#include <unordered_map>

typedef struct
{
	int sock_fd; /* socket descriptor */
	int fd; /* file descriptor */
	size_t fsize; /* file size */
	char *buf; /* buffer for non-block I/O */
	size_t bsize; /* buffer size */
	size_t r; /* bytes in buffer */
	size_t s; /* send bytes from buffer */
	ssize_t sended; /* total send bytes for data, not header */
	short block; /* block I/O event */
	//short send; /* send in progress */
} sock_item;

#define SOCK_ITEM_INIT(si, sd) \
		do { \
			si.sock_fd = sd; si.fd = -1; si.fsize = 0; si.buf = NULL; \
			si.r = 0; si.s = 0; si.sended = -1; si.block = 0; \
		} while (0)

#define SOCK_ITEM_PINIT(si, sd) \
		do { \
			si->sock_fd = sd; si->fd = -1; si->fsize = -1; si->buf = NULL; \
			si->r = 0; si->s = 0; si->sended = -1; si->block = -1; \
		} while (0)

#define SOCK_ITEM_FREE(si) \
		do { \
			if (si.fd) close(si.fd); free(si.buf); \
		} while (0)

#define SOCK_ITEM_PFREE(s) \
		do { \
			if (si->fd) close(si->fd); free(si->buf); \
		} while (0)

/*
typedef spp::sparse_hash_map<int, sock_item> sock_s;
typedef sock_s::iterator sock_s_it;
*/
typedef std::unordered_map<int, sock_item> sock_s;
typedef sock_s::iterator sock_s_it;

/*
#ifdef __cplusplus
extern "C" {
#endif
*/

sock_item *find_socket(sock_s *fds, int sock_fd);
sock_item *add_socket(sock_s *fds, int sock_fd, short *found);
/* 
 * @return 0 - found, 1 - not found
 */
int delete_socket(sock_s *fds, int sock_fd);
int delete_socket_iter(sock_s *fds, sock_s_it s);

/*
#ifdef __cplusplus
}
#endif
*/

#endif /* _DATASTRUCT_H_ */

