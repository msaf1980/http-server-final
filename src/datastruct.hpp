#ifndef _DATASTRUCT_H_
#define _DATASTRUCT_H_

//#include "sparsepp/spp.h"
#include <unordered_map>

typedef struct
{
	int fd; /* descriptor */
} sock_item;

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

sock_item *find_socket(sock_s *fds, int fd);
sock_item *add_socket(sock_s *fds, int fd, short *found);
/* 
 * @return 0 - found, 1 - not found
 */
int delete_socket(sock_s *fds, int fd);
int delete_socket_iter(sock_s *fds, sock_s_it s);

/*
#ifdef __cplusplus
}
#endif
*/

#endif /* _DATASTRUCT_H_ */

