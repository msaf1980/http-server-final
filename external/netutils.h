#ifndef _NETUTILS_H_
#define _NETUTILS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 

/* socket helpers macros */
#define SA struct sockaddr
#define SA_IN struct sockaddr_in 

#ifdef __cplusplus
extern "C" {
#endif

/* Set SO_REUSEADDR for listen socket */
int set_reuseaddr(int sock_fd);

#ifdef __cplusplus
}
#endif

#endif /* _NETUTILS_H_ */

