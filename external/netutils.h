#ifndef _NETUTILS_H_
#define _NETUTILS_H_

#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <netinet/in.h> 

/* socket helpers macros */
#define SA struct sockaddr
#define SA_IN struct sockaddr_in 

/* Set SO_REUSEADDR for listen socket */
int set_reuseaddr(int sock_fd);

/* return 1 if IPv4 string is valid, else return 0 */
int is_valid_ipv4(char *ip_str);

#ifdef __cplusplus
}
#endif

#endif /* _NETUTILS_H_ */
