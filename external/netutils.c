#include "netutils.h"

int set_reuseaddr(int sock_fd)
{
	int enable = 1;
	return setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
}
