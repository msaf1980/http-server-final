#include "datastruct.hpp"

sock_item *find_socket(sock_s *fds, int fd)
{
	sock_s_it s;
	s = fds->find(fd);
	if (s == fds->end())
		return NULL;
	return &s->second;
}

sock_item *add_socket(sock_s *fds, int fd, short *found)
{
	sock_s_it s;
	sock_item si;
	std::pair<sock_s_it, bool> ret;
	si.fd = fd;
	ret = fds->insert(std::make_pair(fd, si));
	if (found)
	{
		if (ret.second == false)
			*found = 1;
		else
			*found = 0;
	}
	return & ret.first->second;
}

int delete_socket(sock_s *fds, int fd)
{
	sock_s_it s;
	s = fds->find(fd);
	if (s == fds->end())
		return 0;
	fds->erase(s);
	return 1;	
}

int delete_socket_iter(sock_s *fds, sock_s_it s)
{
	if (s == fds->end())
		return 0;
	return 1;	
}

