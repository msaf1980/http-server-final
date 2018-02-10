#include "datastruct.hpp"

sock_item *find_socket(sock_s *fds, int sock_fd)
{
	sock_s_it s;
	s = fds->find(sock_fd);
	if (s == fds->end())
		return NULL;
	return &s->second;
}

sock_item *add_socket(sock_s *fds, int sock_fd, short *found)
{
	sock_s_it s;
	sock_item si;
	std::pair<sock_s_it, bool> ret;
	SOCK_ITEM_INIT(si, sock_fd);
	ret = fds->insert(std::make_pair(sock_fd, si));
	if (found)
	{
		if (ret.second == false)
			*found = 1;
		else
			*found = 0;
	}
	return & ret.first->second;
}

int delete_socket(sock_s *fds, int sock_fd)
{
	sock_s_it s;
	s = fds->find(sock_fd);
	if (s == fds->end())
		return 0;
	SOCK_ITEM_FREE(s->second);
	fds->erase(s);
	return 1;	
}

int delete_socket_iter(sock_s *fds, sock_s_it s)
{
	if (s == fds->end())
		return 0;
	SOCK_ITEM_FREE(s->second);
	fds->erase(s);
	return 1;	
}

