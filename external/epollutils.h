#define EPOLL_EVENT_SET(epoll_event, sockfd, event) do { (epoll_event).data.fd = sockfd; (epoll_event).events = event; } while(0)  
