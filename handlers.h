#ifndef NLTRACE_HANDLERS_H
#define NLTRACE_HANDLERS_H

#include <sys/types.h>
#include <sys/socket.h>

void handle_socket (int ret, int domain, int type, int protocol);
void handle_sendto (ssize_t ret, int sockfd, const char *buf, size_t buflen, const struct sockaddr *dest_addr, socklen_t addrlen);
void handle_recvfrom (ssize_t ret, int sockfd, const char *buf, size_t buflen, int flags, const struct sockaddr *src_addr, const socklen_t * addrlen);
void handle_close (int ret, int fd);

#endif
