#ifndef NLTRACE_HANDLERS_H
#define NLTRACE_HANDLERS_H

#include <sys/types.h>
#include <sys/socket.h>

struct msghdr;

void handle_socket (pid_t pid, int ret, int domain, int type, int protocol);
void handle_sendto (pid_t pid, ssize_t ret, int sockfd, const char *buf, size_t buflen, const struct sockaddr *dest_addr, socklen_t addrlen);
void handle_recvfrom (pid_t pid, ssize_t ret, int sockfd, const char *buf, size_t buflen, int flags, const struct sockaddr *src_addr, const socklen_t *addrlen);
void handle_close (pid_t pid, int ret, int fd);


void handle_dup (pid_t pid, int ret, int oldfd);
void handle_dup2 (pid_t pid, int ret, int oldfd, int newfd);
void handle_dup3 (pid_t pid, int ret, int oldfd, int newfd, int flags);


void handle_recvmsg (pid_t pid, ssize_t ret, int sockfd, struct msghdr *msg, int flags);
void handle_sendmsg (pid_t pid, ssize_t ret, int sockfd, const struct msghdr *msg, int flags);

#endif
