#ifndef NLTRACE_HANDLERS_H
#define NLTRACE_HANDLERS_H

#include <sys/types.h>
#include <sys/socket.h>

struct msghdr;
struct process;

void handle_socket (struct process *process, int ret, int domain, int type, int protocol);
void handle_sendto (struct process *process, ssize_t ret, int sockfd, const char *buf, size_t buflen, const struct sockaddr *dest_addr, socklen_t addrlen);
void handle_recvfrom (struct process *process, ssize_t ret, int sockfd, const char *buf, size_t buflen, int flags, const struct sockaddr *src_addr,
                      const socklen_t *addrlen);
void handle_close (struct process *process, int ret, int fd);


void handle_dup (struct process *process, int ret, int oldfd);
void handle_dup2 (struct process *process, int ret, int oldfd, int newfd);
void handle_dup3 (struct process *process, int ret, int oldfd, int newfd, int flags);


void handle_recvmsg (struct process *process, ssize_t ret, int sockfd, struct msghdr *msg, int flags);
void handle_sendmsg (struct process *process, ssize_t ret, int sockfd, const struct msghdr *msg, int flags);

#endif
