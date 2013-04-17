#ifndef MM_NL_STUB_H
#define MM_NL_STUB_H

#include <sys/types.h>
void handle_netlink_appear (pid_t pid, int sockfd, int protocol);

void handle_netlink_send (pid_t pid, int sockfd, unsigned char *data, size_t length);
void handle_netlink_recv (pid_t pid, int sockfd, unsigned char *data, size_t length);

void handle_netlink_close (pid_t pid, int sockfd);

#endif
