#include <stdio.h>
#include "nl_stub.h"

void handle_netlink_appear (pid_t pid, int sockfd)
{
  fprintf (stderr, "Netlink socket fd %d created\n", sockfd);
  return;
}

void handle_netlink_close (pid_t pid, int sockfd)
{
  fprintf (stderr, "Netlink socket fd %d closed\n", sockfd);
  return;
}

void handle_netlink_send (pid_t pid, int sockfd, const char *data, size_t length)
{
//  nl_recvmsgs (fake->sk, fake->cb);
  fprintf (stderr, "Netlink send\n");
  return;
}

void handle_netlink_recv (pid_t pid, int sockfd, const char *data, size_t length)
{
  //  nl_recvmsgs (fake->sk, fake->cb);
  fprintf (stderr, "Netlink recv\n");
  return;
}
