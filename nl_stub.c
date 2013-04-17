#include <stdio.h>
#include <netlink/netlink.h>
#include <stdbool.h>

#include "nl_stub.h"

void handle_netlink_appear (pid_t pid, int sockfd)
{
  (void) pid;
  fprintf (stderr, "Netlink socket fd %d created\n", sockfd);
  return;
}

void handle_netlink_close (pid_t pid, int sockfd)
{
  (void) pid;
  fprintf (stderr, "Netlink socket fd %d closed\n", sockfd);
  return;
}

static void handle_netlink_data (unsigned char *data, size_t length)
{

  struct nl_sock *sk;
  struct nl_cb *cb;

  bool used = false;

  int my_faked_recv (struct nl_sock *sk1, struct sockaddr_nl *addr1, unsigned char **buf1, struct ucred **cred1)
  {

    (void) sk1;
    (void) addr1;
    (void) cred1;

    if (used)
      return 0;

    *buf1 = data;
    used = true;
    return length;
  }

  if (!(cb = nl_cb_alloc (NL_CB_DEBUG)))
  {
    fprintf (stderr, "nl_cb_alloc failed\n");
    return;
  }
  if (!(sk = nl_socket_alloc_cb (cb)))
  {
    fprintf (stderr, "nl_socket_alloc failed\n");
    nl_cb_put (cb);
    return;
  }

  nl_socket_disable_seq_check (sk);
  nl_socket_disable_auto_ack (sk);      //is not really required
  nl_socket_disable_msg_peek (sk);      //is not really needed ?

  nl_cb_overwrite_recv (cb, my_faked_recv);

  if (nl_recvmsgs_default (sk) > 0)
  {
    fprintf (stderr, "nl_recvmsgs failed\n");
    nl_socket_free (sk);
    return;
  }

  nl_socket_free (sk);
}

void handle_netlink_send (pid_t pid, int sockfd, unsigned char *data, size_t length)
{
  (void) pid;
  (void) sockfd;

  fprintf (stderr, "netlink send(%d):\n", sockfd);
  handle_netlink_data (data, length);
}

void handle_netlink_recv (pid_t pid, int sockfd, unsigned char *data, size_t length)
{
  (void) pid;
  (void) sockfd;

  fprintf (stderr, "netlink recv(%d):\n", sockfd);
  handle_netlink_data (data, length);
}
