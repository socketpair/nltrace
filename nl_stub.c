#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>

#include <stdbool.h>

#include "nl_stub.h"

static int protocols[65536];

void handle_netlink_appear (pid_t pid, int sockfd, int protocol)
{
  (void) pid;

  fprintf (stderr, "Netlink socket fd %d created (protocol %d)\n", sockfd, protocol);

  protocols[sockfd] = protocol;

  return;
}

void handle_netlink_close (pid_t pid, int sockfd)
{
  (void) pid;
  fprintf (stderr, "Netlink socket fd %d closed\n", sockfd);
  return;
}

static int message_protocol_setter (struct nl_msg *msg, void *arg)
{
  int protocol;
  protocol = *(int *) arg;
  fprintf (stderr, "Setting msg proto to %d\n", protocol);

  nlmsg_set_proto (msg, protocol);
  nl_msg_dump (msg, stderr);

  return NL_OK;
}


static void handle_netlink_data (int sockfd, unsigned char *data, size_t length)
{

  struct nl_sock *sk;
  struct nl_cb *cb;

  bool used = false;
#warning free memory if netlink faild to do that...

  /* Yes, closure (!)
   * We cannot "subclass" original socket to add new fields :(
   * */
  int my_faked_recv (struct nl_sock *sk1 /* input */ , struct sockaddr_nl *addr1 /* output */ , unsigned char **buf1 /* output */ ,
                     struct ucred **cred1 /*output */ )
  {

    (void) sk1;
    (void) addr1;
    (void) cred1;

    /* prevent nl_recvmsgs to read this buffer again and again.
     * Just simulate that last recv() return 0 :)
     * */
    if (used)
      return 0;

    *buf1 = data;
    used = true;
    return length;
  }

  // initialize all hooks to DEBUG variant...
  if (!(cb = nl_cb_alloc (NL_CB_CUSTOM)))
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

  // required to call nlmsg_set_proto(msg, 123456);
  // as the libnl3 have no API to set socket's s_proto
  // message's proto is required for correct parsing of data...
  // last argument is a pointer to "int protocol"

  //fprintf(stderr, "Calling nl_cb_set for fd %d\n", sockfd);
  if (nl_cb_set (cb, NL_CB_MSG_IN, NL_CB_CUSTOM, message_protocol_setter, &protocols[sockfd]) < 0)
  {
    fprintf (stderr, "nl_cb_set failed\n");
    nl_socket_free (sk);
    return;
  }


  //nl_object_dump() ??
  //  nlmsg_set_proto(msg, sk->s_proto);

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
  handle_netlink_data (sockfd, data, length);
}

void handle_netlink_recv (pid_t pid, int sockfd, unsigned char *data, size_t length)
{
  (void) pid;


  fprintf (stderr, "netlink recv(%d):\n", sockfd);
  handle_netlink_data (sockfd, data, length);
}
