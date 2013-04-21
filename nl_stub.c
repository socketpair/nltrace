#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>

#include <stdbool.h>

#include "nl_stub.h"

//////////////////////////////////////
// THIS IS NEEDED TO PREVENT LIBRARIES TO BE OPTIMIZED_OUT
// cache regitration is done in __init constructors of the libnl libraries.
#include <netlink/route/route.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/genl/genl.h>
void *references[] = {
  rtnl_route_alloc_cache,
  nfnl_connect,
  genl_connect,
};

static int message_dumper (struct nl_msg *msg, void *arg)
{
  int protocol;
  protocol = *(int *) arg;
  fprintf (stderr, "Setting msg proto to %d\n", protocol);

  nlmsg_set_proto (msg, protocol);
  nl_msg_dump (msg, stderr);

  return NL_OK;
}




void handle_netlink_data (int protocol, unsigned char *data, size_t length)
{

  struct nl_sock *sk = NULL;
  struct nl_cb *cb = NULL;

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
    if (!data)
      return 0;

    *buf1 = data;
    data = NULL;
    return length;
  }

  // initialize all hooks to DEBUG variant...
  // cb->refcount will be 1 after that
  if (!(cb = nl_cb_alloc (NL_CB_CUSTOM)))
  {
    fprintf (stderr, "nl_cb_alloc failed\n");
    goto end;
  }

  /* nl_socket_alloc_cb(cb) */
  if (!(sk = nl_socket_alloc ()))
  {
    fprintf (stderr, "nl_socket_alloc failed\n");
    goto end;
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
  if (nl_cb_set (cb, NL_CB_MSG_IN, NL_CB_CUSTOM, message_dumper, &protocol) < 0)
  {
    fprintf (stderr, "nl_cb_set failed\n");
    goto end;
  }

/*
  if (nl_recvmsgs_default (sk) > 0)
  {
    fprintf (stderr, "nl_recvmsgs failed\n");
    goto end;
  }
*/
  /* TODO: log retval of nl_recvmsgs_report */
  if (nl_recvmsgs (sk, cb) < 0)
  {
    fprintf (stderr, "nl_recvmsgs_report() returns error\n");
  }


end:
  if (data)
  {
    fprintf (stderr, "WARNING: data was not handled\n");
    free (data);
  }

  if (sk)
    nl_socket_free (sk);

  if (cb)
    nl_cb_put (cb);
}
