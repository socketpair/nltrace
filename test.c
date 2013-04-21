#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

int main (void)
{
  int qwe;


  qwe = socket (AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);


//  printf ("addr=%p\n", &qwe);
//  send(qwe, &qwe, sizeof(qwe), 0);
///////////////////////////////////////////////////

  struct iovec iov = {
    .iov_base = &qwe,
    .iov_len = sizeof (qwe)
  };

  struct msghdr msg = {
    .msg_iovlen = 1,
    .msg_iov = &iov,
  };

  printf ("sendmsg msg child addr: addr=%p\n", &msg);
  sendmsg (qwe, &msg, 0);

}
