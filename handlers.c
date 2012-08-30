#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/syscall.h>        /* For SYS_xxx definitions */


#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "utils.h"

static BITARRAY_TYPE used_sockets[65536 / WORDBITS];

//TODO: exactly the same, but on UNIX sockets...

void handle_socket (int ret, int domain, int type, int protocol)
{
  if (domain != AF_NETLINK)
    return;

  if (ret < 0)
  {
    printf ("Attempt to create NETLINK socket failed\n");
    return;
  }

  // TODO: track information about protocol of that socket. really unneded, as this information exists in message
  bit_set (used_sockets, ret);

  printf ("Netlink socket created: %d, protocol: %d\n", ret, protocol);
}

void handle_sendto (ssize_t ret, int sockfd, const char *buf, size_t buflen, const struct sockaddr *dest_addr, socklen_t addrlen)
{
  if (!bit_get (used_sockets, sockfd))
    return;

  printf ("Sendto(%d): buflen=%zu, returns %zd\n", sockfd, buflen, ret);


//  fake->buf nl_recvmsgs (fake->sk, fake->cb);

  if (ret < 0)
  {

    printf ("Attempt to sendto(NETLINK socket) failed\n");
    return;
  }
  //TODO: send not all, zero and so on
}


void handle_recvfrom (ssize_t ret, int sockfd, const char *buf, size_t buflen, int flags, const struct sockaddr *src_addr, const socklen_t * addrlen)
{

  if (!bit_get (used_sockets, sockfd))
    return;

  if (ret < 0)
  {
    printf ("Attempt to recvfrom(NETLINK socket) failed\n");
    return;
  }

  if (ret == 0)
  {
    printf ("Received zero bytes\n");
    return;
  }

  printf ("Recvfrom(%d): buflen=%zu, returns %zd\n", sockfd, buflen, ret);

}

void handle_close (int ret, int fd)
{

  if (!bit_get (used_sockets, fd))
    return;

  if (ret < 0)
  {
    printf ("Close of netlink socket failed...\n");
    return;
  }

  printf ("Close(%d)\n", fd);

  bit_clear (used_sockets, fd);
}
