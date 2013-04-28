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
#include <string.h>
#include <stdlib.h>

#include "syscalls.h"
#include "descriptor.h"
#include "process.h"
#include "handlers.h"

#define UNUSED __attribute__((unused))

void handle_socket (struct process *process, int ret, int domain, int type UNUSED, int protocol)
{
  if (ret < 0)
    return;

  struct descriptor *descriptor;

  if (!(descriptor = descriptor_alloc (ret, domain, protocol)))
  {
    fprintf (stderr, "descriptor allocation failed\n");
    return;
  }

  if (process_add_descriptor (process, descriptor) == -1)
  {
    fprintf (stderr, "Cannot add descriptor to process\n");
    descriptor_destroy (descriptor);
    return;
  }

}

static struct descriptor *get_netlink_descriptor (struct process *process, int fd)
{

  struct descriptor *descriptor;

  if (!(descriptor = process_get_descriptor (process, fd)))
  {
    fprintf (stderr, "Cannot get descriptor from process\n");
    return NULL;
  }

  if (descriptor_get_family (descriptor) != AF_NETLINK)
    return NULL;

  return descriptor;

}

void handle_sendto (struct process *process, ssize_t ret, int sockfd, const char *buf, size_t buflen, const struct sockaddr *dest_addr, socklen_t addrlen)
{

  (void) buf;
  (void) buflen;
  (void) dest_addr;
  (void) addrlen;

  struct descriptor *descriptor;

  if (!(descriptor = get_netlink_descriptor (process, sockfd)))
    return;

  if (ret < 0)
  {
    // TODO: do not parse if EINVAL or so
    fprintf (stderr, "sendto() failed\n");
  }
  else if ((size_t) ret != buflen)
  {
    fprintf (stderr, "Warning sent only part of the message\n");
  }

  unsigned char *data = NULL;

  if (!(data = process_dup_memory (process, buf, buflen)))
  {
    perror ("malloc");
    return;
  }

  descriptor_handle_send (descriptor, data, buflen);
}


void handle_recvfrom (struct process *process, ssize_t ret, int sockfd, const char *buf, size_t buflen, int flags, const struct sockaddr *src_addr,
                      const socklen_t *addrlen)
{
  if (ret < 0)
    return;


  (void) buf;
  (void) buflen;
  (void) flags;
  (void) src_addr;
  (void) addrlen;

  struct descriptor *descriptor;

  if (!(descriptor = get_netlink_descriptor (process, sockfd)))
    return;


  if (ret == 0)
  {
    fprintf (stderr, "netlink recv returns zero...\n");
    return;
  }

  unsigned char *data = NULL;

  if (!(data = process_dup_memory (process, buf, ret)))
  {
    perror ("malloc");
    return;
  }

  descriptor_handle_recv (descriptor, data, ret);
}


static int handle_msg (void *data, size_t datalen, const struct process *process, const struct msghdr *msg)
{
  const struct iovec *msg_iov;
  size_t msg_iovlen;


  if (process_memcpy (process, &msg_iov, &msg->msg_iov, sizeof (msg_iov)) == -1)
  {
    fprintf (stderr, "process_memcpy() [recvmsg1] failed\n");
    return -1;
  }

  if (process_memcpy (process, &msg_iovlen, &msg->msg_iovlen, sizeof (msg_iovlen)) == -1)
  {
    fprintf (stderr, "process_memcpy() [recvmsg2] failed\n");
    return -1;
  }

//  fprintf (stderr, "datalen=%ld, msg_iov=%p, iov_len=%lu\n", (long) datalen, msg_iov, (unsigned long) msg_iovlen);

  for (; msg_iovlen && datalen; msg_iovlen--, msg_iov++)
  {
    void *iov_base;
    size_t iov_len;

//    fprintf (stderr, "RECVMSG: begin of copying iovec fields\n");

    if (process_memcpy (process, &iov_base, &msg_iov->iov_base, sizeof (iov_base)) == -1)
    {
      fprintf (stderr, "process_memcpy() [recvmsg3] failed\n");
      return -1;
    }

    if (process_memcpy (process, &iov_len, &msg_iov->iov_len, sizeof (iov_len)) == -1)
    {
      fprintf (stderr, "process_memcpy() [recvmsg4] failed\n");
      return -1;
    }

//    fprintf (stderr, "RECVMSG: Starting to copy iovec data: %p, length=%lu\n", iov_base, (unsigned long) iov_len);

    if (iov_len > datalen)
    {
//      fprintf (stderr, "IOV was TOO LONG...\n");
      iov_len = datalen;
    }

    if (process_memcpy (process, data, iov_base, iov_len) == -1)
    {
      fprintf (stderr, "process_memcpy() [recvmsg5] failed\n");
      return -1;
    }

    data += iov_len;
    datalen -= iov_len;
  }

  if (msg_iovlen)
  {
    fprintf (stderr, "not all IOVs was read\n");
  }

  if (datalen)
  {
    fprintf (stderr, "not all data was filled\n");
  }

  return 0;
}


void handle_recvmsg (struct process *process, ssize_t ret, int sockfd, struct msghdr *msg, int flags)
{
  if (ret < 0)
    return;

  (void) msg;
  (void) flags;

  struct descriptor *descriptor;

  if (!(descriptor = get_netlink_descriptor (process, sockfd)))
    return;

  unsigned char *data = NULL;

  if (!(data = malloc (ret)))
  {
    perror ("malloc");
    goto end;
  }

  if (handle_msg (data, ret, process, msg) == -1)
  {
    fprintf (stderr, "handle_msg FAILED\n");
    goto end;
  }

  descriptor_handle_recv (descriptor, data, ret);
  /* was already handled/freed */
  data = NULL;

end:
  free (data);
}

void handle_sendmsg (struct process *process, ssize_t ret, int sockfd, const struct msghdr *msg, int flags)
{
  if (ret < 0)
    return;

  (void) msg;
  (void) flags;

  struct descriptor *descriptor;

  if (!(descriptor = get_netlink_descriptor (process, sockfd)))
    return;

  unsigned char *data = NULL;

  // TODO: we must detect total length of original message (!)
  if (!(data = malloc (ret)))
  {
    perror ("malloc");
    goto end;
  }

  if (handle_msg (data, ret, process, msg) == -1)
  {
    fprintf (stderr, "handle_msg FAILED\n");
    goto end;
  }

  descriptor_handle_send (descriptor, data, ret);
/* was already handled/freed */
  data = NULL;
end:
  free (data);

}


void handle_close (struct process *process, int ret, int fd)
{
  if (ret < 0)
    return;

  //will not fail if no such descriptor...
  process_delete_descriptor_int (process, fd);
}

void handle_dup2 (struct process *process, int ret, int oldfd, int newfd)
{
  if (ret < 0)
    return;

  struct descriptor *olddescriptor, *newdescriptor;

  if (!(olddescriptor = process_get_descriptor (process, oldfd)))
  {
    fprintf (stderr, "Cannot get descriptor from process\n");
    return;
  }

  //will not fail if no such descriptor...
  process_delete_descriptor_int (process, newfd);

  if (!(newdescriptor = descriptor_alloc (newfd, descriptor_get_family (olddescriptor), descriptor_get_protocol (olddescriptor))))
  {
    fprintf (stderr, "cannot allocate new descriptor in dup2\n");
    return;
  }

  if (!process_add_descriptor (process, newdescriptor))
  {
    fprintf (stderr, "cannot add duplicated descriptor to process\n");
    return;
  }
}

void handle_dup (struct process *process, int ret, int oldfd)
{
  handle_dup2 (process, ret, oldfd, ret);
}

void handle_dup3 (struct process *process, int ret, int oldfd, int newfd, int flags)
{
  (void) flags;
  handle_dup2 (process, ret, oldfd, newfd);
}
