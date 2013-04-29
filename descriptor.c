#include <search.h>
#include <sys/types.h>          /* pid_t */
#include <stdlib.h>             /* malloc */
#include <stdio.h>              /* perror */
#include <string.h>             /* strcmp */
#include <sys/socket.h>         /* AF_NETLINK */
#include <unistd.h>             /* readlink */
#include <errno.h>

#include "descriptor.h"
#include "nl_stub.h"

struct descriptor
{
  int fd;                       /* should be the first member - primary key */
  int family;
  int protocol;
};

static int _compare_descriptors (const struct descriptor *a, const struct descriptor *b)
{
  /* Note: void pointer may point to either struct descriptor or it's primary key (int fd) */
  pid_t pa = a->fd;
  pid_t pb = b->fd;

  if (pa == pb)
    return 0;
  else
    return (pa > pb) ? 1 : -1;
}

int compare_descriptors (const void *a, const void *b)
{
  /* Note: void pointer may point to either struct descriptor or it's primary key (int fd) */
  return _compare_descriptors ((const struct descriptor *) a, (const struct descriptor *) b);
}

struct descriptor *descriptor_alloc (int fd, int family, int protocol)
{
  struct descriptor *descriptor;

  if (!(descriptor = malloc (sizeof (*descriptor))))
  {
    perror ("malloc");
    return NULL;
  }

  descriptor->fd = fd;
  descriptor->family = family;
  descriptor->protocol = protocol;
  return descriptor;
}

void descriptor_destroy (struct descriptor *descriptor)
{
  fprintf (stderr, "Destroying descriptor fd %d\n", descriptor->fd);
  free (descriptor);
}

/*.
returns:
-1 on error
 0 if given inode is not netlink socket
 1 if given inode is netlink socket, writes its protocol to ret_protocol
*/
static int scan_proc_net_netlink (unsigned long inode, int *ret_protocol)
{
  FILE *netlink;
  char result[256];
  /* http://lxr.linux.no/linux+v3.8.8/net/netlink/af_netlink.c#L2055 */
  static const char *header = "sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode\n";
  int protocol;
  unsigned long scanned_inode;
  int retval = -1;


  if (!(netlink = fopen ("/proc/net/netlink", "rte")))
  {
    perror ("Opening /proc/net/netlink");
    goto end;
  }

  if (!fgets (result, sizeof (result), netlink))
  {
    fprintf (stderr, "Error reading header of /proc/net/netlink\n");
    goto end;
  }

  if (strcmp (result, header))
  {
    fprintf (stderr, "header on your kernel does not match ours we expect!:\n"  /* */
             " our:%s"          /* */
             "your:%s",         /* */
             header, result);
    goto end;
  }

  while (fgets (result, sizeof (result), netlink))
  {

    if (strlen (result) == sizeof (result) - 1)
    {
      fprintf (stderr, "/proc/net/netlink line truncated\n");
      goto end;
    }

    // TODO: fscanf?
    // 0000000000000000 0   4195573 00000000 0        0        0000000000000000 2        0        8636
    if (sscanf (result, "%*s %d %*s %*s %*s %*s %*s %*s %*s %lu", &protocol, &scanned_inode) != 2)
    {
      fprintf (stderr, "Can not parse string %s\n", result);
      goto end;
    }

    if (inode != scanned_inode)
      continue;

    fprintf (stderr, "Found that socket inode %lu is the netlink socket of protocol %d\n", inode, protocol);
    *ret_protocol = protocol;
    retval = 1;
    goto end;
  }

  fprintf (stderr, "Found that socket inode %lu is not netlink socket\n", inode);
  retval = 0;

end:
  if (netlink)
    fclose (netlink);
  return retval;
}



struct descriptor *descriptor_alloc_detect_proc (int fd, pid_t pid)
{
  unsigned long inode;
  int tmp;

  char path[128];
  char description[256];


  tmp = snprintf (path, sizeof (path), "/proc/%u/fd/%d", (unsigned int) pid, fd);

  if (tmp <= 0)
  {
    perror ("sprintf of path");
    return NULL;
  }

  if (tmp >= (int) (sizeof (path)))
  {
    fprintf (stderr, "printf buffer overflow\n");
    return NULL;
  }

  if (readlink (path, description, sizeof (description)) == -1)
  {
    perror ("readlink");
    // TODO: if very long link value => non-netlnik
    return NULL;
  }

  /* this is not socket at all */
  if (sscanf (description, "socket:[%lu]", &inode) != 1)
    return descriptor_alloc (fd, AF_UNSPEC, -1);

  int protocol;
  if ((tmp = scan_proc_net_netlink (inode, &protocol)) == -1)
  {
    fprintf (stderr, "/proc/net/... scanning failed\n");
    return NULL;
  }

  if (!tmp)
    return descriptor_alloc (fd, AF_UNSPEC, -1);

  return descriptor_alloc (fd, AF_NETLINK, protocol);
}

struct descriptor *descriptor_alloc_detect_live (int fd)
{
  struct sockaddr addr;
  socklen_t addrlen = sizeof (addr);


  if (getsockname (fd, &addr, &addrlen) == -1)
  {
    int error = errno;
    switch (error)
    {
    case EBADF:
      fprintf (stderr, "getsockname(%d) returns EBADF\n", fd);
      return NULL;
    case ENOTSOCK:
      return descriptor_alloc (fd, AF_UNSPEC, -1);
    }

    fprintf (stderr, "getsockname returns %d\n", error);
    return NULL;
  }

  if (addr.sa_family != AF_NETLINK)
    return descriptor_alloc (fd, AF_UNSPEC, -1);

  int proto;
  addrlen = sizeof (proto);

  if (getsockopt (fd, SOL_SOCKET, SO_PROTOCOL, &proto, &addrlen) == -1)
  {
    fprintf (stderr, "getsockopt for socket does not work...\n");
    return NULL;
  }

  return descriptor_alloc (fd, AF_NETLINK, proto);
}



int descriptor_get_family (const struct descriptor *descriptor)
{
  return descriptor->family;
}

int descriptor_get_protocol (const struct descriptor *descriptor)
{
  return descriptor->protocol;
}



void descriptor_handle_send (struct descriptor *descriptor, unsigned char *data, size_t length)
{
  if (descriptor->family != AF_NETLINK)
    return;

  fprintf (stderr, "netlink send(%d):\n", descriptor->fd);
  handle_netlink_data (descriptor->protocol, data, length);
}

void descriptor_handle_recv (struct descriptor *descriptor, unsigned char *data, size_t length)
{
  if (descriptor->family != AF_NETLINK)
    return;

  fprintf (stderr, "netlink recv(%d):\n", descriptor->fd);
  handle_netlink_data (descriptor->protocol, data, length);
}
