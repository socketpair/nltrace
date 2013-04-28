#include <dlfcn.h>              /* dlsym */
#include <stdlib.h>             /* abort */
#include <stdio.h>              /* fprintf */
#include <sys/socket.h>         /* socklen_t */

#include "process.h"
#include "handlers.h"

#define QWE(name) \
    static typeof (&name) orig_ ## name; \
    if (!orig_ ## name && !(orig_ ## name = (typeof (&name)) dlsym (RTLD_NEXT, #name))) { \
            abort(); \
    }

static struct process *process;

static void myinit (void) __attribute__ ((constructor));
void myinit (void)
{
  if (!(process = process_alloc (0)))
    abort ();
}

int socket (int domain, int type, int protocol)
{
  int ret;
  QWE (socket);
  ret = orig_socket (domain, type, protocol);
  handle_socket (process, ret, domain, type, protocol);
  return ret;
}

ssize_t send (int sockfd, const void *buf, size_t len, int flags)
{
  ssize_t ret;
  QWE (send);
  ret = orig_send (sockfd, buf, len, flags);
  handle_sendto (process, ret, sockfd, buf, len, flags, NULL, 0);
  return ret;

}

ssize_t sendto (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
  ssize_t ret;
  QWE (sendto);
  ret = orig_sendto (sockfd, buf, len, flags, dest_addr, addrlen);
  handle_sendto (process, ret, sockfd, buf, len, flags, dest_addr, addrlen);
  return ret;

}

ssize_t sendmsg (int sockfd, const struct msghdr *msg, int flags)
{
  ssize_t ret;
  QWE (sendmsg);
  ret = orig_sendmsg (sockfd, msg, flags);
  handle_sendmsg (process, ret, sockfd, msg, flags);
  return ret;
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags)
{
  ssize_t ret;
  QWE (recv);
  ret = orig_recv (sockfd, buf, len, flags);
  handle_recvfrom (process, ret, sockfd, buf, len, flags, 0, NULL);
  return ret;
}

ssize_t recvfrom (int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
  ssize_t ret;
  QWE (recvfrom);
  ret = orig_recvfrom (sockfd, buf, len, flags, src_addr, addrlen);
  handle_recvfrom (process, ret, sockfd, buf, len, flags, src_addr, addrlen);
  return ret;

}

ssize_t recvmsg (int sockfd, struct msghdr *msg, int flags)
{
  ssize_t ret;
  QWE (recvmsg);
  ret = orig_recvmsg (sockfd, msg, flags);
  handle_recvmsg (process, ret, sockfd, msg, flags);
  return ret;
}

int close (int fd)
{
  int ret;
  QWE (close);
  ret = orig_close (fd);
  handle_close (process, ret, fd);
  return ret;
}

int dup (int oldfd)
{
  int ret;
  QWE (dup);
  ret = orig_dup (oldfd);
  handle_dup (process, ret, oldfd);
  return ret;
}

int dup2 (int oldfd, int newfd)
{
  int ret;
  QWE (dup2);
  ret = orig_dup2 (oldfd, newfd);
  handle_dup2 (process, ret, oldfd, newfd);
  return ret;
}

int dup3 (int oldfd, int newfd, int flags)
{
  int ret;
  QWE (dup3);
  ret = orig_dup3 (oldfd, newfd, flags);
  handle_dup3 (process, ret, oldfd, newfd, flags);
  return ret;
}
