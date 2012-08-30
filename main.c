#define _GNU_SOURCE             /* See feature_test_macros(7) */

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


static int wait_for_stopped (pid_t pid, bool sysgood, int *retstatus)
{
  int status;

  for (;;)
  {

    if (waitpid (pid, &status, 0) == -1)
      return -1;                //FAIL

    if (WIFEXITED (status))
    {
      *retstatus = status;
      return -2;                // FAIL
    }

    if (!WIFSTOPPED (status))
      continue;

    if ((WSTOPSIG (status) & 0x7F) != SIGTRAP)
      continue;

    if (sysgood && !(WSTOPSIG (status) & 0x80))
      continue;

    return 0;                   // OK
  }
}

static int wait_for_break (pid_t pid, struct user_regs_struct *state, int *status)
{
  int ret;

  if (ptrace (PTRACE_SYSCALL, pid, 0, 0) == -1)
    return -1;                  // FAIL

  if ((ret = wait_for_stopped (pid, true, status)))
    return ret;

  if (ptrace (PTRACE_GETREGS, pid, 0, state) == -1)
    return -1;

  return 0;
}

typedef struct
{
  unsigned long nr, a1, a2, a3, a4, a5, a6, ret;
} args_t;

static void get_args (const struct user_regs_struct *state, args_t * args)
{
#ifdef __amd64__
  args->nr = state->orig_rax;
  args->a1 = state->rdi;
  args->a2 = state->rsi;
  args->a3 = state->rdx;
  args->a4 = state->rcx;
  args->a5 = state->r8;
  args->a6 = state->r9;
  args->ret = state->rax;
#else
  args->nr = state->orig_eax;
  args->a1 = state->ebx;
  args->a2 = state->ecx;
  args->a3 = state->edx;
  args->a4 = state->esi;
  args->a5 = state->edi;
  args->a6 = state->ebp;
  args->ret = state->eax;
#endif
}

#define WORDBITS (8 * sizeof(unsigned long))

static inline void bit_set (unsigned long *data, unsigned long index)
{
  data[index / WORDBITS] |= (1 << (index % WORDBITS));
}

static inline void bit_clear (unsigned long *data, unsigned long index)
{
  data[index / WORDBITS] &= ~(1 << (index % WORDBITS));
}

static inline bool bit_get (const unsigned long *data, unsigned long index)
{
  return (data[index / WORDBITS] >> (index % WORDBITS)) & 1;
}

static void trace_syscall (pid_t pid, const struct user_regs_struct *state1, const struct user_regs_struct *state2, unsigned long *data)
{
  args_t args1;
  args_t args2;

  get_args (state1, &args1);
  get_args (state2, &args2);


  switch (state1->orig_rax)
  {
  case SYS_socket:
    {
      int ret = args2.ret;
      int domain = args1.a1;
      int type = args1.a2;
      int protocol = args1.a3;

      if (domain != AF_NETLINK)
        break;
      if (ret < 0)
      {
        printf ("Attempt to create NETLINK socket failed\n");
        break;
      }

      // TODO: track information about protocol of that socket. really unneded, as this information exists in message
      bit_set (data, ret);

      printf ("Netlink socket created: %d, protocol: %d\n", ret, protocol);
    }
    break;
  case SYS_sendto:
    {
      ssize_t ret = args2.ret;

      int sockfd = args1.a1;
      const char *buf = (const char *) args1.a2;
      size_t buflen = args1.a3;
      const struct sockaddr *dest_addr = (const struct sockaddr *) args1.a4;
      socklen_t addrlen = args1.a5;

      if (!bit_get (data, sockfd))
        break;


      printf ("Sendto(%d): buflen=%zu, returns %zd\n", sockfd, buflen, ret);


      if (ret < 0)
      {
        printf ("Attempt to sendto(NETLINK socket) failed\n");
        break;
      }
      //TODO: send not all, zero and so on
    }
    break;
  case SYS_recvfrom:
    {
      ssize_t ret = args2.ret;

      int sockfd = args1.a1;
      const char *buf = (const char *) args1.a2;
      size_t buflen = args1.a3;
      int flags = args1.a4;
      const struct sockaddr *src_addr = (const struct sockaddr *) args1.a5;
      const socklen_t *addrlen = (const socklen_t *) args1.a6;

      if (!bit_get (data, sockfd))
        break;

      if (ret < 0)
      {
        printf ("Attempt to recvfrom(NETLINK socket) failed\n");
        break;
      }

      if (ret == 0)
      {
        printf ("Received zero bytes\n");
        break;
      }

      printf ("Recvfrom(%d): buflen=%zu, returns %zd\n", sockfd, buflen, ret);
    }
    break;
  case SYS_recvmmsg:
    break;
  case SYS_recvmsg:
//       ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);


    break;
  case SYS_sendmmsg:
    break;
  case SYS_sendmsg:
    /* 
       ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

     */
    break;

    // HANDLE unix socket (!) - receiving of descriptors
  case SYS_close:
    {
      int ret = args2.ret;
      int fd = args1.a1;

      if (!bit_get (data, fd))
        break;

      if (ret < 0)
      {
        printf ("Close of netlink socket failed...\n");
        break;
      }

      printf ("Close(%d)\n", fd);

      bit_clear (data, fd);
    }
    break;
  case SYS_dup3:
    break;
  case SYS_dup2:
    break;
  case SYS_dup:
    break;
  case SYS_socketpair:
    break;                      ///??!?
  case SYS_clone:
    /* syscalls in threads ?! AIEIEIEIO!! */
    break;
  case SYS_execve:
  case SYS_fork:
    break;
  default:
    return;
  }

#if 0
  // sys_write
  if (state.orig_eax == SYS_write)
  {
    char *text = (char *) state.ecx;
    ptrace (PTRACE_POKETEXT, pid, (void *) (text + 7), 0x72626168);     //habr
    ptrace (PTRACE_POKETEXT, pid, (void *) (text + 11), 0x00000a21);    //!\n
  }
#endif
}

int main (int argc, char *argv[])
{
  pid_t pid;
  static unsigned long data[65536 / WORDBITS + 1];

  if (argc < 2)
    return 1;

  if (!(pid = fork ()))
  {
    if (prctl (PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == -1)
      return 1;
    if (getppid () <= 1)
      return 2;
    //TODO: check if non-cloexec descriptors are NETLINK sockets...
    if (ptrace (PTRACE_TRACEME, 0, 0, 0) == -1)
      return 3;
    execvp (argv[1], argv + 1);
    return 4;
  }

  int status = 1;
  if (wait_for_stopped (pid, false, &status))
    return status;
  if (ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1)
    return 5;
  for (;;)
  {
    struct user_regs_struct state1;
    struct user_regs_struct state2;
    if (wait_for_break (pid, &state1, &status))
      break;
    if (wait_for_break (pid, &state2, &status))
      break;
    trace_syscall (pid, &state1, &state2, data);
  }
  return status;
}
