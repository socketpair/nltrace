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
#include "syscalls.h"

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

//TODO: different sockets for different fds?
typedef struct
{
  struct nl_sock *sk;
  struct nl_cb *cb;
  char *buf;
  size_t datalen;
} fake_t;

int main (int argc, char *argv[])
{
  pid_t pid;

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
    trace_syscall (pid, &state1, &state2);
  }
  return status;
}
