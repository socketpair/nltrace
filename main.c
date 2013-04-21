#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <stdbool.h>
#include <string.h>             /* memcpy */

#include <unistd.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>

#include "syscalls.h"
#include "tracer.h"
#include "process.h"
#include "main.h"

static int wait_for_stopped (pid_t pid, bool sysgood, int *retstatus)
{
  int status;

  for (;;)
  {

    if (waitpid (pid, &status, 0) == -1)
    {
      perror ("waitpid failed");
      return -1;                //FAIL
    }

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

    break;
  }

  return 0;                     // OK
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


int ptrace_memcpy (pid_t pid, void *destination, const void *usermem, size_t length)
{
  size_t tmp = ((size_t) usermem) % sizeof (long);

  if (tmp)
  {
    size_t useful_bytes = sizeof (long) - tmp;

//    fprintf (stderr, "usermemcpy: copying unaligned start (%lu bytes) of user memory\n", (unsigned long) useful_bytes);
    long chunk;
    if ((chunk = ptrace (PTRACE_PEEKDATA, pid, (void *) (((size_t) usermem) / sizeof (long) * sizeof (long)), NULL)) == -1 && errno)
    {
      perror ("ptrace");
      return -1;
    }

    memcpy (destination, ((char *) &chunk) + tmp, useful_bytes);
    usermem += useful_bytes;
    destination += useful_bytes;
    length -= useful_bytes;
  }

//  if (length >= sizeof (long))
//    fprintf (stderr, "usermemcpy: copying aligned %lu bytes of memory\n", (unsigned long) (length / sizeof (long) * sizeof (long)));

  while (length >= sizeof (long))
  {
    long chunk;
    if ((chunk = ptrace (PTRACE_PEEKDATA, pid, usermem, NULL)) == -1 && errno)
    {
      perror ("ptrace");
      return -1;
    }
    *(long *) destination = chunk;
    destination += sizeof (long);
    usermem += sizeof (long);
    length -= sizeof (long);
  }

  if (length)
  {
//    fprintf (stderr, "usermemcpy: copying last %lu bytes from aligned user memory\n", (unsigned long) length);

    long chunk;

    if ((chunk = ptrace (PTRACE_PEEKDATA, pid, usermem, NULL)) == -1 && errno)
    {
      perror ("trace");

      return -1;
    }
    memcpy (destination, &chunk, length);
  }

  return 0;
}



static void __attribute__ ((noreturn)) fork_and_trace_child (char **argv)
{

  /* child here */
  if (prctl (PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == -1)
    _exit (1);

  if (getppid () <= 1)
    _exit (2);

  if (ptrace (PTRACE_TRACEME, 0, 0, 0) == -1)
    _exit (3);

  /* will cause this child to super-stop */
  execvp (argv[1], argv + 1);
  _exit (6);
}

int main (int argc, char *argv[])
{
  pid_t pid;
  int status = 1;
  struct tracer *tracer = NULL;
  struct process *process = NULL;


  if (argc < 2)
    return 1;

  pid = fork ();

  if (pid < 0)
  {
    perror ("fork");
    return 2;
  }

  if (pid == 0)
    fork_and_trace_child (argv);

  if (wait_for_stopped (pid, false, &status))
  {
    fprintf (stderr, "child process unexpectedly dead\n");
    return 3;
  }

  /*
     When  delivering syscall traps, set bit 7 in the signal number
     (i.e., deliver SIGTRAP | 0x80).  This makes it easy for the tracer
     to tell the difference between normal traps and those caused by a
     syscall.  (PTRACE_O_TRACESYSGOOD may not work on all architectures.)
   */
  if (ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1)
    return 5;

  status = 1;

  if (!(tracer = tracer_alloc ()))
  {
    fprintf (stderr, "Can not allocate tracer\n");
    goto end;
  }

  if (!(process = process_alloc (pid)))
  {
    fprintf (stderr, "Can not allocate process\n");
    goto end;
  }

  if (tracer_add_process (tracer, process) == -1)
  {
    fprintf (stderr, "Cannot add process to tracer\n");
    goto end;
  }

  /* process = NULL should be here (!) */

  for (;;)
  {
    struct user_regs_struct state1;
    struct user_regs_struct state2;
    if (wait_for_break (pid, &state1, &status))
      break;
    if (wait_for_break (pid, &state2, &status))
      break;
    trace_syscall (process, &state1, &state2);
  }

  process = NULL;

  status &= 0xff;

end:
  if (process)
    process_destroy (process);
  if (tracer)
    tracer_destroy (tracer);

  return status;
}
