#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/syscall.h>        /* For SYS_xxx definitions */
#include <errno.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#include "handlers.h"
#include "syscalls.h"

/* match order as in struct user_regs_struct */
typedef struct
{
#ifdef __amd64__
  unsigned long a6;
  unsigned long a5;
  unsigned long ret;
  unsigned long a4;
  unsigned long a3;
  unsigned long a2;
  unsigned long a1;
  unsigned long nr;
#else
  unsigned long a1;
  unsigned long a2;
  unsigned long a3;
  unsigned long a4;
  unsigned long a5;
  unsigned long a6;
  unsigned long ret;
  unsigned long nr;
#endif

} args_t;

static void print_args_t (FILE *output, const args_t *args)
{

  fprintf (output, " a1: 0x%lx\n", args->a1);
  fprintf (output, " a2: 0x%lx\n", args->a2);
  fprintf (output, " a3: 0x%lx\n", args->a3);
  fprintf (output, " a4: 0x%lx\n", args->a4);
  fprintf (output, " a5: 0x%lx\n", args->a5);
  fprintf (output, " a6: 0x%lx\n", args->a6);
  fprintf (output, "ret: 0x%lx\n", args->ret);
  fprintf (output, " nr: 0x%lx\n", args->nr);

}



static void get_args (const struct user_regs_struct *state, args_t *args)
{
/* match order as in struct user_regs_struct */
#ifdef __amd64__
  args->a6 = state->r9;
  args->a5 = state->r8;
  args->ret = state->rax;
  args->a4 = state->rcx;
  args->a3 = state->rdx;
  args->a2 = state->rsi;
  args->a1 = state->rdi;
  args->nr = state->orig_rax;
#else
  args->a1 = state->ebx;
  args->a2 = state->ecx;
  args->a3 = state->edx;
  args->a4 = state->esi;
  args->a5 = state->edi;
  args->a6 = state->ebp;
  args->ret = state->eax;

  args->nr = state->orig_eax;

#endif
}

void trace_syscall (struct process *process, const struct user_regs_struct *state1, const struct user_regs_struct *state2)
{
  args_t args1;
  args_t args2;

  get_args (state1, &args1);
  get_args (state2, &args2);

  // http://www.skyfree.org/linux/kernel_network/socket.html
  switch (args1.nr)
  {
#ifdef SYS_socketcall
  case SYS_socketcall:
    print_args_t (stderr, &args1);
    print_args_t (stderr, &args2);
    break;
#else
  case SYS_socket:
    handle_socket (process, args2.ret, args1.a1, args1.a2, args1.a3);
    break;
  case SYS_sendto:
    handle_sendto (process, args2.ret, args1.a1, (const char *) args1.a2, args1.a3, (const struct sockaddr *) args1.a4, args1.a5);
    break;
  case SYS_recvfrom:
    handle_recvfrom (process, args2.ret, args1.a1, (const char *) args1.a2, args1.a3, args1.a4, (const struct sockaddr *) args1.a5,
                     (const socklen_t *) args1.a6);
    break;
  case SYS_recvmsg:
    handle_recvmsg (process, args2.ret, args1.a1, (struct msghdr *) args1.a2, args1.a3);
    break;
  case SYS_sendmsg:
    handle_sendmsg (process, args2.ret, args1.a1, (const struct msghdr *) args1.a2, args1.a3);
    break;
  case SYS_recvmmsg:
    break;
  case SYS_sendmmsg:
    break;
#endif
  case SYS_close:
    handle_close (process, args2.ret, args1.a1);
    break;
  case SYS_dup3:
    handle_dup3 (process, args2.ret, args1.a1, args1.a2, args1.a3);
    break;
  case SYS_dup2:
    handle_dup2 (process, args2.ret, args1.a1, args1.a2);
    break;
  case SYS_dup:
    handle_dup (process, args2.ret, args1.a1);
    break;
    /*
       case SYS_execve:
       case SYS_fork:
       case SYS_clone:


       pread64
       preadv
       pwrite64
       pwritev
       read
       readv
       recv
       sendfile (file -> socket)
       sendfile64  (file -> socket)
       splice (pipe -> socket), (socket->pipe)
       write
       writev
     */
  }
}
