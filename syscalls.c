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

#include "handlers.h"

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

static inline void get_args (const struct user_regs_struct *state, args_t * args)
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

void trace_syscall (pid_t pid, const struct user_regs_struct *state1, const struct user_regs_struct *state2)
{
  args_t args1;
  args_t args2;

  get_args (state1, &args1);
  get_args (state2, &args2);

  switch (state1->orig_rax)
  {
  case SYS_socket:
    handle_socket (args2.ret, args1.a1, args1.a2, args1.a3);
    break;
  case SYS_sendto:
    handle_sendto (args2.ret, args1.a1, (const char *) args1.a2, args1.a3, (const struct sockaddr *) args1.a4, args1.a5);
    break;
  case SYS_recvfrom:
    handle_recvfrom (args2.ret, args1.a1, (const char *) args1.a2, args1.a3, args1.a4, (const struct sockaddr *) args1.a5, (const socklen_t *) args1.a6);
    break;
  case SYS_close:
    handle_close (args2.ret, args1.a1);
    break;
  case SYS_dup3:
  case SYS_dup2:
  case SYS_dup:
  case SYS_socketpair:
  case SYS_clone:
  case SYS_recvmmsg:
  case SYS_recvmsg:
//       ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
  case SYS_sendmmsg:
  case SYS_sendmsg:
    /* 
       ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

     */
    // HANDLE unix socket (!) - receiving of descriptors

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
