#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>

void child ();
void parent (pid_t pid);

int main (int argc, char *argv[])
{
  pid_t pid;

  if (argc < 2)
    return 1;


  if (!(pid = fork ()))
  {
    if (prctl (PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == -1)
      return 1;
    if (ptrace (PTRACE_TRACEME, 0, 0, 0) == -1)
      return 2;
    execvp (argv[1], argv + 1);
    return 3;
  }

  int status;

  if (waitpid (pid, &status, 0) == -1)
    return 4;

  if (WIFEXITED (status))
    return status;

  if (ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1)
    return 5;

  while (!WIFEXITED (status))
  {

    struct user_regs_struct state;

    if (ptrace (PTRACE_SYSCALL, pid, 0, 0) == -1)
      return 6;

    if (waitpid (pid, &status, 0) == -1)
      return 7;

    // at syscall
    if (!WIFSTOPPED (status))
      continue;

    if (!(WSTOPSIG (status) & 0x80))
      continue;

    if (ptrace (PTRACE_GETREGS, pid, 0, &state) == -1)
      return 8;

    printf ("SYSCALL %lx at %08lx\n", state.orig_rax, state.rip);

#if 0
    // sys_write
    if (state.orig_eax == 4)
    {
      char *text = (char *) state.ecx;
      ptrace (PTRACE_POKETEXT, pid, (void *) (text + 7), 0x72626168);   //habr
      ptrace (PTRACE_POKETEXT, pid, (void *) (text + 11), 0x00000a21);  //!\n
    }
#endif

    // skip after syscall
    if (ptrace (PTRACE_SYSCALL, pid, 0, 0) == -1)
      return 9;
    if (waitpid (pid, &status, 0) == -1)
      return 10;
  }
  return status;
}
