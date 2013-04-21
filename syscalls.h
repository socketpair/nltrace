#ifndef NLTACE_SYCALLS_H
#define NLTACE_SYCALLS_H

#include <sys/types.h>

struct user_regs_struct;
struct process;

void trace_syscall (struct process *process, const struct user_regs_struct *state1, const struct user_regs_struct *state2);
int usermemcpy (void *destination, pid_t pid, const void *usermem, size_t length);

#endif
