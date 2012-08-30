#ifndef NLTACE_SYCALLS_H
#define NLTACE_SYCALLS_H

#include <sys/types.h>

struct user_regs_struct;

void trace_syscall (pid_t pid, const struct user_regs_struct *state1, const struct user_regs_struct *state2);

#endif
