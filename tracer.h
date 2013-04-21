#ifndef NLTRACE_TRACER_H
#define NLTRACE_TRACER_H

struct tracer;
struct process;

int tracer_add_process (struct tracer *tracer, struct process *process);
struct tracer *tracer_alloc (void);
void tracer_destroy (struct tracer *tracer);
#endif
