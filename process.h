#ifndef NLTRACE_PROCESS_H
#define NLTRACE_PROCESS_H

struct process;
struct descriptor;

int process_add_descriptor (struct process *process, struct descriptor *descriptor);
struct process *process_alloc (pid_t pid);
void process_destroy (struct process *process);
int compare_processes (const void *a, const void *b);
struct descriptor *process_get_descriptor (struct process *process, int fd);
void process_delete_descriptor_int (struct process *process, int fd);

unsigned char *process_dup_memory (const struct process *process, const char *buf, size_t buflen);
int process_memcpy (const struct process *process, void *dst, const void *src, size_t length);
#endif
