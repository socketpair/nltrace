#include <search.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>             /* malloc */

#include "descriptor.h"
#include "process.h"
#include "main.h"               /* ptrace_memcpy */

struct process
{
  pid_t pid;                    /* should be the first (primary key) */
  void *descriptors;
};

int process_add_descriptor (struct process *process, struct descriptor *descriptor)
{
  void *tmp;

  if (!(tmp = tsearch (descriptor, &process->descriptors, compare_descriptors)))
  {
    fprintf (stderr, "This descriptor adding failure\n");
    return -1;
  }

  if (*(struct descriptor **) tmp != descriptor)
  {
    fprintf (stderr, "This descriptor already in process\n");
    return -1;
  }

  return 0;
}

struct process *process_alloc (pid_t pid)
{
  struct process *process;

  if (!(process = malloc (sizeof (*process))))
  {
    perror ("malloc");
    return NULL;
  }

  process->pid = pid;
  process->descriptors = NULL;
  return process;
}

static void _descriptor_destroy (void *arg)
{
  descriptor_destroy ((struct descriptor *) arg);
}

void process_destroy (struct process *process)
{
  tdestroy (process->descriptors, _descriptor_destroy);
  free (process);
}

int compare_processes (const void *a, const void *b)
{
  /* void pointer may point to either struct process or it's primary key (pid_t pid) */

  pid_t pa = *(const pid_t *) a;
  pid_t pb = *(const pid_t *) b;

  if (pa == pb)
    return 0;
  else
    return (pa > pb) ? 1 : -1;
}

struct descriptor *process_get_descriptor (struct process *process, int fd)
{
  struct descriptor *descriptor;
  void *tmp1;
  pid_t pid;

  if ((tmp1 = tfind (&fd, &process->descriptors, compare_descriptors)))
    return *(struct descriptor **) tmp1;

  fprintf (stderr, "Detecting descriptor type of fd %d!\n", fd);

  pid = process->pid;

  if (!pid)
  {
    if ((descriptor = descriptor_alloc_detect_live (fd)))
      goto descriptor_ready;

    fprintf (stderr, "descriptor_alloc_detect_live failed. Falling back to /proc detector\n");
    pid = getpid ();
  }

  if (!(descriptor = descriptor_alloc_detect_proc (fd, pid)))
  {
    fprintf (stderr, "descriptor_alloc_detect_proc failed\n");
    return NULL;
  }

descriptor_ready:

  if (process_add_descriptor (process, descriptor) == -1)
  {
    fprintf (stderr, "Failed to add descriptor to process\n");
    descriptor_destroy (descriptor);
    return NULL;
  }

  return descriptor;
}

void process_delete_descriptor_int (struct process *process, int fd)
{
  void *tmp;
  struct descriptor *descriptor;

  //fprintf (stderr, "BUG: descriptor not found (or cannot be deleted)\n");
  // should not bark, as it called in places where descriptor really may not exists...

  if (!(tmp = tfind (&fd, &process->descriptors, compare_descriptors)))
    return;

  descriptor = *(struct descriptor **) tmp;

  if (!tdelete (descriptor, &process->descriptors, compare_descriptors))
  {
    fprintf (stderr, "Achtung! descriptor was found but cannot be deleted!\n");
    return;
  }

  descriptor_destroy (descriptor);
}


int process_memcpy (const struct process *process, void *dst, const void *src, size_t length)
{
  if (process->pid)
    return ptrace_memcpy (process->pid, dst, src, length);

  memcpy (dst, src, length);
  return 0;
}

unsigned char *process_dup_memory (const struct process *process, const char *buf, size_t buflen)
{
  unsigned char *data;

  if (!(data = malloc (buflen)))
  {
    perror ("malloc");
    return NULL;
  }

  if (process_memcpy (process, data, buf, buflen) == -1)
  {
    fprintf (stderr, "process_memcpy() failed\n");
    free (data);
    return NULL;
  }

  return data;
}
