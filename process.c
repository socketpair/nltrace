#include <search.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>             /* malloc */

#include "descriptor.h"
#include "process.h"

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
  char path[128];
  char result[256];
  int tmp;
  void *tmp1;

  if ((tmp1 = tfind (&fd, &process->descriptors, compare_descriptors)))
    return *(struct descriptor **) tmp1;

  fprintf (stderr, "Detecting descriptor type of fd %d!\n", fd);
  tmp = snprintf (path, sizeof (path), "/proc/%u/fd/%d", process->pid, fd);

  if (tmp <= 0)
  {
    perror ("sprintf of path");
    return NULL;
  }

  if (tmp >= (int) (sizeof (path)))
  {
    fprintf (stderr, "printf buffer overflow\n");
    return NULL;
  }

  if (readlink (path, result, sizeof (result)) == -1)
  {
    perror ("readlink");
    return NULL;
  }

  if (!(descriptor = descriptor_alloc_detect (fd, result)))
  {
    fprintf (stderr, "descriptor_alloc_detect failed\n");
    return NULL;
  }

  if (!(tmp1 = tsearch (descriptor, &process->descriptors, compare_descriptors)))
  {
    fprintf (stderr, "Failed to find add descriptor to process\n");
    descriptor_destroy (descriptor);
    return NULL;
  }

  return descriptor;
}

void process_delete_descriptor_int (struct process *process, int fd)
{
  void *tmp;

  if (!(tmp = tdelete (&fd, &process->descriptors, compare_descriptors)))
  {
    //fprintf (stderr, "BUG: descriptor not found (or cannot be deleted)\n");
    // should not bark, as it called in places where descriptor really may not exists...
    return;
  }

  descriptor_destroy (*(struct descriptor **) tmp);
}

pid_t process_get_pid (const struct process *process)
{
  return process->pid;
}
