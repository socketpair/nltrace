#include <search.h>
#include <stdlib.h>             /* malloc */
#include <stdio.h>              /* fprintf */

#include "tracer.h"
#include "process.h"

struct tracer
{
  void *processes;
};

/* 
 Should return error if such process already here
*/
int tracer_add_process (struct tracer *tracer, struct process *process)
{


  void *tmp;

  if (!(tmp = tsearch (process, &tracer->processes, compare_processes)))
  {
    fprintf (stderr, "Process adding failure\n");
    return -1;
  }

  if (*(struct process **) tmp != process)
  {
    fprintf (stderr, "Process already exists\n");
    return -1;
  }

  return 0;
}


struct tracer *tracer_alloc (void)
{
  struct tracer *tracer;

  if (!(tracer = malloc (sizeof (*tracer))))
  {
    perror ("malloc");
    return NULL;
  }

  tracer->processes = NULL;
  return tracer;
}


static void _process_destroy (void *arg)
{
  process_destroy ((struct process *) arg);
}


void tracer_destroy (struct tracer *tracer)
{
  tdestroy (tracer->processes, _process_destroy);
  free (tracer);
}
