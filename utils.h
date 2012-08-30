#ifndef NLTRACE_UTILS_H
#define NLTRACE_UTILS_H

#include <stdbool.h>

typedef unsigned long BITARRAY_TYPE;

#define WORDBITS (8 * sizeof(BITARRAY_TYPE))

static inline void bit_set (BITARRAY_TYPE *data, BITARRAY_TYPE index)
{
  data[index / WORDBITS] |= (1 << (index % WORDBITS));
}

static inline void bit_clear (BITARRAY_TYPE *data, BITARRAY_TYPE index)
{
  data[index / WORDBITS] &= ~(1 << (index % WORDBITS));
}

static inline bool bit_get (const BITARRAY_TYPE *data, BITARRAY_TYPE index)
{
  return (data[index / WORDBITS] >> (index % WORDBITS)) & 1;
}

#endif
