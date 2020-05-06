/*
 * Copyright 2018 Brad Lanam Walnut Creek CA
 */
#ifndef _INC_SHA_H
#define _INC_SHA_H

#include <stdint.h>

/* one of 256, 512 */
#if ! defined(BASEHASHSIZE)
# define BASEHASHSIZE 512
#endif

#if BASEHASHSIZE == 512
  typedef uint64_t hash_t;
#endif
#if BASEHASHSIZE == 256
  typedef uint32_t hash_t;
#endif

#define SHA_VALSINHASH 8
#define SHA_CHARSINHASH (sizeof(hash_t)*SHA_VALSINHASH)
#define SHA_DIGESTSIZE (SHA_CHARSINHASH*2+1)
typedef unsigned char buff_t;

int shahash (char *hsize, buff_t *buf, size_t blen, char *ret, char *fn);

#endif
