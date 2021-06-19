/*
 * Copyright 2018 Brad Lanam Walnut Creek CA
 * Copyright 2020 Brad Lanam Pleasant Hill CA
 * Copyright 2021 Eckhard Lehmann Norderstedt Germany
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

#define VALSINCHUNK 16
#define CHARSINCHUNK (sizeof(hash_t)*VALSINCHUNK)

typedef unsigned char buff_t;

#define SHA_RETURN_RAW   0x00000001
#define SHA_KEYISFILE    0x00000002
#define SHA_HAVEFILE     0x00000004
#define SHA_HAVEDATA     0x00000008
#define SHA_HAVEBITS     0x00000010
#define SHA_BUFFER_ALLOC 0x00000020

int shahash (char *hsize, char *buf, size_t blen, buff_t *predata,
    char *fn, int flags, char *ret, size_t *rlen);
int hmac (char *hsize, char *buf, size_t blen,
    char *inkey, size_t inklen,
    char *fn, int flags, char *ret, size_t *rlen);

#endif
