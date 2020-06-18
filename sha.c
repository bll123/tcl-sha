/*
 * Copyright 2018 Brad Lanam Walnut Creek CA
 * Copyright 2020 Brad Lanam Pleasant Hill CA
 *
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include <sys/stat.h>
#include <string.h>

#define SHA_DEBUG 0

#define bs32(x) \
    ( (((x) << 24) & 0xff000000) \
    | (((x) <<  8) & 0x00ff0000) \
    | (((x) >>  8) & 0x0000ff00) \
    | (((x) >> 24) & 0x000000ff ))
#define bs64(x) \
    ( (((x) & 0xff00000000000000ull) >> 56) \
    | (((x) & 0x00ff000000000000ull) >> 40) \
    | (((x) & 0x0000ff0000000000ull) >> 24) \
    | (((x) & 0x000000ff00000000ull) >> 8) \
    | (((x) & 0x00000000ff000000ull) << 8) \
    | (((x) & 0x0000000000ff0000ull) << 24) \
    | (((x) & 0x000000000000ff00ull) << 40) \
    | (((x) & 0x00000000000000ffull) << 56))

#include "sha.h"

#define IS_BIG_ENDIAN (!*(unsigned char*)(void*)&(uint16_t){1})
#define LASTSIZE (sizeof(uint64_t)*(BASEHASHSIZE/256))

#define RR(a,b,c) (((a) >> (b)) | ((a) << ((c)-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

typedef struct {
  size_t      flen;     /* actual length        */
  size_t      aflen;    /* adjusted length      */
  size_t      foffset;  /* actual offset        */
  size_t      blen;     /* length of buffer     */
  size_t      boffset;  /* offset into buffer   */
  buff_t      *buf;
  buff_t      *chunk;
} shainfo_t;

#if BASEHASHSIZE == 512

# define SHAFMT "%016llx"
# define bs bs64    /* the bs macro is for use on hash_t */

# define SIG0(x) (RR(x,1,64) ^ RR(x,8,64) ^ ((x) >> 7))
# define SIG1(x) (RR(x,19,64) ^ RR(x,61,64) ^ ((x) >> 6))
# define EP0(x) (RR(x,28,64) ^ RR(x,34,64) ^ RR(x,39,64))
# define EP1(x) (RR(x,14,64) ^ RR(x,18,64) ^ RR(x,41,64))

  static hash_t sha_h512_init[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
  };
  static hash_t sha_h384_init[] = {
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
  };

  static hash_t sha_h512_224_init[] = {
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1
  };

  static hash_t sha_h512_256_init[] = {
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2
  };

  static hash_t sha_k[] = {
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817
  };
#endif

#if BASEHASHSIZE == 256

# define SHAFMT "%08x"
# define bs bs32   /* the bs macro is for use on hash_t */

# define SIG0(x) (RR(x,7,32) ^ RR(x,18,32) ^ ((x) >> 3))
# define SIG1(x) (RR(x,17,32) ^ RR(x,19,32) ^ ((x) >> 10))
# define EP0(x) (RR(x,2,32) ^ RR(x,13,32) ^ RR(x,22,32))
# define EP1(x) (RR(x,6,32) ^ RR(x,11,32) ^ RR(x,25,32))

  static hash_t sha_h256_init[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };
  static hash_t sha_h224_init[] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4
  };

  static hash_t sha_k[] = {
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
  };
#endif
#define MAXLOOP (sizeof(sha_k)/sizeof(hash_t))

#if SHA_DEBUG

static void
dump (char *msg, buff_t *buf, size_t len)
{
  printf ("%s: ", msg);
  for (int i = 0; i < len; ++i) {
    printf ("%02x", buf[i]);
  }
  printf ("\n");
  fflush (stdout);
}

#endif


static inline int
fillChunk (shainfo_t *shainfo, buff_t *predata)
{
  size_t        copylen = CHARSINCHUNK;
  size_t        coffset;
  int           last = 0;
  uint64_t      nlen;
  long          left;


  if (predata != NULL) {
    memcpy (shainfo->chunk, predata, CHARSINCHUNK);
#if SHA_DEBUG
    dump ("fc:predata", shainfo->chunk, CHARSINCHUNK);
#endif
    shainfo->aflen += CHARSINCHUNK;
    return last;
  }

  left = (long) (shainfo->flen - shainfo->foffset);
  if ( left < (long) CHARSINCHUNK ) {
    copylen = left < 0 ? 0 : shainfo->blen - shainfo->boffset;
    memset (shainfo->chunk, '\0', CHARSINCHUNK);
    coffset = copylen;
    if (left >= 0) {
      *(shainfo->chunk + coffset) = 0x80;
    }
    if (CHARSINCHUNK - copylen - 1 >= LASTSIZE) {
      /* 512/384 actually use a 128 bit value */
      nlen = (uint64_t) shainfo->aflen * 8;
      if ( ! IS_BIG_ENDIAN ) {
        nlen = bs64 (nlen);
      }
      memcpy (shainfo->chunk + CHARSINCHUNK - sizeof(nlen), &nlen, sizeof (nlen));
      last = 1;
    }
  }

  memcpy (shainfo->chunk, shainfo->buf + shainfo->boffset, copylen);
#if SHA_DEBUG
  dump ("fc:chunk", shainfo->chunk, CHARSINCHUNK);
#endif
  return last;
}

int
shahash (char *hsize, char *buf, size_t blen, buff_t *predata,
    char *fn, int flags, char *ret, size_t *rlen)
{
  hash_t      sha_h [SHA_VALSINHASH];
  hash_t      w [MAXLOOP];
  hash_t      a, b, c, d, e, f, g, h;
  hash_t      t1, t2;
  size_t      i;
  size_t      maxbuff = 1024 * 1024 * 5;
  hash_t      *ptr;               /* used for return_raw */
  int         last, half;
  shainfo_t   shainfo;
  FILE        *fh = NULL;

  if ((flags & SHA_RETURN_RAW) != SHA_RETURN_RAW) {
    ret [0] = '\0';
    ret [SHA_CHARSINHASH * 2] = '\0';
  }
#if BASEHASHSIZE == 512
  if (strcmp (hsize, "512") != 0 &&
      strcmp (hsize, "384") != 0 &&
      strcmp (hsize, "512/256") != 0 &&
      strcmp (hsize, "512/224") != 0) {
    return 2;
  }
  if (strcmp (hsize, "384") == 0) {
    memcpy (sha_h, sha_h384_init, sizeof (sha_h384_init));
  }
  if (strcmp (hsize, "512") == 0) {
    memcpy (sha_h, sha_h512_init, sizeof (sha_h512_init));
  }
  if (strcmp (hsize, "512/224") == 0) {
    memcpy (sha_h, sha_h512_224_init, sizeof (sha_h512_init));
  }
  if (strcmp (hsize, "512/256") == 0) {
    memcpy (sha_h, sha_h512_256_init, sizeof (sha_h512_init));
  }
#endif
#if BASEHASHSIZE == 256
  if (strcmp (hsize, "256") != 0 &&
      strcmp (hsize, "224") != 0) {
    return 2;
  }
  if (strncmp (hsize, "256", 3) == 0) {
    memcpy (sha_h, sha_h256_init, sizeof (sha_h256_init));
  }
  if (strcmp (hsize, "224") == 0) {
    memcpy (sha_h, sha_h224_init, sizeof (sha_h224_init));
  }
#endif

  shainfo.flen = blen;
  shainfo.aflen = blen;
  shainfo.foffset = 0;
  shainfo.blen = blen;
  shainfo.boffset = 0;
  shainfo.buf = (buff_t *) buf;
  shainfo.chunk = (buff_t *) w;

  if ((flags & SHA_HAVEFILE) == SHA_HAVEFILE && fn != NULL) {
    struct stat statbuf;

    buf = malloc (maxbuff);
    if (buf == NULL) {
      return 1;
    }
    shainfo.buf = (buff_t *) buf;
    flags |= SHA_BUFFER_ALLOC;
    fh = fopen (fn, "rb");
    if (fh == (FILE *) NULL) {
      free (buf);
      flags &= ~SHA_BUFFER_ALLOC;
      return 3;
    }
    stat (fn, &statbuf);
    shainfo.flen = (size_t) statbuf.st_size;
    shainfo.aflen = shainfo.flen;
    shainfo.blen = fread (buf, 1, maxbuff, fh);
  }

  do {
    last = fillChunk (&shainfo, predata);
    if ( ! IS_BIG_ENDIAN ) {
      for (i = 0; i < VALSINCHUNK; ++i) {
        w[i] = bs (w[i]);
      }
    }
    if (predata == NULL) {
      shainfo.boffset += CHARSINCHUNK;
      shainfo.foffset += CHARSINCHUNK;
    }

    /* if the buffer is getting empty, move what's left to
       the beginning and fill it up again */
    if (predata == NULL &&
        (flags & SHA_HAVEFILE) == SHA_HAVEFILE &&
        shainfo.blen - shainfo.boffset < CHARSINCHUNK) {
      i = shainfo.blen - shainfo.boffset;
      if (i > 0) {
        memmove (buf, buf + shainfo.boffset, i);
      }
      shainfo.blen -= shainfo.boffset;
      shainfo.boffset = 0;
      shainfo.blen += fread (buf + shainfo.boffset,
          1, maxbuff - shainfo.blen, fh);
    }

    for (i = 16; i < MAXLOOP; ++i) {
      w[i] = w[i-16] + SIG0(w[i-15]) + w[i-7] + SIG1(w[i-2]);
    }

    a = sha_h[0];
    b = sha_h[1];
    c = sha_h[2];
    d = sha_h[3];
    e = sha_h[4];
    f = sha_h[5];
    g = sha_h[6];
    h = sha_h[7];

    for (i = 0; i < MAXLOOP; ++i) {
      t1 = h + EP1(e) + CH(e,f,g) + sha_k[i] + w[i];
      t2 = EP0(a) + MAJ(a,b,c);

      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    sha_h[0] += a;
    sha_h[1] += b;
    sha_h[2] += c;
    sha_h[3] += d;
    sha_h[4] += e;
    sha_h[5] += f;
    sha_h[6] += g;
    sha_h[7] += h;

    predata = NULL;
  } while (last == 0);

  if ((flags & SHA_HAVEFILE) == SHA_HAVEFILE && fn != NULL) {
    fclose (fh);
  }

  if ((flags & SHA_RETURN_RAW) == SHA_RETURN_RAW) {
    ptr = (hash_t *) ret;
  }

  half = 0;
  *rlen = 0;
  for (i = 0; i < SHA_VALSINHASH; ++i) {
    if (strcmp (hsize, "224") == 0 && i == 7) {
      break;
    }
    if (strcmp (hsize, "512/224") == 0 && i > 3) {
      break;
    }
    if (strcmp (hsize, "512/224") == 0 && i == 3) {
      half = 1;
    }
    if (strcmp (hsize, "512/256") == 0 && i > 3) {
      break;
    }
    if (strcmp (hsize, "384") == 0 && i > 5) {
      break;
    }

    if ((flags & SHA_RETURN_RAW) == SHA_RETURN_RAW) {
      if ( ! IS_BIG_ENDIAN ) {
        *(ptr+i) = bs (sha_h[i]);
      } else {
        *(ptr+i) = sha_h[i];
      }
    } else {
      sprintf (ret+(i*sizeof(hash_t)*2), SHAFMT, sha_h[i]);
      if (half) {
        *(ret+((i+1)*sizeof(hash_t)*2)-8) = '\0';
      }
    }
    ++*rlen;
  }
#if SHA_DEBUG
  if ((flags & SHA_RETURN_RAW) == SHA_RETURN_RAW) {
    printf ("rlen-a: %d\n", *rlen);
  }
#endif
  *rlen *= sizeof (hash_t);

#if SHA_DEBUG
  if ((flags & SHA_RETURN_RAW) == SHA_RETURN_RAW) {
    printf ("rlen-b: %d\n", *rlen);
    dump ("ret-raw", ret, *rlen);
  }
#endif

  if ((flags & SHA_RETURN_RAW) != SHA_RETURN_RAW) {
    ret [SHA_CHARSINHASH*2] = '\0';
  }
  if ((flags & SHA_BUFFER_ALLOC) == SHA_BUFFER_ALLOC) {
    free (buf);
    flags &= ~SHA_BUFFER_ALLOC;
  }
  return 0;
}

static void
hmacpad (buff_t *key, buff_t xorvalue, buff_t *ret)
{
  memcpy (ret, key, CHARSINCHUNK);
  for (int i = 0; i < (int) CHARSINCHUNK; ++i) {
    ret[i] ^= xorvalue;
  }
#if SHA_DEBUG
  dump ("hmac-key", ret, CHARSINCHUNK);
#endif
}

int
hmac (char *hsize, char *buf, size_t blen, char *inkey, size_t inklen,
    char *fn, int flags, char *ret, size_t *rlen)
{
  int           rc;
  buff_t        key [CHARSINCHUNK];
  buff_t        ikey [CHARSINCHUNK];
  buff_t        okey [CHARSINCHUNK];
  buff_t        *predata;
  size_t        klen;

  memset (key, '\0', CHARSINCHUNK);
  memset (ret, '\0', CHARSINCHUNK);
  if ((flags & SHA_KEYISFILE) == SHA_KEYISFILE) {
    FILE        *fh;
    struct stat statbuf;

#if SHA_DEBUG
    printf ("keyfile: %s\n", inkey);
#endif
    fh = fopen (inkey, "rb");
    if (fh == (FILE *) NULL) {
      return 1;
    }
    stat (inkey, &statbuf);
    if ((size_t) statbuf.st_size > CHARSINCHUNK) {
#if SHA_DEBUG
      printf ("hmac: %d > %d : key by hash \n", statbuf.st_size, CHARSINCHUNK);
#endif
      flags |= SHA_RETURN_RAW;
      shahash (hsize, inkey, 0, NULL, inkey, flags, (char *) key, &klen);
      flags &= ~SHA_RETURN_RAW;
    } else {
#if SHA_DEBUG
      printf ("key from file\n");
#endif
      fread (key, 1, CHARSINCHUNK, fh);
    }
    fclose (fh);
  } else {
#if SHA_DEBUG
    printf ("key from data\n");
#endif
    memcpy (key, inkey, inklen);
  }
#if SHA_DEBUG
  dump ("key", key, CHARSINCHUNK);
#endif

  hmacpad (key, 0x36, ikey);
  hmacpad (key, 0x5c, okey);
  predata = ikey;
  flags |= SHA_RETURN_RAW;
  rc = shahash (hsize, buf, blen, predata, fn, flags, (char *) key, rlen);
#if SHA_DEBUG
  printf ("hmac-ret len: %d\n", *rlen);
  dump ("hmac-ret", key, *rlen);
#endif

  predata = okey;
  flags &= ~SHA_RETURN_RAW;
  flags &= ~SHA_HAVEFILE;
  flags |= SHA_HAVEDATA;
  rc = shahash (hsize, (char *) key, *rlen, predata, fn, flags, ret, rlen);
  return rc;
}
