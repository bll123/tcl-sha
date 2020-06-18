/*
 * Copyright 2018 Brad Lanam Walnut Creek CA
 *
 * This is a very basic test program and will
 * segfault when given the wrong arguments.
 *
 * Could be enhanced to take similar arguments as tclsha.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "sha.h"

int
main (int argc, char *argv[]) {
  char      *buf = argv[2];
  char      ret [SHA_CHARSINHASH*2+1];
  char      *sz;
  size_t    msz;
  int       flags;
  size_t    rlen;

  sz = argv[1];
  flags = 0;
  flags |= SHA_HAVEBITS;
  if (strcmp (buf, "-file") == 0) {
    msz = 1024 * 1024 * 5;
    buf = NULL;
    flags |= SHA_HAVEFILE;
    shahash (sz, buf, msz, NULL, argv[3], flags, ret, &rlen);
  } else {
    flags |= SHA_HAVEDATA;
    shahash (sz, buf, strlen (buf), NULL, NULL, flags, ret, &rlen);
  }
  printf ("%s\n", ret);
}
