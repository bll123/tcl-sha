/*
 * Copyright 2018 Brad Lanam Walnut Creek CA
 *
 * This is a very basic test program and will
 * segfault when given the wrong arguments.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "sha.h"

int
main (int argc, char *argv[]) {
  char *buf = argv[2];
  char ret [SHA_CHARSINHASH*2+1];
  size_t sz;
  size_t msz;

  sz = (size_t) atol(argv[1]);
  if (strcmp (buf, "-file") == 0) {
    msz = 1024 * 1024 * 5;
    buf = malloc (msz);
    shahash (sz, (buff_t *) buf, msz, ret, argv[3]);
    free (buf);
  } else {
    shahash (sz, (buff_t *) buf, strlen (buf), ret, NULL);
  }
  printf ("%s\n", ret);
}
