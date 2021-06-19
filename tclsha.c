/*
 * Copyright 2018 Brad Lanam Walnut Creek, CA
 * Copyright 2020 Brad Lanam Pleasant Hill, CA
 *
 * HMAC reference:
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
 */

#define USE_TCL_STUBS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tcl.h>

#include "sha.h"

static int hexchr2bin(const char hex, char* out)
{
    if (out == NULL)
        return 0;

    if (hex >= '0' && hex <= '9') {
        *out = hex - '0';
    }
    else if (hex >= 'A' && hex <= 'F') {
        *out = hex - 'A' + 10;
    }
    else if (hex >= 'a' && hex <= 'f') {
        *out = hex - 'a' + 10;
    }
    else {
        return 0;
    }

    return 1;
}

static int hexs2bin(const char* hex, char** out, int* doFree)
{
    size_t len;
    char   b1;
    char   b2;
    size_t i;

    if (hex == NULL || *hex == '\0' || out == NULL) {
        return 0;
    }

    len = strlen(hex);
    if (len % 2 != 0) {
        return 0;
    }
    len /= 2;

    *out = ckalloc(len);
    *doFree = 1;
    memset(*out, 'A', len);
    for (i = 0; i < len; i++) {
        if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2)) {
            return 0;
        }
        (*out)[i] = (b1 << 4) | b2;
    }
    return len;
}


static int
shaObjCmd (
  ClientData cd,
  Tcl_Interp* interp,
  int objc,
  Tcl_Obj * const objv[]
  )
{
  char              *buf;         /* temporary string buffer            */
  char              *dbuf;        /* data buffer                        */
  char              *key;         /* key data specified by -key (hmac)  */
  int               keyDynAlloc = 0; /* if -keyhex is specified, the memory for key is ckalloc'ed and must be ckfree'd at the end. This flag takes care about that */
  char              *fn;          /* filename specified by -file        */
  int               len;
  char              *sz;          /* hash type, number of bits          */
  int               szlen;
  int               klen;
  int               rc;
  int               argidx;
  int               argcount;
  int               havemac;
  int               rettype;
  int               flags;
  size_t            msz;
  char              dstr [SHA_DIGESTSIZE];
  size_t            dlen;
  const char        *usagestr =
      "-bits <bits> [{-key <key>|-keyhex <key in hex format>|-keyfile <fn>} -mac hmac] {-file <fn>|-data <string>}";

  if (objc < 3 || objc > 9) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
  }

  /*
   * backwards compatibility:
   *    bits datastr (3)
   *    bits -file fn (4)
   * current:
   *    -bits bits -file fn (5)
   *    -bits bits -data datastr (5)
   *    -bits bits -key key -mac mac -file fn (9)
   *    -bits bits -keyfile keyfn -mac mac -file fn (9)
   *    -bits bits -key key -mac mac -data datastr (9)
   *    -bits bits -keyfile keyfn -mac mac -data datastr (9)
   */
  argcount = 0;
  argidx = 1;
  flags = 0;
  havemac = 0;
  dbuf = NULL;
  fn = NULL;

  while (argidx < objc) {
    buf = Tcl_GetStringFromObj (objv[argidx], &len);
    if (strncmp (buf, "-", 1) == 0) {
      if (strcmp (buf, "-bits") == 0) {
        ++argidx;
        if (argidx < objc) {
          sz = Tcl_GetStringFromObj (objv[argidx], &szlen);
          flags |= SHA_HAVEBITS;
        }
      } else if (strcmp (buf, "-file") == 0) {
        ++argidx;
        if (argidx < objc) {
          fn = Tcl_GetStringFromObj (objv[argidx], &len);
          flags |= SHA_HAVEFILE;
        }
      } else if (strcmp (buf, "-data") == 0) {
        ++argidx;
        if (argidx < objc) {
          dbuf = Tcl_GetStringFromObj (objv[argidx], &len);
          flags |= SHA_HAVEDATA;
          msz = len;
        }
      }
      else if (strcmp(buf, "-key") == 0) {
        ++argidx;
        if (argidx < objc) {
          key = Tcl_GetStringFromObj(objv[argidx], &klen);
          havemac += 1;
        }
      } else if (strcmp(buf, "-keyhex") == 0) {
        ++argidx;
        if (argidx < objc) {
          int khexlen = 0;
          char* khex = Tcl_GetStringFromObj(objv[argidx], &khexlen);
          klen = hexs2bin(khex, &key, &keyDynAlloc);
          havemac += 1;
        }
      } else if (strcmp (buf, "-keyfile") == 0) {
        ++argidx;
        if (argidx < objc) {
          key = Tcl_GetStringFromObj (objv[argidx], &klen);
          havemac += 1;
          flags |= SHA_KEYISFILE;
        }
      } else if (strcmp (buf, "-mac") == 0) {
        ++argidx;
        if (argidx < objc) {
          buf = Tcl_GetStringFromObj (objv[argidx], &len);
          if (strcmp (buf, "hmac") != 0) {
            Tcl_WrongNumArgs (interp, 1, objv, usagestr);
            rc = TCL_ERROR;
            goto cleanupFinish;
          }
          havemac += 1;
        }
      } else {
        Tcl_WrongNumArgs (interp, 1, objv, usagestr);
        rc = TCL_ERROR;
        goto cleanupFinish;
      }
    } else {
      /* backwards compatibility for sha 0.1 */
      if (argcount == 0) {
        sz = Tcl_GetStringFromObj (objv[argidx], &szlen);
        flags |= SHA_HAVEBITS;
        ++argcount;
      } else if (argcount == 1) {
        dbuf = Tcl_GetStringFromObj (objv[argidx], &len);
        flags |= SHA_HAVEDATA;
        msz = len;
        ++argcount;
      } else {
        Tcl_WrongNumArgs (interp, 1, objv, usagestr);
        rc = TCL_ERROR;
        goto cleanupFinish;
      }
    }
    ++argidx;
  }

  if ((havemac > 0 && havemac < 2) || havemac > 2) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    rc = TCL_ERROR;
    goto cleanupFinish;
  }
  if (! ((flags & SHA_HAVEBITS) == SHA_HAVEBITS &&
      (((flags & SHA_HAVEFILE) == SHA_HAVEFILE &&
        (flags & SHA_HAVEDATA) != SHA_HAVEDATA) ||
       ((flags & SHA_HAVEFILE) != SHA_HAVEFILE &&
        (flags & SHA_HAVEDATA) == SHA_HAVEDATA)))) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    rc = TCL_ERROR;
    goto cleanupFinish;
  }

  if (havemac == 2) {
    rc = hmac (sz, dbuf, (size_t) len, key, (size_t) klen, fn, flags, dstr, &dlen);
  } else {
    rc = shahash (sz, dbuf, (size_t) msz, NULL, fn, flags, dstr, &dlen);
  }

  if (rc == 0) {
    Tcl_SetObjResult (interp, Tcl_NewStringObj (dstr, -1));
    rc = TCL_OK;
  } else {
    rc = TCL_ERROR;
  }

cleanupFinish:
  if (keyDynAlloc) {
      ckfree(key);
  }
  return rc;
}


DLLEXPORT int
Sha_Init (Tcl_Interp *interp)
{
  if (!Tcl_InitStubs (interp, "8.4", 0)) {
    return TCL_ERROR;
  }

  Tcl_CreateObjCommand (interp, "sha", shaObjCmd, NULL, NULL);
  Tcl_PkgProvide (interp, "sha", "2.1");
  return TCL_OK;
}
