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

int Sha_Init (Tcl_Interp *interp);

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
  char              *fn;          /* filename specified by -file        */
  int               len;
  char              *sz;          /* hash type, number of bits          */
  int               szlen;
  int               klen;
  int               rc;
  int               argidx;
  int               argcount;
  int               havemac;
  int               flags;
  size_t            msz;
  char              dstr [SHA_DIGESTSIZE];
  size_t            dlen;
  const char        *usagestr =
      "-bits <bits> [{-key <key>|-keyfile <fn>} -mac hmac] {-file <fn>|-data <string>}";

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
          msz = (size_t) len;
        }
      } else if (strcmp (buf, "-key") == 0) {
        ++argidx;
        if (argidx < objc) {
          key = Tcl_GetStringFromObj (objv[argidx], &klen);
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
            return TCL_ERROR;
          }
          havemac += 1;
        }
      } else {
        Tcl_WrongNumArgs (interp, 1, objv, usagestr);
        return TCL_ERROR;
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
        msz = (size_t) len;
        ++argcount;
      } else {
        Tcl_WrongNumArgs (interp, 1, objv, usagestr);
        return TCL_ERROR;
      }
    }
    ++argidx;
  }

  if ((havemac > 0 && havemac < 2) || havemac > 2) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
  }
  if (! ((flags & SHA_HAVEBITS) == SHA_HAVEBITS &&
      (((flags & SHA_HAVEFILE) == SHA_HAVEFILE &&
        (flags & SHA_HAVEDATA) != SHA_HAVEDATA) ||
       ((flags & SHA_HAVEFILE) != SHA_HAVEFILE &&
        (flags & SHA_HAVEDATA) == SHA_HAVEDATA)))) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
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
  return rc;
}


int
Sha_Init (Tcl_Interp *interp)
{
  if (!Tcl_InitStubs (interp, "8.4", 0)) {
    return TCL_ERROR;
  }

  Tcl_CreateObjCommand (interp, "sha", shaObjCmd, NULL, NULL);
  Tcl_PkgProvide (interp, "sha", "2.0");
  Tcl_PkgProvide (interp, "sha256", "2.0");
  return TCL_OK;
}
