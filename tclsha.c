/*
 * Copyright 2018 Brad Lanam Walnut Creek, CA
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
  char              *buf;
  char              *fn;
  int               len;
  char              *sz;
  int               szlen;
  int               rc;
  int               argidx;
  int               argcount;
  unsigned int      msz;
  char              dstr [SHA_DIGESTSIZE];
  const char        *usagestr = "-bits <bits> {-file <fn>|-data <string>}";

  if (objc < 3 || objc > 5) {
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
   */
  argcount = 3;
  argidx = 1;
  buf = Tcl_GetStringFromObj (objv[argidx], &len);
  /* backwards compatibility: no -bits specified. */
  if (strcmp (buf, "-bits") == 0) {
    ++argidx;
    /* if -bits is specified, must have -file or -data. */
    argcount = 5;
  }

  sz = Tcl_GetStringFromObj (objv[argidx], &szlen);
  if (szlen != 3 && szlen != 7) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
  }

  ++argidx;
  buf = Tcl_GetStringFromObj (objv[argidx], &len);
  if (argcount != 5 && strcmp (buf, "-file") == 0) {
    ++argcount;
  }
  if (argcount == 5 &&
      strcmp (buf, "-file") != 0 &&
      strcmp (buf, "-data") != 0) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
  }
  if (objc != argcount) {
    Tcl_WrongNumArgs (interp, 1, objv, usagestr);
    return TCL_ERROR;
  }

  rc = TCL_ERROR;
  if (strcmp (buf, "-file") == 0) {
    ++argidx;
    msz = 1024 * 1024 * 5;
    buf = Tcl_Alloc (msz);
    fn = Tcl_GetStringFromObj (objv[argidx], &len);
    rc = shahash (sz, (buff_t *) buf, (size_t) msz, dstr, fn);
    Tcl_Free (buf);
  } else if (strcmp (buf, "-data") == 0) {
    ++argidx;
    buf = Tcl_GetStringFromObj (objv[argidx], &len);
    rc = shahash (sz, (buff_t *) buf, (size_t) len, dstr, NULL);
  } else {
    /* for backwards compatibility */
    rc = shahash (sz, (buff_t *) buf, (size_t) len, dstr, NULL);
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
  if (!Tcl_InitStubs (interp, "8.3", 0)) {
    return TCL_ERROR;
  }

  Tcl_CreateObjCommand (interp, "sha", shaObjCmd, NULL, NULL);
  Tcl_PkgProvide (interp, "sha", "1.0");
  Tcl_PkgProvide (interp, "sha256", "1.0");
  return TCL_OK;
}
