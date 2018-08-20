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
  unsigned int      msz;
  char              dstr [SHA_DIGESTSIZE];

  if (objc != 3 && objc != 4) {
    Tcl_WrongNumArgs (interp, 1, objv, "hashsize {-file fn|string}");
    return TCL_ERROR;
  }
  buf = Tcl_GetStringFromObj (objv[2], &len);
  if (strcmp (buf, "-file") != 0 && objc == 4) {
    Tcl_WrongNumArgs (interp, 1, objv, "hashsize {-file fn|string}");
    return TCL_ERROR;
  }

  sz = Tcl_GetStringFromObj (objv[1], &szlen);
  if (szlen != 3 && szlen != 7) {
    Tcl_WrongNumArgs (interp, 1, objv, "hashsize {-file fn|string}");
    return TCL_ERROR;
  }

  rc = TCL_ERROR;
  if (strcmp (buf, "-file") == 0) {
    msz = 1024 * 1024 * 5;
    buf = Tcl_Alloc (msz);
    fn = Tcl_GetStringFromObj (objv[3], &len);
    rc = shahash (sz, (buff_t *) buf, (size_t) msz, dstr, fn);
    Tcl_Free (buf);
  } else {
    rc = shahash (sz, (buff_t *) buf, (size_t) len, dstr, NULL);
  }
  if (rc == 0) {
    Tcl_SetObjResult (interp, Tcl_NewStringObj(dstr, -1));
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
  Tcl_PkgProvide (interp, "sha", "0.2");
  return TCL_OK;
}
