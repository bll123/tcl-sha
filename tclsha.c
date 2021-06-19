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

static const char* OutputFormats[] = {
    "binary",
    "hex",
    "base64",
    NULL
};

enum OutputFormatsIndex {
    OutputFormatBinaryIx,
    OutputFormatHexIx,
    OutputFormatBase64Ix
};

/*
 * Gracefully taken from https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
 */
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Gracefully taken from https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
 */
size_t b64_encoded_size(size_t inlen)
{
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

/*
 * Gracefully taken from https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
 */
static char* b64_encode(const unsigned char* in, size_t len)
{
    char* out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out = ckalloc(elen + 1);
    out[elen] = '\0';

    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        v = in[i];
        v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
        v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        if (i + 1 < len) {
            out[j + 2] = b64chars[(v >> 6) & 0x3F];
        }
        else {
            out[j + 2] = '=';
        }
        if (i + 2 < len) {
            out[j + 3] = b64chars[v & 0x3F];
        }
        else {
            out[j + 3] = '=';
        }
    }

    return out;
}

/*
 * Gracefully taken from https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/
 */
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

/*
 * Gracefully taken from https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/
 */
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

static int convert_to_binary(Tcl_Obj* tclObj, char** bufOut, int* doFree) {
    int i = 0;
    int len;
    Tcl_UniChar* uniStr = Tcl_GetUnicodeFromObj(tclObj, &len);
    *bufOut = ckalloc(len);
    *doFree = 1;
    for (i = 0; i < len; i++) {
        (*bufOut)[i] = (char)uniStr[i];
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
  int               dataDynAlloc = 0; /* if -datahex is specified, the memory for data is ckalloc'ed and must be ckfree'd at the end. This flag takes care about that */
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
  int               outputFormatIdx = OutputFormatHexIx;

  if (objc < 3 || objc > 11) {
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
          msz = len;
        }
      } else if (strcmp (buf, "-data") == 0) {
        ++argidx;
        if (argidx < objc) {
          dbuf = Tcl_GetStringFromObj (objv[argidx], &len);
          flags |= SHA_HAVEDATA;
          msz = len;
        }
      } else if (strcmp(buf, "-databin") == 0) {
          ++argidx;
          if (argidx < objc) {
              msz = convert_to_binary(objv[argidx], &dbuf, &dataDynAlloc);
              flags |= SHA_HAVEDATA;
          }
      } else if (strcmp(buf, "-datahex") == 0) {
          ++argidx;
          if (argidx < objc) {
              int dhexlen = 0;
              char* dhex = Tcl_GetStringFromObj(objv[argidx], &dhexlen);
              msz = hexs2bin(dhex, &dbuf, &dataDynAlloc);
              flags |= SHA_HAVEDATA;
          }
      } else if (strcmp(buf, "-key") == 0) {
        ++argidx;
        if (argidx < objc) {
          key = Tcl_GetStringFromObj(objv[argidx], &klen);
          havemac += 1;
        }
      } else if (strcmp(buf, "-keybin") == 0) {
          ++argidx;
          if (argidx < objc) {
              klen = convert_to_binary(objv[argidx], &key, &keyDynAlloc);
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
      } else if (strcmp(buf, "-mac") == 0) {
        ++argidx;
        if (argidx < objc) {
          buf = Tcl_GetStringFromObj(objv[argidx], &len);
          if (strcmp(buf, "hmac") != 0) {
            Tcl_WrongNumArgs(interp, 1, objv, usagestr);
            rc = TCL_ERROR;
            goto cleanupFinish;
          }
          havemac += 1;
        }
      } else if (strcmp(buf, "-output") == 0) {
          ++argidx;
          if (argidx < objc) {
              int fmtIdx;
              if (Tcl_GetIndexFromObj(interp, objv[argidx], OutputFormats, "format", 0, &outputFormatIdx) != TCL_OK) {
                  return TCL_ERROR;
              }
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
    rc = hmac (sz, dbuf, (size_t) msz, key, (size_t) klen, fn, flags, dstr, &dlen);
  } else {
    rc = shahash (sz, dbuf, (size_t) msz, NULL, fn, flags, dstr, &dlen);
  }

  if (rc == 0) {
      switch (outputFormatIdx) {
      case OutputFormatBinaryIx: {
          char *binaryOutput;
          int dynAlloc;
          int oLen = hexs2bin(dstr, &binaryOutput, &dynAlloc);
          Tcl_UniChar* uniChars = ckalloc(oLen*sizeof(Tcl_UniChar));
          Tcl_DString* dStr = ckalloc(sizeof(Tcl_DString));

          Tcl_DStringInit(dStr);

          for (int i = 0; i < oLen; i++) {
              uniChars[i] = (Tcl_UniChar)binaryOutput[i];
          }
          Tcl_UniCharToUtfDString(uniChars, oLen, dStr);
          Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_DStringValue(dStr), -1));
          ckfree(binaryOutput);
          Tcl_DStringFree(dStr);
          ckfree(dStr);
          ckfree(uniChars);
          break;
      }
      case OutputFormatBase64Ix: {
          char *binaryOutput, *base64Output;
          int dynAlloc;
          int oLen = hexs2bin(dstr, &binaryOutput, &dynAlloc);

          base64Output = b64_encode(binaryOutput, oLen);
          Tcl_SetObjResult(interp, Tcl_NewStringObj(base64Output, -1));
          ckfree(binaryOutput);
          ckfree(base64Output);
          break;
      }
      case OutputFormatHexIx:
      default:
          Tcl_SetObjResult(interp, Tcl_NewStringObj(dstr, -1));
      }

    rc = TCL_OK;
  } else {
    rc = TCL_ERROR;
  }

cleanupFinish:
  if (keyDynAlloc) {
      ckfree(key);
  }
  if (dataDynAlloc) {
      ckfree(dbuf);
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
