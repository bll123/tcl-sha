Version 2.0

Changes:
  2.0
    - Added support for hmac.
    - Code cleanup.
    - Arguments no longer require a specific order.

sha-1.0.zip : binary package
              Includes Linux 32 bit, Linux 64 bit,
              MacOS 64 bit, Windows 64 bit, and Windows 32 bit.
              Does not include the sha-256 binaries.

sha-src-1.0.zip : sources and NIST test suite.

Usage:

  package require sha
  set buffer abc123
  set sha512 [sha -bits 512 -data $buffer]
  set sha512 [sha -bits 512 -file pkgIndex.tcl]
  set sha384 [sha -bits 384 -file pkgIndex.tcl]
  set sha512_224 [sha -bits 512/224 -file pkgIndex.tcl]
  set sha512_256 [sha -bits 512/256 -file pkgIndex.tcl]

  package require sha
  set buffer abc123
  set key def456
  set hmac [sha -bits 512 -key $key -mac hmac -data $buffer]
  set hmac [sha -bits 512 -keyfile pkgIndex.tcl -mac hmac -file pkgIndex.tcl]
  set hmac [sha -bits 384 -keyfile pkgIndex.tcl -mac hmac -file pkgIndex.tcl]

  # Using the -data argument is not recommended for binary data.
  # It should only be used for simple textual data.

  # The sha and sha256 packages cannot both be loaded at the same time
  # due to internal naming conflicts.
  # These are not included in the binaries .zip file.
  package require sha256
  set buffer abc123
  set sha256 [sha -bits 256 -data $buffer]
  set sha224 [sha -bits 224 -file pkgIndex.tcl]

  set buffer abc123
  set key def456
  set hmac [sha -bits 256 -key $key -mac hmac -data $buffer]
  set hmac [sha -bits 224 -keyfile pkgIndex.tcl -mac hmac -file pkgIndex.tcl]
  set hmac [sha -bits 256 -keyfile pkgIndex.tcl -mac hmac -file pkgIndex.tcl]

Building:
  make {linux|darwin|windows}
    make linux should work for freebsd also.

  To validate against the NIST data:
    cd test.dir
    tclsh testsha.tcl
    tclsh testsha.tcl 256
