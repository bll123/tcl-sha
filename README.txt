Version 2.1.1

Changes:
  2.1.1
    - minor cleanup (bll)
  2.1
    - added CMakeLists.txt for cmake build (EL)
    - added -keyhex/-datahex for hex encoded key resp. data (EL)
    - added -keybin/-databin for strictly binary key resp. data (EL)
    - added -output [hex|base64|binary] option. Hex is default as before (EL)
    - removed sha256 package provide from C code (EL)
  2.0.1
    - Fixed pkgIndex.tcl for Windows.
    - Repackaging only.  The sha version number is still 2.0.
  2.0
    - Added support for hmac.
    - Code cleanup.
    - Arguments no longer require a specific order.
    - Fixed missing cflags for 32-bit linux (large file support).
    - Cleaned up Makefile.

sha-2.1.1.zip : binary package
              Includes Linux 32 bit, Linux 64 bit,
              MacOS 64 bit, Windows 64 bit and Windows 32 bit.
              Does not include the sha-256 binaries.

sha-src-2.1.1.zip : sources and NIST test suite.

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

Using cmake (recommended):

  1. install tcl-devel and cmake for your platform
  2. To build in the "build" directory:

    mkdir -p build && cd build
    cmake ..

    # for unix/linux/darwin
    make

    # for windows, requires the MSVC command prompt
    msbuild tcl-sha.sln /property:Configuration=Release

Using make:

unix/darwin:
    make

  make {linux|darwin|windows}
    make linux should work for freebsd also.

  To validate against the NIST data:
    cd test.dir
    tclsh testsha.tcl
    tclsh testsha.tcl 256
