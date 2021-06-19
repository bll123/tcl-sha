#!/bin/bash

find . -name '*~' -print0 | xargs -0 rm -f
find . -name '*.orig' -print0 | xargs -0 rm -f

#  Tcl_PkgProvide (interp, "sha", "2.1.1");
tclshaver=$(egrep 'PkgProvide' tclsha.c | sed -e 's/"[^"]*$//' -e 's/.*"//')
ver=$(egrep '^set shaver ' pkgIndex.tcl | sed 's/.* //')
if [ "$tclshaver" != "$ver" ]; then
  echo "Version mismatch betweek pkgIndex and tclsha.c"
  exit 1
fi
echo "version $ver"

make clean

buildloc=../ballroomdj
top=sha-${ver}
mkdir -p $top/linux64 $top/linux32 $top/windows64 $top/darwin64 $top/windows32
cp ${buildloc}/linux/64/tcl/lib/sha/sha.so $top/linux64
cp ${buildloc}/linux/32/tcl/lib/sha/sha.so $top/linux32
cp ${buildloc}/darwin/64/tcl/lib/sha/sha.dylib $top/darwin64
cp ${buildloc}/windows/64/tcl/lib/sha/sha.dll $top/windows64
cp ${buildloc}/windows/32/tcl/lib/sha/sha.dll $top/windows32
cp pkgIndex.tcl README.txt $top
test -f ${top}.zip && rm -f ${top}.zip
zip -rq ${top}.zip ${top}
rm -rf $top

top=sha-src-${ver}
mkdir -p $top
cp -r *.c *.h CMakeLists.txt Makefile pkgIndex.tcl README.txt test.dir $top
test -f ${top}.zip && rm -f ${top}.zip
zip -rq ${top}.zip ${top}
rm -rf $top
