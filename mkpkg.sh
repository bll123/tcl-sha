#!/bin/bash

find . -name '*~' -print0 | xargs -0 rm -f
find . -name '*.orig' -print0 | xargs -0 rm -f

ver=2.0.1
echo "version $ver"

make clean

top=sha-${ver}
mkdir -p $top/linux64 $top/linux32 $top/windows64 $top/darwin64
cp ../ballroomdj/linux/64/tcl/lib/sha/sha.so $top/linux64
cp ../ballroomdj/linux/32/tcl/lib/sha/sha.so $top/linux32
cp ../ballroomdj/darwin/64/tcl/lib/sha/sha.dylib $top/darwin64
cp ../ballroomdj/windows/64/tcl/lib/sha/sha.dll $top/windows64
cp pkgIndex.tcl README.txt $top
test -f ${top}.zip && rm -f ${top}.zip
zip -rq ${top}.zip ${top}
rm -rf $top

top=sha-src-${ver}
mkdir -p $top
cp -r *.c *.h Makefile pkgIndex.tcl README.txt test.dir $top
test -f ${top}.zip && rm -f ${top}.zip
zip -rq ${top}.zip ${top}
rm -rf $top
