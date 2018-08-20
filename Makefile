#!/usr/bin/make
#
#

CFLAGS_OPT = -O2
VER = 8.6
SVER = 86
BITS=64

LINUXTGTS = tsha sha.so
LINC = -I${HOME}/local/include
LLIB = -L${HOME}/local/lib

DARWINTGTS = tsha sha.dylib
DINC = -I${HOME}/local/include
DLIB = -L${HOME}/local/Library/Frameworks/Tcl.Framework/Versions/$(VER)

WINTGTS = tsha.exe sha.dll

.PHONY: unknown
unknown:
	@echo "make darwin/linux/windows"

.PHONY: darwin
darwin:
	$(MAKE) darwintgt

.PHONY: darwintgt
darwintgt:
	$(MAKE) PLATFORM=darwin SFX=.dylib INCS="$(DINC)" \
		LIBS="$(DLIB)" \
		CFLAGS="-mmacosx-version-min=10.9" \
		LDFLAGS="-mmacosx-version-min=10.9" \
		$(DARWINTGTS)

.PHONY: linux
linux:
	$(MAKE) linuxtgt

.PHONY: linuxtgt
linuxtgt:
	$(MAKE) PLATFORM=linux SFX=.so \
		INCS="$(LINC)" \
		LIBS="$(LLIB)" \
		$(LINUXTGTS)

.PHONY: windows
windows:
	$(MAKE) windowstgt

.PHONY: windowstgt
windowstgt:
	$(MAKE) PLATFORM=windows SFX=.dll \
		INCS="-I${HOME}/local-${BITS}/include" \
		LIBS="-L${HOME}/local-${BITS}/lib \
			-L../windows/${BITS}" \
		CFLAGS="-DCOMP_WINDOWS" \
		LDFLAGS="-static-libgcc" \
		$(WINTGTS)

.PHONY: clean
clean:
	@-rm -f *.o *.so *.dylib *.dll *.exe tsha *~

.PHONY: distclean
distclean:
	@$(MAKE) clean

sha.c:			sha.h
tclsha.c:		sha.h

# all
.c.o:
	$(CC) -c $(CFLAGS_OPT) $(CFLAGS) \
		-m${BITS} -fPIC -o $@ $(INCS) $<

# all
sha$(SFX):	tclsha.o sha.o 
	$(CC) $(CFLAGS_OPT) $(LDFLAGS) \
		-m${BITS} -shared -fPIC -o $@ \
		tclsha.o sha.o \
        	$(LIBS) -ltclstub${TCLVER}
tsha:	tsha.o sha.o
	$(CC) $(CFLAGS_OPT) $(LDFLAGS) \
		-m${BITS} -fPIC -o $@ \
		tsha.o sha.o $(LIBS)

# windows
tsha.exe:	tsha.o sha.o
	$(CC) $(CFLAGS_OPT) $(LDFLAGS) \
		-m${BITS} -fPIC -o $@ tsha.o sha.o
