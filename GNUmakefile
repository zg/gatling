#DEBUG=1
ZLIB=1
prefix=/opt/diet
BINDIR=${prefix}/bin
MANDIR=${prefix}/man
man1dir=$(MANDIR)/man1

TARGETS=gatling httpbench bindbench dl ioerr bench tlsgatling_nofail \
pthreadbench cgi ptlsgatling_nofail
TARGETS2=mktestdata mmapbench manymapbench forkbench forksbench
ALLTARGETS=$(TARGETS) acc hcat referrer hitprofile matchiprange getlinks \
rellink $(TARGETS2)

all: $(ALLTARGETS)

CROSS=
#CROSS=i686-mingw32-
CC=$(CROSS)gcc
CFLAGS=-pipe -Wall
LDFLAGS=

#CFLAGS+=-DSTATE_DEBUG -DMOREDEBUG -DDEBUG_EVENTS -DSMDEBUG

path = $(subst :, ,$(PATH))
diet_path = $(foreach dir,$(path),$(wildcard $(dir)/diet))
ifeq ($(strip $(diet_path)),)
ifneq ($(wildcard /opt/diet/bin/diet),)
DIET=/opt/diet/bin/diet
else
DIET=
endif
else
DIET:=$(strip $(diet_path))
endif

# to build without diet libc support, use $ make DIET=
# see http://www.fefe.de/dietlibc/ for details about the diet libc

ifneq ($(DEBUG),)
CFLAGS+=-g
LDFLAGS+=-g
else
CFLAGS+=-O2 -fomit-frame-pointer -I/usr/local/include
LDFLAGS+=-s
ifneq ($(DIET),)
DIET+=-Os
endif
endif

LDLIBS=-lowfat

ifeq ($(ZLIB),1)
CFLAGS+=-DUSE_ZLIB
LDLIBS+=-lz
endif

libowfat_path = $(strip $(foreach dir,../libowfat*,$(wildcard $(dir)/textcode.h)))
ifneq ($(libowfat_path),)
CFLAGS+=$(foreach fnord,$(libowfat_path),-I$(dir $(fnord)))
LDFLAGS+=$(foreach fnord,$(libowfat_path),-L$(dir $(fnord)))
endif

ifneq ($(REDIRECT),)
CFLAGS+="-DREDIRECT=\"$(REDIRECT)\""
endif

acc: acc.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS) -lowfat

CC:=$(DIET) $(CC)

pthreadbench: pthreadbench.o
	$(CC) $< -o $@ -I. $(CFLAGS) $(LDFLAGS) $(LDLIBS) -lpthread

forksbench: forkbench.o
	$(CC) -static -o $@ forkbench.o $(LDFLAGS) $(LDLIBS)

gatling.o tlsgatling ptlsgatling: havesetresuid.h

OBJS=mime.o ftp.o http.o smb.o common.o connstat.o
HTTPS_OBJS=mime.o ftp.c https.o smb.c common.c connstat.o
PHTTPS_OBJS=mime.o ftp.o phttps.o smb.o common.o connstat.o

$(OBJS) https.o gatling.o: gatling.h version.h gatling_features.h

tlsgatling: gatling.c ssl.o $(HTTPS_OBJS) libsocket libiconv libcrypt
	$(CC) -o $@ gatling.c ssl.o $(HTTPS_OBJS) $(CFLAGS) -DSUPPORT_HTTPS $(LDFLAGS) -lssl -lcrypto $(LDLIBS)

tlsgatling_nofail: gatling.c ssl.o $(HTTPS_OBJS) libsocket libiconv libcrypt
	-$(CC) -o tlsgatling gatling.c ssl.o $(HTTPS_OBJS) $(CFLAGS) -DSUPPORT_HTTPS $(LDFLAGS) -lssl -lcrypto $(LDLIBS)

ptlsgatling: gatling.c pssl.o $(PHTTPS_OBJS) libsocket libiconv libcrypt
	$(CC) -o $@ gatling.c pssl.c $(PHTTPS_OBJS) $(CFLAGS) -DSUPPORT_HTTPS -DUSE_POLARSSL $(LDFLAGS) -lpolarssl $(LDLIBS)

ptlsgatling_nofail: gatling.c pssl.o $(PHTTPS_OBJS) libsocket libiconv libcrypt
	-$(CC) -o ptlsgatling gatling.c pssl.c $(PHTTPS_OBJS) $(CFLAGS) -DSUPPORT_HTTPS -DUSE_POLARSSL $(LDFLAGS) -lpolarssl $(LDLIBS)

gatling: gatling.o $(OBJS) md5lib
	$(CC) $(LDFLAGS) $@.o $(OBJS) -o $@ $(LDLIBS) `cat md5lib`

httpbench: httpbench.o
bindbench: bindbench.o
dl: dl.o
ioerr: ioerr.o
bench: bench.o
getlinks: getlinks.o
rellink: rellink.o
matchiprange: matchiprange.o

cgi: cgi.o

version.h: CHANGES
	(head -n 1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -o $@ -I. $(CFLAGS)

https.o: http.c
	$(CC) -c $< -o $@ -I. $(CFLAGS) -DSUPPORT_HTTPS

phttps.o: http.c
	$(CC) -c $< -o $@ -I. $(CFLAGS) -DSUPPORT_HTTPS -DUSE_POLARSSL

%: %.o
	$(CC) $(LDFLAGS) $@.o -o $@ $(LDLIBS)

hitprofile.o: referrer.c
	$(CC) -c $< -o $@ -I. $(CFLAGS) -DALL

libsocket: trysocket.c
	if $(CC) $(CFLAGS) -o trysocket trysocket.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket >/dev/null 2>&1; then echo "-lsocket"; else \
	if $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket -lnsl >/dev/null 2>&1; then echo "-lsocket -lnsl"; else \
	if $(CC) $(CFLAGS) -o trysocket trysocket.c -lwsock32 >/dev/null 2>&1; then echo "-lwsock32"; \
	fi; fi; fi; fi > libsocket
	rm -f trysocket

libiconv: tryiconv.c
	if $(CC) $(CFLAGS) -o tryiconv tryiconv.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o tryiconv tryiconv.c -liconv >/dev/null 2>&1; then echo "-liconv"; else \
	if $(CC) $(CFLAGS) -o tryiconv tryiconv.c -L/usr/local/lib -liconv >/dev/null 2>&1; then \
	  echo "-L/usr/local/lib -liconv"; \
	fi; fi; fi > libiconv
	rm -f tryiconv

libcrypt: trycrypt.c
	if $(CC) $(CFLAGS) -o trycrypt trycrypt.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o trycrypt trycrypt.c -lcrypt >/dev/null 2>&1; then echo "-lcrypt"; \
	fi; fi > libcrypt
	rm -f trycrypt

md5lib: trymd5.c
	if $(CC) $(CFLAGS) -o trymd5 trymd5.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o trymd5 trymd5.c -lmd >/dev/null 2>&1; then echo "-lmd"; else \
	if $(CC) $(CFLAGS) -o trymd5 trymd5.c -lcrypto >/dev/null 2>&1; then echo "-lcrypto"; \
	fi; fi; fi > md5lib
	rm -f trymd5

havesetresuid.h: trysetresuid.c
	-rm -f $@
	if $(CC) $(CFLAGS) -o tryresuid $^ >/dev/null 2>&1; then echo "#define LIBC_HAS_SETRESUID"; fi > $@
	-rm -f tryresuid

dummy.c:
	touch $@

libsocketkludge.a: libsocket libiconv dummy.o
	ar q $@ dummy.o
	-ranlib $@

LDLIBS+=`cat libsocket libiconv libcrypt`

$(TARGETS): libsocketkludge.a libsocket libiconv libcrypt md5lib

install: gatling dl getlinks
	install -d $(DESTDIR)$(BINDIR) $(man1dir)
	install $^ $(DESTDIR)$(BINDIR)
	if test -f tlsgatling; then install tlsgatling $(DESTDIR)$(BINDIR); fi
	install -m 644 gatling.1 bench.1 $(DESTDIR)$(man1dir)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/gatling $(DESTDIR)$(BINDIR)/tlsgatling $(DESTDIR)$(man1dir)/gatling.1 $(DESTDIR)$(man1dir)/bench.1

clean:
	rm -f $(ALLTARGETS) *.o version.h core *.core libsocket libsocketkludge.a dummy.c libiconv libcrypt havesetresuid.h md5lib havealloca.h tlsgatling ptlsgatling

VERSION=gatling-$(shell head -n 1 CHANGES|sed 's/://')
CURNAME=$(notdir $(shell pwd))

rename:
	if test $(CURNAME) != $(VERSION); then cd .. && mv $(CURNAME) $(VERSION); fi

tar: clean rename
	rm -f dep libdep
	cd ..; tar cvvf $(VERSION).tar.bz2 --use=bzip2 --exclude CVS --exclude default $(VERSION)

cert: server.pem

rand.dat:
	-dd if=/dev/random of=rand.dat bs=1024 count=1

cakey.key: rand.dat
	openssl genrsa -out cakey.key -rand rand.dat 2048

cakey.csr: cakey.key
	openssl req -new -key cakey.key -out cakey.csr

cakey.pem: cakey.key cakey.csr
	openssl x509 -req -days 1780 -set_serial 1 -in cakey.csr \
	  -signkey cakey.key -out $@

server.pem: cakey.key cakey.pem
	cat cakey.key cakey.pem > server.pem

windoze:
	$(MAKE) DIET= CROSS=i686-mingw32-

havealloca.h: tryalloca.c
	-rm -f $@
	echo "#include <stdlib.h>" > $@
	if $(DIET) $(CC) $(CFLAGS) -c tryalloca.c -DA >/dev/null 2>&1; then echo "#include <alloca.h>"; fi >> $@
	if $(DIET) $(CC) $(CFLAGS) -c tryalloca.c -DB >/dev/null 2>&1; then echo "#include <malloc.h>"; fi >> $@
	-rm -f tryalloca.o

bench.o bindbench.o common.o dl.o ftp.o gatling.o getlinks.o http.o \
httpbench.o ioerr.o rellink.o smb.o torrent.o: havealloca.h
