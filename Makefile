prefix=/usr/local
BINDIR=${prefix}/bin
MANDIR=${prefix}/man
man1dir=$(MANDIR)/man1

TARGET=gatling httpbench dl bindbench mmapbench forkbench pthreadbench \
mktestdata manymapbench ioerr bench tlsgatling forksbench cgi getlinks \
acc hcat referrer hitprofile matchiprange

all: $(TARGET)

CC=gcc
CFLAGS=-pipe -Wall -O -I../libowfat/ -I/usr/local/include
LDFLAGS=-s -L../libowfat/ -lowfat

OBJS=mime.o ftp.o http.o smb.o common.o connstat.o
HTTPS_OBJS=mime.o ftp.c https.o smb.c common.c connstat.o

$(OBJS) https.o gatling.o: gatling.h version.h gatling_features.h

gatling: gatling.o $(OBJS) libsocket libiconv libcrypt md5lib
	$(CC) -o $@ gatling.o $(OBJS) $(LDFLAGS) `cat libsocket libiconv libcrypt md5lib`

httpbench: httpbench.o libsocket
	$(CC) -o $@ httpbench.o $(LDFLAGS) `cat libsocket`

dl: dl.o libsocket
	$(CC) -o $@ dl.o $(LDFLAGS) `cat libsocket`

bindbench: bindbench.o libsocket
	$(CC) -o $@ bindbench.o $(LDFLAGS) `cat libsocket`

mmapbench: mmapbench.o
	$(CC) -o $@ mmapbench.o $(LDFLAGS)

forkbench: forkbench.o
	$(CC) -o $@ forkbench.o $(LDFLAGS)

forksbench: forkbench.o
	$(CC) -static -o $@ forkbench.o $(LDFLAGS)

pthreadbench: pthreadbench.o
	$(CC) -o $@ pthreadbench.o $(LDFLAGS) -lpthread

mktestdata: mktestdata.o
	$(CC) -o $@ mktestdata.o $(LDFLAGS)

manymapbench: manymapbench.o
	$(CC) -o $@ manymapbench.o $(LDFLAGS)

bench: bench.o
	$(CC) -o $@ bench.o $(LDFLAGS)

ioerr: ioerr.o libsocket
	$(CC) -o $@ ioerr.o $(LDFLAGS) `cat libsocket`

acc: acc.o
	$(CC) -o $@ acc.o $(LDFLAGS)

cgi: cgi.o
	$(CC) -o $@ cgi.o $(LDFLAGS)

getlinks: getlinks.o
	$(CC) -o $@ getlinks.o $(LDFLAGS)

matchiprange: matchiprange.o
	$(CC) -o $@ matchiprange.o $(LDFLAGS)

gatling.o: version.h gatling.h havesetresuid.h
tlsgatling ptlsgatling: havesetresuid.h libsocket libiconv libcrypt

version.h: CHANGES
	(head -n 1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -I. $(CFLAGS)

https.o: http.c
	$(CC) -c http.c -o $@ -I. $(CFLAGS) -DSUPPORT_HTTPS

hitprofile.o: referrer.c
	$(CC) -c referrer.c -o $@ -I. $(CFLAGS) -DALL

hitprofile: hitprofile.o

tlsgatling: gatling.c ssl.o version.h gatling.h libsocket libiconv libcrypt $(HTTPS_OBJS)
	-$(CC) -o $@ $(CFLAGS) gatling.c ssl.o $(HTTPS_OBJS) -DSUPPORT_HTTPS $(LDFLAGS) -lssl -lcrypto $(LDLIBS) `cat libsocket libiconv libcrypt`

libsocket: trysocket.c
	if $(CC) $(CFLAGS) -o trysocket trysocket.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket >/dev/null 2>&1; then echo "-lsocket"; else \
	if $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket -lnsl >/dev/null 2>&1; then echo "-lsocket -lnsl"; \
	fi; fi; fi > libsocket
	rm -f trysocket

libiconv: tryiconv.c
	if $(CC) $(CFLAGS) -o tryiconv tryiconv.c >/dev/null 2>&1; then echo ""; else \
	if $(CC) $(CFLAGS) -o tryiconv tryiconv.c -liconv >/dev/null 2>&1; then echo "-liconv"; else \
	if $(CC) $(CFLAGS) -o tryiconv -I/usr/local/include tryiconv.c -L/usr/local/lib -liconv >/dev/null 2>&1; then \
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

install: gatling dl getlinks
	install -d $(BINDIR) $(man1dir)
	install $^ $(BINDIR)
	test -f tlsgatling && install tlsgatling $(BINDIR)
	install -m 644 gatling.1 bench.1 $(man1dir)

uninstall:
	rm -f $(BINDIR)/gatling $(BINDIR)/tlsgatling $(man1dir)/gatling.1 $(man1dir)/bench.1

clean:
	rm -f $(TARGET) *.o version.h core *.core libsocket libsocketkludge.a dummy.c libiconv libcrypt havesetresuid.h md5lib

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

havealloca.h: tryalloca.c
	-rm -f $@
	echo "#include <stdlib.h>" > $@
	if $(DIET) $(CC) $(CFLAGS) -c tryalloca.c -DA >/dev/null 2>&1; then echo "#include <alloca.h>"; fi >> $@
	if $(DIET) $(CC) $(CFLAGS) -c tryalloca.c -DB >/dev/null 2>&1; then echo "#include <malloc.h>"; fi >> $@
	-rm -f tryalloca.o

bench.o bindbench.o common.o dl.o ftp.o gatling.o getlinks.o http.o \
httpbench.o ioerr.o rellink.o smb.o torrent.o: havealloca.h
