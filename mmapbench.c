#include "byte.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "io.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>

#ifdef __i386__
#define rdtscl(low) \
     __asm__ __volatile__ ("rdtsc" : "=A" (low))
#endif

int main(int argc,char* argv[]) {
  unsigned long count=25000;
  int64 fd;
#ifdef __i386__
  unsigned long long a,b,c;
#else
  struct timeval a,b,c;
  unsigned long d;
#endif

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"mmapbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,
		  "usage: mmapbench [-h] [-c count] filename\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tmmap n 4k pages (default: 25000)\n");
      return 0;
    }
  }

  if (!argv[optind]) goto usage;
  if (!io_readfile(&fd,argv[optind])) {
    buffer_puts(buffer_2,"could not open ");
    buffer_puts(buffer_2,argv[optind]);
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    exit(1);
  }

  buffer_puts(buffer_2,"cache priming: reading ");
  buffer_putulong(buffer_2,count*2);
  buffer_puts(buffer_2," pages (");
  buffer_putulong(buffer_2,count*8);
  buffer_putsflush(buffer_2," KB)...\n");
  {
    unsigned long i;
    char* p;
    volatile char c;
    p = mmap(NULL, count*8192, PROT_READ, MAP_SHARED, fd, 0);
    if (p==MAP_FAILED) {
      buffer_puts(buffer_2,"mmap failed: ");
      buffer_puterror(buffer_2);
      buffer_putnlflush(buffer_2);
      return 111;
    }
    for (i=0; i<count; ++i)
      c += p[i*8192];
    munmap(p,count*8192);
  }

  {
    unsigned long i;
    char **p=malloc(count*sizeof(char*));
    if (!p) {
      buffer_puts(buffer_2,"out of memory!\n");
      exit(1);
    }
    for (i=0; i<count; ++i) {
      volatile char ch;
#ifdef __i386__
      rdtscl(a);
#else
      gettimeofday(&a,0);
#endif
      p[i]=mmap(0,4096,PROT_READ,MAP_SHARED,fd,((off_t)i)*8192);
      if (p[i]==MAP_FAILED) {
	buffer_puts(buffer_2,"mmap failed: ");
	buffer_puterror(buffer_2);
	buffer_putnlflush(buffer_2);
	return 111;
      }
#ifdef __i386__
      rdtscl(b);
#else
      gettimeofday(&b,0);
#endif
      ch=*p[i];
#ifdef __i386__
      rdtscl(c);
      buffer_putulong(buffer_1,b-a);
#else
      gettimeofday(&c,0);
      d=(b.tv_sec-a.tv_sec)*1000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_putulong(buffer_1,d);
#endif
      buffer_putspace(buffer_1);
#ifdef __i386__
      buffer_putulong(buffer_1,c-b);
#else
      d=(c.tv_sec-b.tv_sec)*1000000;
      d=d+c.tv_usec-b.tv_usec;
      buffer_putulong(buffer_1,d);
#endif
      buffer_puts(buffer_1,"\n");
    }
  }

  buffer_flush(buffer_1);
  return 0;
}
