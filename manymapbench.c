#include "byte.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "io.h"
#include "fmt.h"
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

static void carp(const char* routine) {
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

int main(int argc,char* argv[]) {
  unsigned long count=10000;
#ifdef __i386__
  unsigned long long a,b,c,d;
#else
  struct timeval a,b,c,d;
#endif
  struct entry {
    int fd;
    char* m;
    unsigned long a,b,c;
  } *x;

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"manymapbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case '?':
      buffer_putsflush(buffer_2,
		  "usage: manymapbench [-h] [-c count]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tmmap n files (default: 10000)\n");
      return 0;
    }
  }

  {
    struct rlimit rl;
    rl.rlim_cur=count+5; rl.rlim_max=count+5;
    setrlimit(RLIMIT_NOFILE,&rl);
  }

  x=malloc(count*sizeof(struct entry));

  {
    volatile char ch;
    int64 fd;
    unsigned long i,j;
    char filename[100];
    for (i=0; i<count; ++i) {
      j=fmt_str(filename,"data/");
      j+=fmt_ulong(filename+j,i/100);
      j+=fmt_str(filename+j,"/");
      j+=fmt_ulong(filename+j,i);
      j+=fmt_str(filename+j,".html");
      filename[j]=0;
#ifdef __i386__
      rdtscl(a);
#else
      gettimeofday(&a,0);
#endif
      if (!io_readfile(&fd,filename)) panic("open");
#ifdef __i386__
      rdtscl(b);
#else
      gettimeofday(&b,0);
#endif
      x[i].fd=fd;
      x[i].m=mmap(0,4096,PROT_READ,MAP_SHARED,fd,0);
      if (x[i].m==MAP_FAILED) panic("mmap");
#ifdef __i386__
      rdtscl(c);
#else
      gettimeofday(&c,0);
#endif
      ch=*x[i].m;
#ifdef __i386__
      rdtscl(d);
#else
      gettimeofday(&d,0);
#endif
#ifdef __i386__
      x[i].a=b-a;
      x[i].b=c-b;
      x[i].c=d-c;
#else
      x[i].a=(b.tv_sec-a.tv_sec)*1000000+b.tv_usec-a.tv_usec;
      x[i].b=(c.tv_sec-b.tv_sec)*1000000+c.tv_usec-b.tv_usec;
      x[i].c=(d.tv_sec-c.tv_sec)*1000000+d.tv_usec-c.tv_usec;
#endif
    }

    for (i=0; i<count; ++i) {
      buffer_putulong(buffer_1,x[i].a);
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,x[i].b);
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,x[i].c);
      buffer_puts(buffer_1,"\n");
    }
  }

  buffer_flush(buffer_1);
  return 0;
}
