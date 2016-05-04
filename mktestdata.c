#include "buffer.h"
#include "io.h"
#include "fmt.h"
#include "scan.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <sys/stat.h>

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

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"mktestdata: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'h':
      buffer_putsflush(buffer_2,
		  "usage: mktestdata [-h] [-c count]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tcreate n small files (default: 10000)\n");
      return 0;
    }
  }

  {
    unsigned long i,j;
    char buf[4096];
    char filename[256];
    if (mkdir("data",0700)==-1) panic("mkdir");
    for (i=0; i<(count+99)/100; ++i) {
      j=fmt_str(filename,"data/");
      j+=fmt_ulong(filename+j,i);
      filename[j]=0;
      if (mkdir(filename,0700)==-1) panic("mkdir");
    }
    for (i=0; i<count; ++i) {
      int64 fd;
      j=fmt_str(filename,"data/");
      j+=fmt_ulong(filename+j,i/100);
      j+=fmt_str(filename+j,"/");
      j+=fmt_ulong(filename+j,i);
      j+=fmt_str(filename+j,".html");
      filename[j]=0;
      if (!io_createfile(&fd,filename))
	panic("creat");
      j=fmt_str(buf,"<title>Page ");
      j+=fmt_ulong(buf+j,i);
      j+=fmt_str(buf+j,"</title><h1>Page ");
      j+=fmt_ulong(buf+j,i);
      j+=fmt_str(buf+j,"</h1>\nThis is a nice, small and clean web page.<p>\n");
      if (i==count)
	j+=fmt_str(buf+j,"This is the last page.\n");
      else {
	j+=fmt_str(buf+j,"And <a href=../");
	j+=fmt_ulong(buf+j,(i+1)/100);
	j+=fmt_str(buf+j,"/");
	j+=fmt_ulong(buf+j,i+1);
	j+=fmt_str(buf+j,"html>here</a> is the next one.");
      }
      write(fd,buf,j);
      close(fd);
    }
  }
  buffer_flush(buffer_1);
  return 0;
}
