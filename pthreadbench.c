#include "buffer.h"
#include "scan.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>

void* mythread(int* pipefd) {
//  __libc_write(2,"thread\n",7);
  write(pipefd[1],".",1);
  sleep(60*5);
  return 0;
}

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  struct timeval a,b;
  unsigned long d;

#ifdef RLIMIT_NPROC
  {
    struct rlimit rl;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
  }
#endif

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"pthreadbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'h':
      buffer_putsflush(buffer_2,
		  "usage: pthreadbench [-h] [-c count]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tfork off n children (default: 1000)\n");
      return 0;
    }
  }

  {
    unsigned long i;
    int pfd[2];
    char buf[100];
    pthread_t *p=malloc(count*sizeof(pthread_t));
    if (!p) {
      buffer_puts(buffer_2,"out of memory!\n");
      exit(1);
    }
    if (pipe(pfd)==-1) {
      buffer_puts(buffer_2,"pipe failed: ");
      buffer_puterror(buffer_2);
      buffer_putnlflush(buffer_2);
    }
    for (i=0; i<count; ++i) {
      int r;
      gettimeofday(&a,0);
      switch ((r=pthread_create(p+i,0,(void*(*)(void*))mythread,pfd))) {
      case 0: /* ok */
	break;
      default:
	buffer_puts(buffer_2,"could not create thread: ");
	buffer_puterror(buffer_2);
	buffer_putsflush(buffer_2,".\n");
	exit(1);
      }
      if (read(pfd[0],buf,1)!=1) {
	buffer_putsflush(buffer_2,"thread did not write into pipe?!\n");
	exit(1);
      }
      gettimeofday(&b,0);
      d=(b.tv_sec-a.tv_sec)*1000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_putulong(buffer_1,d);
      buffer_puts(buffer_1,"\n");
    }
    buffer_flush(buffer_1);
  }

  return 0;
}
