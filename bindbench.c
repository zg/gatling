#include "socket.h"
#include "byte.h"
#include "dns.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include "havealloca.h"

#ifdef __i386__
#define rdtscl(low) \
     __asm__ __volatile__ ("rdtsc" : "=A" (low))
#endif

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  int v6;

  v6=0;

  {
    struct rlimit rl;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NOFILE,&rl);
#ifdef RLIMIT_NPROC
    setrlimit(RLIMIT_NPROC,&rl);
#endif
  }

  for (;;) {
    int i;
    int c=getopt(argc,argv,"h6c:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case '6':
      v6=1;
      break;
    case 'h':
      buffer_putsflush(buffer_2,
		  "usage: bindbench [-h] [-6] [-c count]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tbind n sockets to port 0 (default: 1000)\n"
		  "\t-6\tbind IPv6 sockets instead of IPV4\n");
      return 0;
    }
  }


  {
    int i,r;
    char ip[16];
    int port;
#ifdef __i386__
    unsigned long long a,b,c;
#else
    struct timeval a,b,c;
    unsigned long d;
#endif
    int *socks=alloca(count*sizeof(int));
    port=0; byte_zero(ip,16);
    for (i=0; i<count; ++i) {
#ifdef __i386__
      rdtscl(a);
#else
      gettimeofday(&a,0);
#endif
      socks[i]=v6?socket_tcp6():socket_tcp4();
#ifdef __i386__
      rdtscl(b);
#else
      gettimeofday(&b,0);
#endif
      if (socks[i]==-1) {
	buffer_puts(buffer_2,"socket() failed: ");
	buffer_puterror(buffer_2);
	buffer_putnlflush(buffer_2);
	exit(1);
      }
      if (v6)
	r=socket_bind6(socks[i],ip,port,0);
      else
	r=socket_bind4(socks[i],ip,port);
      if (r==-1) {
	buffer_puts(buffer_2,"bind() failed: ");
	buffer_puterror(buffer_2);
	buffer_putnlflush(buffer_2);
	exit(1);
      }
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
      if (i>50) {
	close(socks[10]);
	socks[10]=v6?socket_tcp6():socket_tcp4();
      }
    }
  }

  buffer_flush(buffer_1);
  return 0;
}
