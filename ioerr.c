#include "socket.h"
#include "byte.h"
#include "dns.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "textcode.h"
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <errno.h>
#include "havealloca.h"
#include "ndelay.h"

static void carp(const char* routine) {
  buffer_puts(buffer_2,"ioerr: ");
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

uint16 bindport=0;

static int make_connection(char* ip,uint16 port,uint32 scope_id) {
  int v6=byte_diff(ip,12,V4mappedprefix);
  int s;
  if (v6) {
    s=socket_tcp6();
    if (s==-1)
      panic("socket_tcp6()");
    ndelay_off(s);
    if (bindport) {
      for (;;) {
	int r=socket_bind6_reuse(s,V6any,bindport,0);
	if (++bindport<1024) bindport=1024;
	if (r==0) break;
	if (errno!=EADDRINUSE)
	  panic("socket_bind6");
      }
    }
    if (socket_connect6(s,ip,port,scope_id)==-1) {
      carp("socket_connect6");
      close(s);
      return -1;
    }
  } else {
    s=socket_tcp4();
    if (s==-1)
      panic("socket_tcp4()");
    ndelay_off(s);
    if (bindport) {
      for (;;) {
	int r=socket_bind4_reuse(s,V6any,bindport);
	if (++bindport<1024) bindport=1024;
	if (r==0) break;
	if (errno!=EADDRINUSE)
	  panic("socket_bind4");
      }
    }
    if (socket_connect4(s,ip+12,port)==-1) {
      carp("socket_connect4");
      close(s);
      return -1;
    }
  }
  return s;
}

int main(int argc,char* argv[]) {
  int killself=0;
  char ip[16];
  uint16 port=80;
  uint32 scope_id=0;
  stralloc ips={0};
  int s;
  char* request;
  int rlen;

  signal(SIGPIPE,SIG_IGN);

  if (!geteuid()) {
    struct rlimit rl;
    long l;
#ifdef RLIMIT_NPROC
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
#endif
    for (l=0; l<20000; l+=500) {
      rl.rlim_cur=l; rl.rlim_max=l;
      if (setrlimit(RLIMIT_NOFILE,&rl)==-1) break;
    }
  }

  for (;;) {
    int c=getopt(argc,argv,"kb");
    if (c==-1) break;
    switch (c) {
    case 'k':
      killself=1;
      break;
    case 'b':
      bindport=10000;
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,
		  "usage: ioerr [-hbk] url\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-k\tkill ourselves (as opposed to simply dropping the connection)\n"
		  "\t-b\tbind the sockets ourselves, so the OS doesn't choose the ports\n"
		  "Setting the number of connections to 1 measures the throughput\n"
		  "instead of the latency (give URL to a large file).\n");
      return 0;
    }
  }

  if (!argv[optind]) goto usage;
  if (byte_diff(argv[optind],7,"http://")) goto usage;
  {
    char* host=argv[optind]+7;
    int colon=str_chr(host,':');
    int slash=str_chr(host,'/');
    char* c;
    if (host[0]=='[') {	/* ipv6 IP notation */
      int tmp;
      ++host;
      --colon; --slash;
      tmp=str_chr(host,']');
      if (host[tmp]==']') host[tmp]=0;
      if (host[tmp+1]==':') colon=tmp+1;
      if (colon<tmp+1) colon=tmp+1+str_len(host+tmp+1);
    }
    if (colon<slash) {
      host[colon]=0;
      c=host+colon+1;
      if (c[scan_ushort(c,&port)]!='/') goto usage;
      *c=0;
    }
    host[colon]=0;
    c=host+slash;
    *c=0;
    {
      char* tmp=alloca(str_len(host)+1);
      tmp[fmt_str(tmp,host)]=0;
      host=tmp;
    }
    *c='/';
    {
      int tmp=str_chr(host,'%');
      if (host[tmp]) {
	host[tmp]=0;
	scope_id=socket_getifidx(host+tmp+1);
	if (scope_id==0) {
	  buffer_puts(buffer_2,"ioerr: warning: network interface ");
	  buffer_puts(buffer_2,host+tmp+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (dns_ip6(&ips,&a)==-1) {
	buffer_puts(buffer_2,"ioerr: could not resolve IP: ");
	buffer_puts(buffer_2,host);
	buffer_putnlflush(buffer_2);
	return 1;
      }
    }

    request=malloc(300+str_len(host)+str_len(c)*3);
    if (!request) panic("malloc");
    {
      int i;
      i=fmt_str(request,"GET ");
      i+=fmt_urlencoded(request+i,c,str_len(c));
      i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
      i+=fmt_str(request+i,host);
      i+=fmt_str(request+i,":");
      i+=fmt_ulong(request+i,port);
      i+=fmt_str(request+i,"\r\nUser-Agent: ioerr/1.0\r\nConnection: close\r\n\r\n");
      rlen=i; request[rlen]=0;
    }

  }

  {
    int i;
    s=-1;
    for (i=0; i+16<=ips.len; i+=16) {
      char buf[IP6_FMT];
      int v6=byte_diff(ips.s+i,12,V4mappedprefix);
      buffer_puts(buffer_1,"connecting to ");
      buffer_put(buffer_1,buf,
		 v6?
		 fmt_ip6(buf,ips.s+i):
		 fmt_ip4(buf,ips.s+i+12));
      buffer_puts(buffer_1," port ");
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
      s=make_connection(ips.s+i,port,scope_id);
      if (s!=-1) {
	byte_copy(ip,16,ips.s+i);
	break;
      }
    }
    if (s==-1)
      return 1;
  }
  if (write(s,request,rlen)!=rlen) panic("write");

  if (killself)
    kill(getpid(),SIGKILL);
  else
    close(s);
  return 0;
}
