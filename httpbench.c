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
  buffer_flush(buffer_1);
  buffer_puts(buffer_2,"httpbench: ");
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

static int readanswer(int s,int measurethroughput) {
  char buf[8192];
  int i,j,body=-1,r;
  unsigned long rest;
  unsigned long done=0;
  struct timeval a,b;
  i=0;
  while ((r=read(s,buf+i,sizeof(buf)-i)) > 0) {
    i+=r;
    for (j=0; j+3<i; ++j) {
      if (buf[j]=='\r' && buf[j+1]=='\n' && buf[j+2]=='\r' && buf[j+3]=='\n') {
	body=j+4;
	break;
      }
    }
    if (body!=-1) {
      if (byte_diff(buf,7,"HTTP/1.")) {
	buffer_putsflush(buffer_2,"invalid HTTP response!\n");
	return -1;
      }
      break;
    }
  }
  if (r==-1) return -1;
  rest=-1;
  for (j=0; j<r; j+=str_chr(buf+j,'\n')) {
    if (byte_equal(buf+j,17,"\nContent-Length: ")) {
      char* c=buf+j+17;
      if (c[scan_ulong(c,&rest)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Content-Length header!\n");
	return -1;
      }
      break;
    }
    ++j;
  }
  if (measurethroughput) {
    gettimeofday(&a,0);
    done=r-body;
  }
  rest-=(r-body);
  while (rest) {
    r=read(s,buf,rest>sizeof(buf)?sizeof(buf):rest);
    if (r<1) {
      if (r==-1)
	carp("read from HTTP socket");
      else {
	buffer_puts(buffer_2,"early HTTP EOF; expected ");
	buffer_putulong(buffer_2,rest);
	buffer_putsflush(buffer_2,"more bytes!\n");
	return -1;
      }
    } else {
      rest-=r;
      if (measurethroughput) {
	unsigned long x=done/1000000;
	unsigned long y;
	done+=r;
	y=done/1000000;
	if (x!=y) {
	  unsigned long d;
	  unsigned long long z;
	  gettimeofday(&b,0);
	  d=(b.tv_sec-a.tv_sec)*1000000;
	  d=d+b.tv_usec-a.tv_usec;
	  buffer_puts(buffer_1,"tput ");
	  z=1000000000ull/d;
	  buffer_putulong(buffer_1,z);
	  buffer_putnlflush(buffer_1);

	  byte_copy(&a,sizeof(a),&b);
	}
      }
    }
  }
  return 0;
}

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  unsigned long interval=10;
  unsigned long sample=5;
  int keepalive=0;
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
    int i;
    int c=getopt(argc,argv,"c:i:s:kb");
    if (c==-1) break;
    switch (c) {
    case 'k':
      keepalive=1;
      break;
    case 'i':
      i=scan_ulong(optarg,&interval);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse interval: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 's':
      i=scan_ulong(optarg,&sample);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse sample size: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'b':
      bindport=10000;
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,
		  "usage: httpbench [-hb] [-c count] [-i interval] [-s sample] url\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\topen n connections total (default: 1000)\n"
		  "\t-i n\tevery n connections, measure the latency (default: 10)\n"
		  "\t-s n\tlatency == average of time to fetch an URL n times (default: 5)\n"
		  "\t-k\tenable HTTP keep-alive\n"
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
	  buffer_puts(buffer_2,"httpbench: warning: network interface ");
	  buffer_puts(buffer_2,host+tmp+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (dns_ip6(&ips,&a)==-1) {
	buffer_puts(buffer_2,"httpbench: could not resolve IP: ");
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
      i+=fmt_str(request+i,"\r\nUser-Agent: httpbench/1.0\r\nConnection: ");
      i+=fmt_str(request+i,keepalive?"keep-alive":"close");
      i+=fmt_str(request+i,"\r\n\r\n");
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
  if (readanswer(s,count==1)==-1) exit(1);
  close(s);
  if (count==1)
    return 0;

  {
    long i;
    long j;
    long err=0;
    int *socks;
    socks=malloc(sizeof(int)*count);
    if (!socks) panic("malloc");
    for (i=j=0; i<count; ++i) {
      struct timeval a,b;
      long d;
      if (j==0) {
	int k,s=0;
	long x=0,y=0;
	for (k=0; k<sample; ++k) {
	  if (!keepalive || !k) {
	    gettimeofday(&a,0);
	    s=make_connection(ip,port,scope_id);
	    if (s==-1)
	      panic("make_connection");
	    gettimeofday(&b,0);
	    d=(b.tv_sec-a.tv_sec)*1000000;
	    d=d+b.tv_usec-a.tv_usec;
	    x+=d;
	  }
	  gettimeofday(&a,0);
	  write(s,request,rlen);
	  if (readanswer(s,0)==-1) {
	    ++err;
	    keepalive=0;
	  }
	  gettimeofday(&b,0);
	  d=(b.tv_sec-a.tv_sec)*1000000;
	  d=d+b.tv_usec-a.tv_usec;
	  y+=d;
	  if (!keepalive) close(s);
	}
	if (keepalive) close(s);
	buffer_puts(buffer_1,"sample ");
	buffer_putulong(buffer_1,x);
	buffer_puts(buffer_1," ");
	buffer_putulong(buffer_1,y/sample);
	buffer_putnlflush(buffer_1);
      }
      ++j; if (j==interval) j=0;

      gettimeofday(&a,0);
      socks[i]=make_connection(ip,port,scope_id);
      if (socks[i]==-1)
	panic("make_connection");
      gettimeofday(&b,0);
      d=(b.tv_sec-a.tv_sec)*1000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_puts(buffer_1,"clat ");
      buffer_putulong(buffer_1,d);
      buffer_putnlflush(buffer_1);
    }
  }
  buffer_flush(buffer_1);
  return 0;
}
