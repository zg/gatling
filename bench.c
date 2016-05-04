#include <io.h>
#include <byte.h>
#include <str.h>
#include <fmt.h>
#include <scan.h>
#include <socket.h>
#include <errmsg.h>
#include <dns.h>
#include <ip6.h>
#include <textcode.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <buffer.h>
#include <fcntl.h>
#include <string.h>
#include "havealloca.h"

void usage() {
  die(0,"usage: bench [-n requests] [-c concurrency] [-t timeout] [-k] [-K count]\n"
        "       [-C cookie-file] ([http://]host[:port]/uri|@host:port)");
}

unsigned long r[10];
unsigned long kaputt;

static int make_connection(char* ip,uint16 port,uint32 scope_id,int s) {
  int v6=byte_diff(ip,12,V4mappedprefix);
  if (v6) {
    if (s==-1) {
      s=socket_tcp6();
      if (s==-1) return -1;
    }
    if (socket_connect6(s,ip,port,scope_id)==-1) {
      if (errno==EAGAIN || errno==EINPROGRESS || errno==EISCONN)
	return s;
      ++kaputt;
      if (errno!=ECONNREFUSED && errno!=ECONNRESET)
	carpsys("socket_connect6");
      close(s);
      return -1;
    }
  } else {
    if (s==-1) {
      s=socket_tcp4();
      if (s==-1) return -1;
    }
    if (socket_connect4(s,ip+12,port)==-1) {
      if (errno==EAGAIN || errno==EINPROGRESS || errno==EISCONN)
	return s;
      ++kaputt;
      if (errno!=ECONNREFUSED && errno!=ECONNRESET)
	carpsys("socket_connect6");
      close(s);
      return -1;
    }
  }
  return s;
}

buffer* cookies;

void cookiefile(const char* s) {
  static buffer cookiebuffer;
  static char cookiebuf[8192];
  int fd;
  if (!s) {
    lseek(cookiebuffer.fd,0,SEEK_SET);
    buffer_init(&cookiebuffer,read,cookiebuffer.fd,cookiebuf,sizeof cookiebuf);
  } else {
    fd=open(s,O_RDONLY);
    if (fd==-1) die(1,"could not open cookie file \"",s,"\"!");
    if (cookiebuffer.fd!=0) close(cookiebuffer.fd);
    buffer_init(&cookiebuffer,read,fd,cookiebuf,sizeof cookiebuf);
    cookies=&cookiebuffer;
  }
}

int nextcookie(char* dest,unsigned long destlen) {
  int len;
  if (!cookies) return -1;
  if ((len=buffer_getline(cookies,dest,destlen))) {
    if (dest[len]!='\n')
      die(0,"line too long: ",dest);
    dest[len]=0;
  } else {
    cookiefile(0);
    if ((len=buffer_getline(cookies,dest,destlen))) {
      if (dest[len]!='\n')
	die(0,"line too long: ",dest);
      dest[len]=0;
    } else
      return -1;
  }
  return len;
}

int main(int argc,char* argv[]) {
  char server[1024];
  int* fds;
  int* avail;
  int* keepleft;
  long long* expected;
  unsigned long n=10000;	/* requests */
  unsigned long c=10;		/* concurrency */
  unsigned long t=0;		/* time limit in seconds */
  unsigned long k=0;		/* keep-alive */
  unsigned long K=1;		/* keep-alive counter */
  int report=0;
  unsigned long long errors=0;
  unsigned long long bytes=0;
  int v=0;
  unsigned long i,done;
  uint16 port=80;
  uint32 scope_id=0;
  stralloc ips={0};
  char* request,* krequest;
  unsigned long rlen, krlen;
  tai6464 first,now,next,last;
  enum { SAME, REPLAY } mode;
  char* hostname;

  server[0]=0;

  errmsg_iam("bench");
#ifndef __MINGW32__
  signal(SIGPIPE,SIG_IGN);
#endif

  for (;;) {
    int i;
    int ch=getopt(argc,argv,"n:c:t:kvK:C:r");
    if (ch==-1) break;
    switch (ch) {
    case 'r':
      report=1;
      break;
    case 'n':
      i=scan_ulong(optarg,&n);
      if (i==0) die(1,"could not parse -n argument \"",optarg,"\".\n");
      break;
    case 'c':
      i=scan_ulong(optarg,&c);
      if (i==0) die(1,"could not parse -c argument \"",optarg,"\".\n");
      break;
    case 't':
      i=scan_ulong(optarg,&t);
      if (i==0) die(1,"could not parse -t argument \"",optarg,"\".\n");
      break;
    case 'k':
      k=1;
      break;
    case 'K':
      i=scan_ulong(optarg,&K);
      break;
    case 'v':
      v=1;
      break;
    case 'C':
      cookiefile(optarg);
      break;
    case '?':
      break;
    default:
      usage();
    }
  }
  if (n<1 || c<1 || !argv[optind]) usage();

  if (argv[optind][0]=='@') {
    mode=REPLAY;
    char* host;
    n=(unsigned long)-1;
    host=argv[optind]+1;
    {
      int tmp;
      tmp=str_chr(host,'/');
      if (host[tmp]) {
	host[tmp]=0;
	if (!scan_ushort(host+tmp+1,&port)) usage();
      }
      tmp=str_chr(host,'%');
      if (host[tmp]) {
	host[tmp]=0;
	scope_id=socket_getifidx(host+tmp+1);
	if (scope_id==0)
	  carp("warning: network interface \"",host+tmp+1,"\" not found.");
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (dns_ip6(&ips,&a)==-1)
	die(1,"could not find IP for \"",host,"\"!");
    }
    hostname=host;
    request=krequest=0;
    rlen=krlen=0;
  } else {
    char* host=argv[optind];
    int colon;
    int slash;
    char* c;
    mode=SAME;
    if (byte_equal(host,7,"http://")) host+=7;
    colon=str_chr(host,':');
    slash=str_chr(host,'/');
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
      if (c[scan_ushort(c,&port)]!='/') usage();
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
	if (scope_id==0)
	  carp("warning: network interface \"",host+tmp+1,"\" not found.");
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (dns_ip6(&ips,&a)==-1)
	die(1,"could not find IP for \"",host,"\"!");
    }

    request=alloca(1300+str_len(host)+3*str_len(c));
    krequest=alloca(1300+str_len(host)+3*str_len(c));
    {
      int i,j;
      i=fmt_str(request,"GET ");
      i+=fmt_urlencoded(request+i,c,str_len(c));
      i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
      i+=fmt_str(request+i,host);
      i+=fmt_str(request+i,":");
      i+=fmt_ulong(request+i,port);
      i+=fmt_str(request+i,"\r\nUser-Agent: bench/1.0\r\nConnection: ");
      j=i;
      i+=fmt_str(request+i,"close\r\n\r\n");
      rlen=i; request[rlen]=0;
      byte_copy(krequest,rlen,request);
      i=j+fmt_str(krequest+j,"keep-alive\r\n\r\n");
      krlen=i; krequest[krlen]=0;
    }

    hostname=host;

  }

  fds=alloca(c*sizeof(*fds));
  avail=alloca(c*sizeof(*avail));
  expected=alloca(c*sizeof(*expected));
  keepleft=alloca(c*sizeof(*keepleft));
  last.sec.x=23;
  if (!k) K=1;
  for (i=0; i<c; ++i) { fds[i]=-1; avail[i]=1; keepleft[i]=K; }

  taia_now(&first);

  for (done=0; done<n; ) {

    if (t) {
      /* calculate timeout */
      taia_now(&now);
      if (now.sec.x != last.sec.x) {
	byte_copy(&last,sizeof(now),&now);
	byte_copy(&next,sizeof(now),&now);
	next.sec.x += t;
	while ((i=io_timeouted())!=-1) {
	  unsigned long j;
	  char numbuf[FMT_ULONG];
	  numbuf[fmt_ulong(numbuf,i)]=0;
	  carp("timeout on fd ",numbuf,"!");
	  j=(unsigned long)io_getcookie(i);
	  io_close(i);
	  avail[j]=1;
	  fds[j]=-1;
	}
      }
    }

    /* first, fill available connections */
    for (i=0; i<c; ++i)
      if (avail[i]==1 && fds[i]==-1) {
	fds[i]=make_connection(ips.s,port,scope_id,-1);
	if (fds[i]==-1) diesys(1,"socket/connect");
	avail[i]=2;
	if (io_fd_canwrite(fds[i])==0) diesys(1,"io_fd");
	io_setcookie(fds[i],(void*)i);
//	io_wantread(fds[i]);
	io_wantwrite(fds[i]);
      }

    if (t)
      io_waituntil(next);
    else
      io_wait();

    /* second, see if we can write on a connection */
    while ((i=io_canwrite())!=-1) {
      int j;
      j=(unsigned long)io_getcookie(i);
      if (avail[j]==2) {
	if (make_connection(ips.s,port,scope_id,i)==-1) {
	  ++errors;
	  if (v) write(1,"!",1);
	  io_close(i);
	  avail[j]=1;
	  fds[j]=-1;
	  continue;
	}
      }
      {
	char* towrite;
	int writelen;
	if (mode==REPLAY) {
	  static long lines;
	  char line[1024];
	  char req[2048];
	  int len;
	  int i;
	  char* c;
	  char* host;
	  int hlen;
	  if ((len=buffer_getline(buffer_0,line,sizeof(line)))) {
	    ++lines;
	    if (line[len]!='\n')
	      die(0,"line too long: ",line);
	    line[len]=0;
	    c=line;
	    if (str_start(line,"http://")) c+=7;
	    if (c[0]=='/') {
	      host=hostname;
	      hlen=strlen(hostname);
	    } else {
	      host=c;
	      c+=(hlen=str_chr(c,'/'));
	    }
	    if (!*c)
	      c="/";

	    i=fmt_str(req,"GET ");
	    i+=fmt_urlencoded(req+i,c,str_len(c));
	    i+=fmt_str(req+i," HTTP/1.0\r\nHost: ");
	    byte_copy(req+i,hlen,host); i+=hlen;
	    i+=fmt_str(req+i,":");
	    i+=fmt_ulong(req+i,port);
	    if (cookies) {
	      int j;
	      i+=fmt_str(req+i,"\r\n");
	      j=nextcookie(req+i,sizeof(req)-i-100);
	      if (j!=-1) i+=j; else i-=2;
	    }
	    i+=fmt_str(req+i,"\r\nUser-Agent: bench/1.0\r\nConnection: ");
	    i+=fmt_str(req+i,keepleft[j]>1?"keep-alive\r\n\r\n":"close\r\n\r\n");
	    req[i]=0;
	    towrite=req;
	    writelen=i;
	  } else {
	    n=done;
	    break;
	  }
	} else {
	  if (keepleft[j]>1) {
	    towrite=krequest;
	    writelen=krlen;
	  } else {
	    towrite=request;
	    writelen=rlen;
	  }
	  if (cookies) {
	    int i=writelen-2;
	    int j=nextcookie(towrite+i,900);
	    if (j!=-1) i+=j;
	    i+=fmt_str(towrite+i,"\r\n\r\n");
	    writelen=i;
	  }
	}
	if (io_trywrite(i,towrite,writelen)!=writelen) {
	  ++errors;
	  if (v) write(1,"-",1);
	  io_close(i);
	  avail[j]=1;
	  fds[j]=-1;
	  continue;
	}
      }
      io_dontwantwrite(i);
      io_wantread(i);
      expected[j]=-1;
      if (v) write(1,"+",1);
    }

    /* third, see if we got served */
    while ((i=io_canread())!=-1) {
      char buf[8193];
      int l,j;
      buf[8192]=0;
      j=(unsigned long)io_getcookie(i);
      if ((l=io_tryread(i,buf,sizeof(buf)-1))<=0) {
	if (l==0) { /* EOF.  Mhh. */
	  if (expected[j]>0) {
	    ++errors;
	    if (v) write(1,"-",1);	/* so whine a little */
	  }
	  if (expected[j]==-2)
	    ++done;
	  io_close(i);
	  avail[j]=1;
	  fds[j]=-1;
	} else if (l==-3) {
	  ++errors;
	  if (v) write(1,"!",1);
//	  carpsys("read");
	}
      } else {
	bytes+=l;
	if (v) write(1,".",1);
	/* read something */
	if (expected[j]==-1) {	/* expecting header */
	  int k;
	  /* OK, so this is a very simplistic header parser.  No
	   * buffering.  At all.  We expect the Content-Length header to
	   * come in one piece. */
	  if (l>10 && !memcmp(buf,"HTTP/1.",7)) {
	    if (buf[9]>='0' && buf[9]<='9')
	      r[buf[9]-'0']++;
	    else {
	      write(1,buf,15); write(1,"\n",1);
	    }
	  }
	  expected[j]=-2;
	  if (!done) {
	    for (k=0; k<l; ++k)
	      if (str_start(buf+k,"\nServer: ")) {
		char* tmp=buf+(k+=9);
		for (; k<l; ++k)
		  if (buf[k]=='\r') break;
		k=buf+k-tmp;
		if (k>sizeof(server)-1) k=sizeof(server)-1;
		byte_copy(server,k,tmp);
		server[k]=0;
		break;
	      }
	  }
	  for (k=0; k<l; ++k) {
	    if (str_start(buf+k,"\nContent-Length: ")) {
	      k+=17;
	      if (buf[k+scan_ulonglong(buf+k,(unsigned long long*)expected+j)] != '\r')
		die(1,"parse error in HTTP header!");
	    } else if (str_start(buf+k,"\r\n\r\n"))
	      break;
	  }
	  if (expected[j]>0) {
	    if (l-(k+4)>expected[j])
	      expected[j]=0;
	    else
	      expected[j]-=l-(k+4);
	  }
	} else if (expected[j]==-2) {
	  /* no content-length header, eat everything until EOF */
	} else {
	  if (l>expected[j]) {
	    carp("got more than expected!");
	    expected[j]=0;
	  } else
	    expected[j]-=l;
	}
	if (expected[j]==0) {
	  ++done;	/* one down! */
	  avail[j]=1;
//	  printf("fd %d: keepleft[%d]=%d\n",i,j,keepleft[j]);
	  if (keepleft[j]>1) {
	    --keepleft[j];
	    io_dontwantread(i);
	    io_wantwrite(i);
	    expected[j]=0;
	  } else {
	    keepleft[j]=K;
	    io_close(i);
	    fds[j]=-1;
	  }
	}
      }
    }
  }

  taia_now(&now);
  taia_sub(&now,&now,&first);
  {
    char a[FMT_ULONG];
    char b[FMT_ULONG];
    char C[FMT_ULONG];
    char d[FMT_ULONG];
    char e[FMT_ULONG];
    char f[FMT_ULONG];
    char g[FMT_ULONG];
    char h[FMT_ULONG];
    char i[FMT_ULONG];
    char j[FMT_ULONG];
    unsigned long long l;
    a[fmt_ulong(a,now.sec.x)]=0;
    b[fmt_ulong0(b,(now.nano%1000000000)/100000,4)]=0;
    C[fmt_ulong(C,done)]=0;
    d[fmt_ulonglong(d,errors)]=0;
    e[fmt_ulonglong(e,bytes)]=0;

    /* let's say bytes = 10 MB, time = 1.2 sec.
    * then we want 10*1024*1024/1.2 == 8 MB/sec */
    l = (now.sec.x * 1024) + now.nano/976562;
    if (l) {
      int i;
      l=bytes/l;
      if (report)
	i=fmt_ulong(f,l);
      else {
	i=fmt_humank(f,l*1024);
	i+=fmt_str(f+i,"iB/sec");
      }
      f[i]=0;
    } else
      strcpy(f,"n/a");

    l = (now.sec.x * 1000) + now.nano/1000000;
    l = l ? (done*10000) / l : 0;
    g[fmt_ulong(g,l/10)]=0;
    h[fmt_ulong(h,c)]=0;
    i[fmt_ulong(i,K)]=0;
    j[fmt_ulong(j,kaputt)]=0;

    if (server[0]) msg("Server: ",server);
    if (report) {
      errmsg_iam(0);
      msg("req\terr\tconcur\tkeep\tkbytes\tsec\ttput\tr/s\treset");
      msg(C,"\t",d,"\t",h,"\t",i,"\t",e,"\t",a,".",b,"\t",f,"\t",g,"\t",j);
    } else {
      msg(C," requests, ",d," errors.");
      msg(e," bytes in ",a,".",b," seconds.");
      msg("Throughput: ",f);
      msg("Requests per second: ",g);
      msg("Connection refused/reset by peer: ",j);
    }

    {
      int i;
      for (i=0; i<9; ++i) {
	a[fmt_ulong(a,r[i])]=0;
	b[0]=i+'0'; b[1]=0;
	msg(b,"xx: ",a);
      }
    }
  }

  return 0;
}
