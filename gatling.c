#define _GNU_SOURCE
#include "gatling.h"

#include "socket.h"
#include "io.h"
#include "buffer.h"
#include "ip4.h"
#include "ip6.h"
#include "array.h"
#include "case.h"
#include "fmt.h"
#include "iob.h"
#include "str.h"
#include "scan.h"
#include "textcode.h"
#include "uint32.h"
#include "uint16.h"
#include "mmap.h"
#include "rangecheck.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#ifndef __MINGW32__
#include <sys/resource.h>
#include <sys/socket.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <fnmatch.h>
#include <sys/wait.h>
#endif
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include "version.h"
#include <assert.h>
#ifdef SUPPORT_SMB
#include <iconv.h>
#endif
#ifdef SUPPORT_PROXY
#include <regex.h>
#endif
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
// #include <crypt.h>
#include "havealloca.h"
#include "havesetresuid.h"

#if !defined(__OPTIMIZE__) && defined(__linux__)
#include <sys/prctl.h>
#endif

char serverroot[1024];

#ifdef SUPPORT_MULTIPROC
unsigned long instances=1;
#endif
unsigned long timeout_secs=23;
tai6464 now,next;

#ifdef TIMEOUT_DEBUG
void new_io_timeout(int64 d,tai6464 t) {
  struct taia now;
  struct taia diff;
  taia_now(&now);
  taia_sub(&diff,&t,&now);
  buffer_puts(buffer_2,"DEBUG: scheduling timeout for fd #");
  buffer_putlonglong(buffer_2,d);
  buffer_puts(buffer_2," in ");
  buffer_putlonglong(buffer_2,diff.sec.x);
  buffer_putsflush(buffer_2," seconds.\n");
  io_timeout(d,t);
}

int64 new_io_timeouted() {
  int64 x=io_timeouted();
  buffer_puts(buffer_2,"DEBUG: io_timeouted called, returned ");
  buffer_putlonglong(buffer_2,x);
  buffer_putnlflush(buffer_2);
  return x;
}

#define io_timeout new_io_timeout
#define io_timeouted new_io_timeouted
#endif

const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

#ifdef SUPPORT_CGI
int forksock[2];
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__)
#define __broken_itojun_v6__
#endif

int virtual_hosts;
int transproxy;
int directory_index;
int logging;
int nouploads;
int chmoduploads;
#ifdef __MINGW32__
char origdir[PATH_MAX];
#else
int64 origdir;
#endif

#ifdef SUPPORT_SMB
char workgroup[20]="FNORD";
int wglen;
char workgroup_utf16[100];
int wglen16;
#endif

static void carp(const char* routine) {
  buffer_putmflush(buffer_2,routine,": ",strerror(errno),"\n");
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

unsigned long connections;
unsigned long http_connections, https_connections, ftp_connections, smb_connections;
unsigned long cps,cps1;	/* connections per second */
unsigned long rps,rps1;	/* requests per second */
unsigned long eps,eps1;	/* events per second */
unsigned long long tin,tin1;	/* traffic inbound */
unsigned long long tout,tout1;	/* traffic outbound */


#ifdef SUPPORT_THREADED_OPEN
unsigned int threads;
int threadpipe_query[2];
int threadpipe_response[2];

void* worker_thread(void* unused) {
  int src=threadpipe_query[0];
  int dest=threadpipe_response[1];
  (void)unused;
  for (;;) {
    int fd;
    struct http_data* x;
    if (read(src,&fd,sizeof(fd))!=fd) return 0;
    x=io_getcookie(fd);
    if (!x) continue;
    if (fchdir(x->cwd)==-1) continue;
    x->filefd=open(x->name_of_file_to_open,O_RDONLY);
    write(dest,&fd,sizeof(fd));
  }
}

void init_threads(int n) {
  threads=0;
  if (n<=0) return;
  if (threads>0) {
    int i;
    if (pipe(threadpipe_query)==-1 || pipe(threadpipe_response)==-1) return;
    for (i=0; i<n; ++i) {
      pthread_t tmp;
      pthread_create(&tmp,0,worker_thread,0);
      pthread_detach(tmp);
    }
    threads=n;
  }
}
#endif


#if defined(SUPPORT_PROXY) || defined(SUPPORT_CGI)
/* You configure a list of regular expressions, and if a request matches
 * one of them, the request is forwarded to some other IP:port.  You can
 * run another httpd there that can handle CGI, PHP, JSP and whatnot. */
struct cgi_proxy* cgis,* last;

char** _envp;

/* if port==0 then execute the CGI locally */
#endif

#ifdef SUPPORT_CGI
static int add_cgi(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  if (!x) return -1;
  byte_zero(x,sizeof(struct cgi_proxy));
  if (!strcmp(c,"+x"))
    x->file_executable=1;
  else if (regcomp(&x->r,c,REG_EXTENDED)) {
    free(x);
    return -1;
  }
  if (!last)
    cgis=last=x;
  else
    last->next=x; last=x;
  return 0;
}
#endif

void cleanup(int64 fd) {
  struct http_data* h=io_getcookie(fd);
  int buddyfd=-1;
  if (h) {
    buddyfd=h->buddy;

    if (h->t==HTTPREQUEST
#ifdef SUPPORT_FTP
	|| h->t==FTPCONTROL6 || h->t==FTPCONTROL4
#endif
#ifdef SUPPORT_SMB
	|| h->t==SMBREQUEST
#endif
#ifdef SUPPORT_HTTPS
	|| h->t==HTTPSREQUEST || h->t==HTTPSACCEPT || h->t==HTTPSPOST
#endif
	  ) --connections;
    if (h->t==HTTPREQUEST
#ifdef SUPPORT_PROXY
	|| h->t==HTTPPOST
#endif
	) --http_connections;
#ifdef SUPPORT_FTP
    if (h->t==FTPCONTROL4 || h->t==FTPCONTROL6) --ftp_connections;
#endif
#ifdef SUPPORT_SMB
    if (h->t==SMBREQUEST) --smb_connections;
#endif
#ifdef SUPPORT_HTTPS
    if (h->t==HTTPSREQUEST || h->t==HTTPSPOST || h->t==HTTPSACCEPT ||
	h->t==HTTPSACCEPT_CHECK || h->t==HTTPSRESPONSE) --https_connections;
#endif

#if defined(SUPPORT_FTP)
    if (h->t==FTPSLAVE || h->t==FTPACTIVE || h->t==FTPPASSIVE) {
      if (buddyfd!=-1) {
	struct http_data* b=io_getcookie(buddyfd);
	if (b)
	  b->buddy=-1;
      }
      buddyfd=-1;
    }
#endif
    if (h->filefd!=-1) io_close(h->filefd);
    array_reset(&h->r);
    iob_reset(&h->iob);
#if defined(SUPPORT_FTP) || defined(SUPPORT_SMB)
    free(h->ftppath);
#endif
#ifdef SUPPORT_HTTPS
#ifdef USE_OPENSSL
    if (h->ssl) SSL_free(h->ssl);
#endif
#ifdef USE_POLARSSL
    ssl_free(&h->ssl);
#endif
#endif
#ifdef SUPPORT_SMB
    close_all_handles(&h->h);
#endif
    free(h);
  }
  io_close(fd);
  if (buddyfd>=0) {
    h=io_getcookie(buddyfd);
    if (h) h->buddy=-1;
    cleanup(buddyfd);
  }
}

size_t header_complete(struct http_data* r,int64 sock) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
  if (r->t==HTTPREQUEST
#ifdef SUPPORT_PROXY
      || r->t==HTTPPOST
#endif
#ifdef SUPPORT_HTTPS
      || r->t==HTTPSREQUEST || r->t==HTTPSPOST
#endif
     )
  {
    /* first of all, in case someone is bombarding me with crap, detect
     * that early so we can drop the connection */
    if (l>10) {
      tai6464 tarpit;
      for (i=0; i<l; ++i) {
	if (c[i]==' ') goto ok;
	if (c[i]<'A' || c[i]>'Z') break;
      }
      /* detected invalid HTTP request */
      if (logging) {
	char buf[100];
	buffer_puts(buffer_1,"close/not_http_traffic ");
	buffer_putulong(buffer_1,sock);
	buffer_putspace(buffer_1);
	buffer_put(buffer_1,buf,fmt_ip6c(buf,r->peerip));
	buffer_putnlflush(buffer_1);
      }
      io_dontwantread(sock);
      io_dontwantwrite(sock);
      --http_connections;
      changestate(r,PUNISHMENT);
      tarpit=now;
      tarpit.sec.x+=10;
      io_timeout(sock,tarpit);
      return 0;
    }
ok:

    /* Erdgeist nudged me into optimizing this :-)
     * I'd be surprised if this optimization has any measurable
     * advantage, but it sure is impressive */
    for (i=0; i+1<l; i+=2) {
      if (c[i+1]=='\n') {
	if (c[i]=='\n') return i+2;
	else if (c[i]=='\r' && i+3<l && c[i+2]=='\r' && c[i+3]=='\n')
	  return i+4;
	--i;
      } else if (c[i+1]=='\r') {
	if (i+4<l && c[i+2]=='\n' && c[i+3]=='\r' && c[i+4]=='\n')
	  return i+5;
	--i;
      }
    }

#ifdef SUPPORT_SMB
  } else if (r->t==SMBREQUEST) {
    /* SMB */
    /* first four bytes are the NetBIOS session;
     * byte 0: 0 ("session message"),
     * bytes 1-3: message length (big endian) */
    uint32 len;
    if (c[0]!=0) {
//      printf("can't happen error: netbios byte 0 was not 0!?\n");
      return 1;
    }
    len=uint32_read_big(c) & 0x00ffffff;
    if (l>=len+4) return len+4;
#endif
  } else {
    /* FTP */
    for (i=0; i<l; ++i)
      if (c[i]=='\n')
	return i+1;
  }
  return 0;
}

static char oom[]="HTTP/1.0 500 internal error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nout of memory\n";

void httperror_realm(struct http_data* r,const char* title,const char* message,const char* realm,int nobody) {
  char* c;
  if (r->t==HTTPSERVER4 || r->t==HTTPSERVER6 || r->t==HTTPREQUEST
#ifdef SUPPORT_HTTPS
      || r->t==HTTPSSERVER4 || r->t==HTTPSSERVER6
      || r->t==HTTPSREQUEST || r->t==HTTPSRESPONSE
#endif
								) {
    c=r->hdrbuf=(char*)malloc(str_len(message)+str_len(title)+str_len(realm?realm:"")+300);
    if (!c) {
      r->hdrbuf=oom;
      r->hlen=str_len(r->hdrbuf);
      buffer_putsflush(buffer_1,"error_oom\n");
      iob_addbuf(&r->iob,r->hdrbuf,r->hlen);
    } else {
      c+=fmt_str(c,"HTTP/1.0 ");
      c+=fmt_str(c,title);
      c+=fmt_str(c,"\r\nContent-Type: text/html\r\nConnection: ");
      c+=fmt_str(c,r->keepalive?"keep-alive":"close");
      c+=fmt_str(c,"\r\nServer: " RELEASE "\r\nContent-Length: ");
      c+=fmt_ulong(c,str_len(message)+str_len(title)-4+17);
      if (realm) {
	c+=fmt_str(c,"\r\nWWW-Authenticate: Basic realm=\"");
	c+=fmt_str(c,realm);
	c+=fmt_str(c,"\"");
      }
      c+=fmt_str(c,"\r\n\r\n");
      if (!nobody) {
	c+=fmt_str(c,"<title>");
	c+=fmt_str(c,title+4);
	c+=fmt_str(c,"</title>\n");
	c+=fmt_str(c,message);
	c+=fmt_str(c,"\n");
      }
      r->hlen=c - r->hdrbuf;
      iob_addbuf_free(&r->iob,r->hdrbuf,r->hlen);
    }
  } else {
    /* FTP */
    c=r->hdrbuf=(char*)malloc(str_len(title)+3);
    c+=fmt_str(c,title);
    c+=fmt_str(c,"\r\n");
    r->hlen=c-r->hdrbuf;
    iob_addbuf_free(&r->iob,r->hdrbuf,r->hlen);
  }
}

void httperror(struct http_data* r,const char* title,const char* message,int nobody) {
  httperror_realm(r,title,message,0,nobody);
}

unsigned int fmt_2digits(char* dest,int i) {
  dest[0]=(i/10)+'0';
  dest[1]=(i%10)+'0';
  return 2;
}



#if 0
 _     _   _
| |__ | |_| |_ _ __
| '_ \| __| __| '_ \
| | | | |_| |_| |_) |
|_| |_|\__|\__| .__/
              |_|
#endif

const char* mimetypesfilename;

char* base;

int sort_name_a(de* x,de* y) { return (str_diff(base+x->name,base+y->name)); }
int sort_name_d(de* x,de* y) { return (str_diff(base+y->name,base+x->name)); }
int sort_mtime_a(de* x,de* y) { return x->ss.st_mtime-y->ss.st_mtime; }
int sort_mtime_d(de* x,de* y) { return y->ss.st_mtime-x->ss.st_mtime; }
int sort_size_a(de* x,de* y) { return x->ss.st_size-y->ss.st_size; }
int sort_size_d(de* x,de* y) { return y->ss.st_size-x->ss.st_size; }



#ifndef __MINGW32__
static uid_t __uid;
static gid_t __gid;
static int do_switch_uid;

static int prepare_switch_uid(const char* new_uid) {
  uid_t u=0;
  gid_t g=0;
  if (new_uid) {
    if (new_uid[0]>='0' && new_uid[0]<='9') {
      unsigned long l;
      const char *c=new_uid+scan_ulong(new_uid,&l);
      if (*c && *c!=':' && *c!='.') return -1;
      if ((u=l)!=l) return -1; /* catch overflow */
      if (*c) {
	++c;
	c=c+scan_ulong(c,&l);
	if ((g=l)!=l) return -1; /* catch overflow */
	if (*c) return -1;
      }
    } else {
      struct passwd *p=getpwnam(new_uid);
      if (!p) return -1;
      u=p->pw_uid;
      g=p->pw_gid;
    }
    __uid=u;
    __gid=g;
    do_switch_uid=1;
  }
  return 0;
}

int switch_uid() {
  if (!do_switch_uid) return 0;
#ifdef LIBC_HAS_SETRESUID
  if (setresgid(__gid,__gid,__gid) ||
      setgroups(1,&__gid) ||
      setresuid(__uid,__uid,__uid))
#else
  if (setgid(__gid) ||
      setgroups(1,&__gid) ||
      setuid(__uid))
#endif
  {
    /* if dropping privileges failed with EPERM, we are already running
     * with reduced privileges.  Don't make a fuss about it then. */
    if (errno==EPERM) return 0;
    return -1;
  }
  return 0;
}
#endif

static volatile int fini;

void sighandler(int sig) {
  fini=(sig==SIGINT?1:2);	/* 2 for SIGHUP */
}



static int is_server_connection(enum conntype t) {
  return (t==HTTPSERVER6 || t==HTTPSERVER4
#ifdef SUPPORT_FTP
	|| t==FTPSERVER6 || t==FTPSERVER4
#endif
#ifdef SUPPORT_SMB
	|| t==SMBSERVER6 || t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
	|| t==HTTPSSERVER6 || t==HTTPSSERVER4
#endif
	);
}

#ifdef __broken_itojun_v6__
#warning "working around idiotic openbse ipv6 stupidity - please kick itojun for this!"
  int s4;		/* ipv4 http socket */
#ifdef SUPPORT_FTP
  int f4;		/* ipv4 ftp socket */
#endif
#ifdef SUPPORT_HTTPS
  int httpss4;		/* ipv4 https socket */
#endif
#endif

#ifdef SUPPORT_HTTPS
char* sshd;
unsigned long ssh_timeout;
#endif

int limit_to_lan;

static void accept_server_connection(int64 i,struct http_data* H,unsigned long ftptimeout_secs,tai6464 nextftp) {
  /* This is an FTP or HTTP(S) or SMB server connection.
    * This read event means that someone connected to us.
    * accept() the connection, establish connection type from
    * server connection type, and put the new connection into the
    * state table */
  char ip[16];
  uint16 port;
  uint32 scope_id;
  int n;

  while (1) {
    int punk;
#ifdef __broken_itojun_v6__
    if (H->t==HTTPSERVER4 || H->t==FTPSERVER4
#ifdef SUPPORT_SMB
					      || H->t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
					      || H->t==HTTPSSERVER4
#endif
								  ) {
      byte_copy(ip,12,V4mappedprefix);
      scope_id=0;
      n=socket_accept4(i,ip+12,&port);
    } else
#endif
      n=socket_accept6(i,ip,&port,&scope_id);
    if (n==-1) break;
    punk=new_request_from_ip(ip,now.sec.x-4611686018427387914ULL)==1;
    ++cps1;
    ++connections;
    if (logging) {
      char buf[IP6_FMT];

      buffer_puts(buffer_1,punk?(timeout_secs?"dos_tarpit ":"dos_drop "):"accept ");
      buffer_putulong(buffer_1,n);
      buffer_puts(buffer_1," ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,port);
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,connections-1);
      buffer_puts(buffer_1," ");
      {
	const char* service;
	switch (H->t) {
	case HTTPSERVER4:
	case HTTPSERVER6: service="http"; break;
#ifdef SUPPORT_HTTPS
	case HTTPSSERVER4:
	case HTTPSSERVER6: service="https"; break;
#endif
#ifdef SUPPORT_FTP
	case FTPSERVER4:
	case FTPSERVER6: service="ftp"; break;
#endif
#ifdef SUPPORT_SMB
	case SMBSERVER4:
	case SMBSERVER6: service="smb"; break;
#endif
	default: service="unk";
	}
	buffer_puts(buffer_1,service);
      }
      buffer_putnlflush(buffer_1);
    }
    if (limit_to_lan) {
      int passed;
      /* if the -L option is given, only accept connections from local
       * or reserved IP ranges */
      if (byte_equal(ip,12,V4mappedprefix)) {
	unsigned char* ip4=(unsigned char*)ip+12;
	passed = ip4[0]==127 ||	/* 127.0.0.1/8 */
	    ip4[0]==10 ||	/* RFC1918: 10.0.0.0/8 */
	    (ip4[0]==192 && ip4[1]==168) ||	/* RFC1918: 192.168.0.0/16 */
	    (ip4[0]==172 && ip4[1]>=16 && ip4[1]<=31) ||	/* RFC1918: 172.16.0.0/12 */
	    (ip4[0]==169 && ip4[1]==254 && ip4[2]!=0 && ip4[2]!=255);	/* RFC 5735: 169.254.0.0/16 */
      } else {	/* IPv6 */
	unsigned char* ip6=(unsigned char*)ip;
	passed = byte_equal(ip6,16,V6loopback) ||	/* ::1 */
	  (ip6[0]==0xfc && (ip6[1]&0xfe)==0) ||	/* RF4193 ULA fc00::/7 */
	  (ip6[0]==0xfe && (ip6[1]&0xfc)==0xc0) ||	/* deprecated site-local */
	  (ip6[0]==0xfe && (ip6[1]&0xfc)==0x80);	/* RFC5735 link-local */
      }
      if (!passed) {
	timeout_secs=0;
	punk=1;
	if (logging) {
	  buffer_puts(buffer_1,"close/outside_lan_drop ");
	  buffer_putulong(buffer_1,n);
	  buffer_putnlflush(buffer_1);
	}
      }
    }
    if (punk && !timeout_secs) {
      io_close(n);
      continue;
    }
#ifdef SUPPORT_SERVERSTATUS
    if (H->t==HTTPSERVER4 || H->t==HTTPSERVER6) ++http_connections;
#ifdef SUPPORT_HTTPS
    if (H->t==HTTPSSERVER4 || H->t==HTTPSSERVER6) ++https_connections;
#endif
#ifdef SUPPORT_FTP
    if (H->t==FTPSERVER4 || H->t==FTPSERVER6) ++ftp_connections;
#endif
#ifdef SUPPORT_SMB
    if (H->t==SMBSERVER4 || H->t==SMBSERVER6) ++smb_connections;
#endif
#endif

#ifdef TCP_NODELAY
    {
      int i=1;
      setsockopt(n,IPPROTO_TCP,TCP_NODELAY,&i,sizeof(i));
    }
#else
#warning TCP_NODELAY not defined
#endif

    if (io_fd_canwrite(n)) {
      struct http_data* h;
      h=(struct http_data*)malloc(sizeof(struct http_data));
      if (h) {
	io_nonblock(n);
	H->sent=H->received=0;
	if (!punk) {
	  if (H->t==HTTPSERVER6 || H->t==HTTPSERVER4
#ifdef SUPPORT_SMB
	    || H->t==SMBSERVER6 || H->t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
	    || H->t==HTTPSSERVER6 || H->t==HTTPSSERVER4
#endif
	    )
	    io_wantread(n);
	  else
	    io_wantwrite(n);
	}
	byte_zero(h,sizeof(struct http_data));
#ifdef STATE_DEBUG
	h->myfd=n;
#endif
#ifdef __broken_itojun_v6__
	if (i==s4 || i==f4) {
	  byte_copy(h->myip,12,V4mappedprefix);
	  socket_local4(n,h->myip+12,&h->myport);
	} else
	  socket_local6(n,h->myip,&h->myport,0);
#else
	socket_local6(n,h->myip,&h->myport,0);
#endif
	byte_copy(h->peerip,16,ip);
	h->peerport=port;
	h->myscope_id=scope_id;
	if (punk) {
	  changestate(h,PUNISHMENT);
	  io_timeout(n,next);
	} else if (H->t==HTTPSERVER4 || H->t==HTTPSERVER6) {
	  changestate(h,HTTPREQUEST);
	  if (timeout_secs)
	    io_timeout(n,next);
#ifdef SUPPORT_HTTPS
	} else if (H->t==HTTPSSERVER4 || H->t==HTTPSSERVER6) {
#ifdef __MINGW32__
//	  printf("chdir(\"%s\") -> %d\n",origdir,chdir(origdir));
//	  chdir(origdir);
#else
	  fchdir(origdir);
#endif
#ifdef USE_OPENSSL
	  if (init_serverside_tls(&h->ssl,n))
#elif defined(USE_POLARSSL)
	  if (init_serverside_tls(&h->ssl,n))
#endif
	  {
	    if (logging) {
	      char a[FMT_ULONG];
	      a[fmt_ulong(a,n)]=0;
	      buffer_putmflush(buffer_1,"ssl_setup_failed ",a," ",strerror(errno),"\nclose/readerr ",a,"\n");
	    }
	    cleanup(n);
	    continue;
	  }

	  changestate(h,HTTPSACCEPT_CHECK);
	  if (timeout_secs)
	    io_timeout(n,nextftp);
#endif
#ifdef SUPPORT_SMB
	} else if (H->t==SMBSERVER4 || H->t==SMBSERVER6) {
	  changestate(h,SMBREQUEST);
	  if (timeout_secs)
	    io_timeout(n,next);
#endif
#ifdef SUPPORT_FTP
	} else {
	  if (H->t==FTPSERVER6)
	    changestate(h,FTPCONTROL6);
	  else
	    changestate(h,FTPCONTROL4);
	  iob_addbuf(&h->iob,"220 Hi there!\r\n",15);
	  h->keepalive=1;
	  if (ftptimeout_secs)
	    io_timeout(n,nextftp);
#endif
	}
	h->buddy=-1;
	h->filefd=-1;
	io_setcookie(n,h);
      } else
	io_close(n);
    } else
      io_close(n);
#ifdef SUPPORT_MULTIPROC
    if (instances>1) break;
#endif
  }
  if (errno==EAGAIN)
    io_eagain(i);
  else
#ifdef __broken_itojun_v6__
    carp(H->t==HTTPSERVER4||H->t==FTPSERVER4?"socket_accept4":"socket_accept6");
#else
    if (errno==EINVAL) {
      static int64 lasteinval;
      if (lasteinval!=i) {
	lasteinval=i;
	carp("socket_accept6");
      }
    }
#endif
}

#ifdef SUPPORT_HTTPS

int handle_ssl_error_code(int sock,int code,int reading) {
//  printf("handle_ssl_error_code(sock %d,code %d,reading %d)\n",sock,code,reading);
  switch (code) {
#ifdef USE_OPENSSL
  case SSL_ERROR_WANT_READ:
    io_wantread(sock);
    io_dontwantwrite(sock);
    return 0;
  case SSL_ERROR_WANT_WRITE:
    io_wantwrite(sock);
    io_dontwantread(sock);
    return 0;
#elif defined(USE_POLARSSL)
  case POLARSSL_ERR_NET_WANT_READ:
    io_wantread(sock);
    io_dontwantwrite(sock);
    return 0;
  case POLARSSL_ERR_NET_WANT_WRITE:
    io_wantwrite(sock);
    io_dontwantread(sock);
    return 0;
#endif
#ifdef USE_OPENSSL
  case SSL_ERROR_SYSCALL:
#elif defined(USE_POLARSSL)
  case POLARSSL_ERR_NET_RECV_FAILED:
  case POLARSSL_ERR_NET_SEND_FAILED:
  case POLARSSL_ERR_NET_CONN_RESET:
    errno=ECONNRESET;
#endif
    // we already signal the error up and upsteam will then write an
    // error message
    return -1;
  default:
    if (logging) {
      buffer_puts(buffer_1,"ssl_protocol_error ");
      buffer_putulong(buffer_1,sock);
      buffer_puts(buffer_1,"\nclose/readerr ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    errno=EPROTO;
    return -1;
  }
}

void do_sslaccept(int sock,struct http_data* h,int reading) {
  int r;
  if (h->t == HTTPSACCEPT_CHECK) {
    unsigned char buf[10];
    changestate(h,HTTPSACCEPT);
    /* now, try to peek into the buffer, and see if it looks like an SSL
     * handshake */
    r=recv(sock,buf,sizeof(buf),MSG_PEEK);
    if (r>5) {
      if (sshd && buf[0]=='S' && buf[1]=='S' && buf[2]=='H') {
	if (logging) {
	  char numbuf[FMT_ULONG];
	  numbuf[fmt_ulong(numbuf,sock)]=0;
	  buffer_putmflush(buffer_1,"close/ssh_handshake ",numbuf,"\n");
	}
	{
	  uint32 a=0;
	  write(forksock[0],&a,4);
	  io_passfd(forksock[0],sock);
	}
	--https_connections;
	changestate(h,PUNISHMENT);
	cleanup(sock);
	return;
      }
      /* Apparently the packets look radically different depending on
       * whether it's TLS or SSLv2.  GREAT! */
      /* first packet must be handshake */
      if (buf[0]!=0x16 ||	/* content type: handshake */
	  buf[1]>3 ||	/* version major */
	  buf[2]>3 ||	/* version minor */
	  buf[3]>2) {	/* length > 0x200 */
	if (buf[0]!=0x80 ||
	    buf[2]!=1 ||	/* Client Hello */
	    buf[3]>3 ||	/* version major */
	    buf[4]>3) {	/* version minor */
	  tai6464 tarpit;
	  /* this does not look like an SSL packet. */
	  if (logging) {
	    char tmp[100];
	    buffer_puts(buffer_1,"close/not_ssl_traffic ");
	    buffer_putulong(buffer_1,sock);
	    buffer_putspace(buffer_1);
	    buffer_put(buffer_1,tmp,fmt_ip6c(tmp,h->peerip));
	    buffer_putnlflush(buffer_1);
	  }
	  io_dontwantread(sock);
	  io_dontwantwrite(sock);
	  --https_connections;
	  changestate(h,PUNISHMENT);
	  tarpit=now;
	  tarpit.sec.x+=10;
	  io_timeout(sock,tarpit);
	  return;
	}
      }
    }
  }

#ifdef USE_OPENSSL
  r=SSL_get_error(h->ssl,SSL_accept(h->ssl));
//  printf("do_sslaccept -> %d\n",r);
  if (r==SSL_ERROR_NONE)
#elif defined(USE_POLARSSL)
  r=ssl_handshake(&h->ssl);
  if (r==0)
#endif
  {
#if 0
    h->writefail=1;
#endif
    changestate(h,HTTPSREQUEST);
    if (logging) {
      buffer_puts(buffer_1,"ssl_handshake_ok ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    return;
  } else
    if (handle_ssl_error_code(sock,r,reading)==-1)
      cleanup(sock);
}
#endif

static void handle_read_misc(int64 i,struct http_data* h,unsigned long ftptimeout_secs,tai6464 nextftp) {
  /* This is a TCP client connection waiting for input, i.e.
    *   - an HTTP connection waiting for a HTTP request, or
    *   - an FTP connection waiting for a command, or
    *   - an FTP upload waiting for more data, or
    *   - an SMB connection waiting for the next command */
  char buf[8192];
  int l;
#ifdef MOREDEBUG
  printf("MOREDEBUG: entering handle_read_misc for fd #%d\n",(int)i);
#endif
#ifdef SUPPORT_HTTPS
  assert(h->t != HTTPSRESPONSE);
  if (h->t == HTTPSREQUEST) {
#ifdef USE_OPENSSL
    l=SSL_read(h->ssl,buf,sizeof(buf));
#elif defined(USE_POLARSSL)
    l=ssl_read(&h->ssl,(unsigned char*)buf,sizeof(buf));
#else
#error fixme
#endif
//    printf("SSL_read(sock %d,buf %p,n %d) -> %d\n",i,buf,sizeof(buf),l);
#ifdef USE_OPENSSL
    if (l==-1) {
      l=SSL_get_error(h->ssl,l);
      if (l==SSL_ERROR_WANT_READ || l==SSL_ERROR_WANT_WRITE) {
#elif defined(USE_POLARSSL)
    if (l<0) {
      if (l==POLARSSL_ERR_NET_WANT_READ || l==POLARSSL_ERR_NET_WANT_WRITE) {
#else
#error fixme
#endif
//      printf("  error %d %s\n",l,ERR_error_string(l,0));
	io_eagain(i);
	if (handle_ssl_error_code(i,l,1)==-1) {
	  cleanup(i);
	  return;
	}
	l=-1;
#ifdef USE_POLARSSL
      } else if (l==POLARSSL_ERR_NET_RECV_FAILED) {
	l=0;
#endif
      } else {
	printf("got polarssl error %x\n",l);
	errno=ECONNRESET;
	l=-3;
      }
    }
  } else
#endif
  l=io_tryread(i,buf,sizeof buf);
#ifdef MOREDEBUG
  printf("MOREDEBUG: io_tryread on fd #%d returned %ld\n",(int)i,(long)l);
#endif
  if (l==-3) {
#ifdef SUPPORT_FTP
ioerror:
#endif
    if (logging) {
      char a[FMT_ULONG];
      a[fmt_ulong(a,i)]=0;
      buffer_putmflush(buffer_1,"io_error ",a," ",strerror(errno),"\nclose/readerr ",a,"\n");
    }
    cleanup(i);
  } else if (l==0) {
    if (logging) {
      buffer_puts(buffer_1,"close/read0 ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
#ifdef SUPPORT_FTP
    if (h->t==FTPSLAVE) {
      /* This is an FTP upload, it just finished. */
      struct http_data* b=io_getcookie(h->buddy);
      assert(b);
      b->buddy=-1;
      iob_reset(&b->iob);
      iob_adds(&b->iob,"226 Got it.\r\n");
      io_dontwantread(h->buddy);
      io_wantwrite(h->buddy);
      if (chmoduploads)
	fchmod(h->filefd,0644);
      if (logging) {
	struct stat ss;
	if (fstat(h->filefd,&ss)==0) {
	  char a[FMT_ULONG];
	  char b[FMT_ULONG];
	  a[fmt_ulong(a,i)]=0;
	  b[fmt_ulong(b,ss.st_size)]=0;
	  buffer_putmflush(buffer_1,"received ",a," ",b,"\n");
	}
      }
    }
#endif
#ifdef SUPPORT_HTTPS
    if (h->t==HTTPSPOST || h->t==HTTPSRESPONSE || h->t==HTTPSREQUEST) {
#ifdef USE_OPENSSL
      SSL_shutdown(h->ssl);
#endif
    }
#endif
    cleanup(i);
  } else if (l>0) {
    /* successfully read some data (l bytes) */
    h->received+=l;
    tin1+=l;
#ifdef SUPPORT_FTP
    if (h->t==FTPCONTROL4 || h->t==FTPCONTROL6) {
      if (ftptimeout_secs)
	io_timeout(i,nextftp);
    } else {
      if (timeout_secs)
	io_timeout(i,next);
    }

    if (h->t==FTPSLAVE) {
      /* receive an upload */
      if (ftptimeout_secs)
	io_timeout(h->buddy,nextftp);
      if (write(h->filefd,buf,l)!=l)
	goto ioerror;
    } else
#endif
    {
      /* received a request */
//      printf("previous size: %lu, adding %lu bytes.\n",(unsigned long)array_bytes(&h->r),(unsigned long)l);
      array_catb(&h->r,buf,l);
      if (array_failed(&h->r)) {
	httperror(h,"500 Server Error","request too long.",0);
emerge:
	io_dontwantread(i);
	io_wantwrite(i);
      } else if (array_bytes(&h->r)>MAX_HEADER_SIZE) {
	httperror(h,"500 request too long","You sent too much header data",0);
	array_reset(&h->r);
	goto emerge;
      } else if ((l=header_complete(h,i))) {
	/* at this point we saw a \r\n\r\n */
	long alen;
pipeline:
	/* The h->mimetype reference is here so that we don't count both the HTTP
	 * connection and the first request on it as a dos attack. */
	if (h->mimetype && new_request_from_ip(h->peerip,now.sec.x-4611686018427387914ULL)==1) {
	  changestate(h,PUNISHMENT);
	  if (logging) {
	    char buf[IP6_FMT];
	    char n[FMT_LONG];
	    n[fmt_ulong(n,i)]=0;
	    buf[fmt_ip6c(buf,h->peerip)]=0;

	    buffer_putmflush(buffer_1,"dos_tarpit2 ",n," ",buf,"\n");
	  }
	  if (timeout_secs) {
	    io_dontwantread(i);
	    io_dontwantwrite(i);
	  } else
	    /* if we don't have timeouts enabled, just drop the connection */
	    cleanup(i);
	  return;
	}
#ifdef SUPPORT_HTTPS
	if (h->t==HTTPREQUEST || h->t==HTTPSREQUEST) {
	  httpresponse(h,i,l);
	  if (h->t == HTTPSREQUEST) changestate(h,HTTPSRESPONSE);
	}
#else
	if (h->t==HTTPREQUEST)
	  httpresponse(h,i,l);
#endif
#ifdef SUPPORT_SMB
	else if (h->t==SMBREQUEST) {
	  if (smbresponse(h,i)==-1) {
	    cleanup(i);
	    return;
	  }
	}
#endif
#ifdef SUPPORT_FTP
	else
	  ftpresponse(h,i);
#endif
#ifdef SUPPORT_PROXY
	if (h->t != HTTPPOST
#ifdef SUPPORT_HTTPS
	 && h->t != HTTPSPOST
#endif
	                     ) {
#endif
	  if (l < (alen=array_bytes(&h->r))) {
	    char* c=array_start(&h->r);

#if 0
	    printf("continuation: consumed %lu bytes from buffer (%lu still there)\n",
		   (unsigned long)l,
		   (unsigned long)(alen-l));
#endif
	    byte_copy(c,alen-l,c+l);
	    array_truncate(&h->r,1,alen-l);
	    l=header_complete(h,i);

#if 0
	    write(1,"\n\n",2);
	    write(1,array_start(&h->r),array_bytes(&h->r));
	    write(1,"\n\n",2);
#endif

	    if (l) {
	      /* this breaks SMB: */
//	      if (h->r.initialized) --h->r.initialized;
	      goto pipeline;
	    }
	  } else
	    array_reset(&h->r);
#ifdef SUPPORT_PROXY
	}
#endif
      }
    }
  }
#ifdef MOREDEBUG
  printf("MOREDEBUG: entering handle_read_misc for fd #%d\n",(int)i);
#endif
}

#ifdef SUPPORT_HTTPS
int64 https_write_callback(int64 sock,const void* buf,uint64 n) {
  int l;
  struct http_data* H=io_getcookie(sock);
  if (!H) return -3;

#if 0
  H->writefail=!H->writefail;
  if (H->writefail) { errno=EAGAIN; return -1; }
#endif
  if (n>65536) n=65536;
#ifdef USE_OPENSSL
  l=SSL_write(H->ssl,buf,n);
  if (l<0) {
    l=SSL_get_error(H->ssl,l);
#elif defined(USE_POLARSSL)
  l=ssl_write(&H->ssl,buf,n);
  if (l<0) {
#endif
    if (handle_ssl_error_code(sock,l,0)==-1) {
//      cleanup(sock);
      return -3;
    }
#ifdef USE_OPENSSL
    if (l==SSL_ERROR_WANT_READ || l==SSL_ERROR_WANT_WRITE) {
#elif defined(USE_POLARSSL)
    if (l==POLARSSL_ERR_NET_WANT_READ || l==POLARSSL_ERR_NET_WANT_WRITE) {
#endif
      l=-1; errno=EAGAIN;
    } else
      l=-3;
  }
  return l;
}
#endif

static void handle_write_misc(int64 i,struct http_data* h,uint64 prefetchquantum) {
  int64 r;
#ifdef MOREDEBUG
  puts("MOREDEBUG: entering handle_write_misc");
#endif
#ifdef SUPPORT_HTTPS
  assert(h->t != HTTPSREQUEST);
  if (h->t == HTTPSRESPONSE)
    r=iob_write(i,&h->iob,https_write_callback);
  else
#endif
  r=iob_send(i,&h->iob);
#ifdef MOREDEBUG
  printf("MOREDEBUG: iob_send on fd #%d returned %ld (%lu remaining)\n",(int)i,(long)r,(unsigned long)iob_bytesleft(&h->iob));
#endif
  if (r==-1)
    io_eagain(i);
  else if (r<=0) {
    if (r==-3) {
      if (logging) {
	char a[FMT_ULONG];
	char r[FMT_ULONG];
	char s[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	r[fmt_ulonglong(r,h->received)]=0;
	s[fmt_ulonglong(s,h->sent)]=0;
	buffer_putmflush(buffer_1,"socket_error ",a," ",strerror(errno),"\nclose/writefail ",a," ",r," ",s,"\n");
      }
#ifdef SUPPORT_FTP
      if (h->t==FTPSLAVE || h->t==FTPACTIVE) {
	struct http_data* b=io_getcookie(h->buddy);
	if (b) {
	  b->buddy=-1;
	  iob_reset(&b->iob);
	  iob_adds(&b->iob,"554 socket error.\r\n");
	  io_wantwrite(h->buddy);
	} else {
	  /* Apparently the main control connection already died.
	   * Nothing more to do here except clean up. */
	}
      }
#endif
      cleanup(i);
    } else {	/* returned 0, i.e. we wrote it all */
wroteitall:
#ifdef SUPPORT_HTTPS
      if (h->t == HTTPSRESPONSE) h->t = HTTPSREQUEST;
#endif
#ifdef SUPPORT_PROXY
#ifdef SUPPORT_HTTPS
      if ((h->t == HTTPREQUEST || h->t == HTTPSREQUEST) && h->buddy!=-1)
#else
      if (h->t == HTTPREQUEST && h->buddy!=-1)
#endif
      {
	io_dontwantwrite(i);
	io_wantread(h->buddy);
	return;
      }
#endif
      if (logging && (h->t == HTTPREQUEST
#ifdef SUPPORT_HTTPS
	  || h->t == HTTPSREQUEST
#endif
	  )) {
	buffer_puts(buffer_1,"request_done ");
	buffer_putulong(buffer_1,i);
	buffer_puts(buffer_1," ");
	buffer_putulonglong(buffer_1,h->received);
	buffer_puts(buffer_1," ");
	buffer_putulonglong(buffer_1,h->sent);
	buffer_putnlflush(buffer_1);
	h->received=h->sent=0;
      }
      if (array_bytes(&h->r)>0) --h->r.initialized;
      iob_reset(&h->iob);
      h->hdrbuf=0;
      if (h->keepalive) {
//	iob_reset(&h->iob);
	io_dontwantwrite(i);
	io_wantread(i);
      } else {
	if (logging) {
	  buffer_puts(buffer_1,"close/reqdone ");
	  buffer_putulong(buffer_1,i);
	  buffer_putnlflush(buffer_1);
	}
#ifdef SUPPORT_FTP
	if (h->t==FTPSLAVE) {
	  struct http_data* b=io_getcookie(h->buddy);
	  if (b) {
	    b->buddy=-1;
//	    iob_reset(&b->iob);
	    iob_adds(&b->iob,"226 Done.\r\n");
	    io_dontwantread(h->buddy);
	    io_wantwrite(h->buddy);
	  } else
	    buffer_putsflush(buffer_2,"ARGH: no cookie or no buddy for FTP slave!\n");
	}
#endif
	cleanup(i);
      }
    }
  } else {
    h->sent+=r;
    tout1+=r;
    /* write OK, now would be a good time to do some prefetching */
    h->sent_until+=r;
    if (prefetchquantum) {
      if (h->prefetched_until<h->sent_until || h->prefetched_until+prefetchquantum<h->sent_until) {
	if (prefetchquantum) iob_prefetch(&h->iob,2*prefetchquantum);
	h->prefetched_until+=2*prefetchquantum;
      }
    }
    if (iob_bytesleft(&h->iob)==0)	/* optimization, not strictly necessary */
      goto wroteitall;
  }
#ifdef MOREDEBUG
  puts("MOREDEBUG: leaving handle_write_misc");
#endif
}

static void prepare_listen(int s,void* whatever) {
  if (s!=-1) {
    if (!io_fd(s))
      panic("io_fd");
    io_setcookie(s,whatever);
    io_wantread(s);
  }
}

#ifdef SUPPORT_BITTORRENT
int handle_torrent_request(int64 sock,struct http_data* h) {
  /* http://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol */
  /* http://www.bittorrent.org/protocol.html */
  char* req=array_start(&h->r); /* "GET /announce?info_hash=%c3%f4%31%0e%aa%ec%ae%3d%84%c1%63%70%a2%36%67%6b%24%99%b6%e1&peer_id=-TR0006-u0u5j57kcmm4&port=6887&uploaded=0&downloaded=0&left=243269632&compact=1&numwant=50&key=njyytouhv5fymdafkhzi&event=started\r\n" */
  char* t=strchr(req,'\n');
  char* s=strchr(req,'?');
  if (s && t && s<t) {
    if (t[-1]=='\r') --t;
  } else
    httperror(h,"500 invalid bittorrent request","Invalid BitTorrent request",*req=='H');
  return 0;
}
#endif

int main(int argc,char* argv[],char* envp[]) {
  int s;		/* http socket */
  int f=-1;		/* ftp socket */
#ifdef SUPPORT_SMB
  int smbs=-1;		/* smb socket */
  enum conntype sct=SMBSERVER6;
#endif
  int doftp=0;		/* -1 = don't, 0 = try, but don't fail if not working, 1 = do */
  int dohttp=0;		/* -1 = don't, 0 = try, but don't fail if not working, 1 = do */
  int dosmb=0;
  enum { HTTP, FTP, SMB, HTTPS } lastopt=HTTP;
  enum conntype ct=HTTPSERVER6;	/* used as cookie to recognize server connections */
#ifdef SUPPORT_FTP
  enum conntype fct=FTPSERVER6;	/* dito */
#endif
#ifdef SUPPORT_HTTPS
  int httpss=-1;	/* https socket */
  enum conntype httpsct=HTTPSSERVER6;
  int dohttps=0;
#endif
#ifdef __broken_itojun_v6__
  enum conntype ct4=HTTPSERVER4;
#ifdef SUPPORT_FTP
  enum conntype fct4=FTPSERVER4;
#endif
#ifdef SUPPORT_HTTPS
  enum conntype httpsct4=HTTPSSERVER4;
#endif
#endif
  uint32 scope_id;
  char ip[16];
  uint16 port,fport,sport;
#ifdef SUPPORT_HTTPS
  uint16 httpsport=0;
  tai6464 nexthttps;
#endif
  tai6464 last,tick,nextftp;
  unsigned long ftptimeout_secs=600;
  char* new_uid=0;
  char* chroot_to=0;
  unsigned long long prefetchquantum=0;
#ifdef SUPPORT_MULTIPROC
  pid_t* Instances;
#endif

#if defined(DEBUG_EVENTS) || defined(MOREDEBUG) || defined(SMDEBUG) || defined(STATE_DEBUG)
#ifdef __dietlibc__
  fflush(stdout);
#endif
#endif

#ifdef SUPPORT_HTTPS
#ifdef USE_OPENSSL
  SSL_load_error_strings();
#endif
#endif

#if defined(SUPPORT_CGI) || defined(SUPPORT_PROXY)
  _envp=envp;
#endif
#ifdef SUPPORT_CGI
  {
    int found;
    int _argc=argc;
    char* new_uid=0;
    char** _argv=argv;

    found=0;
    for (;;) {
      int c=getopt(_argc,_argv,"HP:hnfFi:p:vVdDtT:c:u:Uaw:sSO:C:lLeEr:o:N:m:A:X:I:");
      if (c==-1) break;
      switch (c) {
      case 'c':
	chroot_to=optarg;
	break;
#ifdef SUPPORT_HTTPS
      case 'X':
	sshd=optarg;
	if (isdigit(*sshd)) {
	  while (isdigit(*sshd)) ++sshd;
	  ++sshd;
	}
	/* fall through */
#endif
      case 'C':
	found=1;
	break;
      case 'u':
	new_uid=optarg;
	break;
      case '?':
	break;
      }
    }

    optind=0;

    forksock[0]=forksock[1]=-1;
    if (found) {
      if (socketpair(AF_UNIX,SOCK_STREAM,0,forksock)==-1)
	panic("socketpair");
      switch (fork()) {
      case -1:
	panic("fork");
      case 0:
	close(forksock[0]);
	{
	  int64 savedir;
	  buffer fsb;
	  /* we want to drop privileges here unless we are configured to
	   * support sshd mode, in which case sshd won't work if we
	   * change our uid before executing it */
#ifdef SUPPORT_HTTPS
	  if (!sshd) {
#endif
#ifndef __MINGW32__
	  if (chroot_to) { chdir(chroot_to); chroot(chroot_to); }
	  if (prepare_switch_uid(new_uid)==-1 || switch_uid()==-1) panic("switch_uid failed");
#endif
#ifdef SUPPORT_HTTPS
#ifndef __MINGW32__
	  } else {
	    if (prepare_switch_uid(new_uid)==-1) panic("switch_uid failed");
#endif
	  }
#endif
	  if (!io_readfile(&savedir,".")) panic("open()");
	  buffer_init(&fsb,(void*)read,forksock[1],fsbuf,sizeof fsbuf);
	  while (1) {
	    pid_t r;
	    do {
	      r=waitpid(-1,0,WNOHANG);
	    } while (r!=0 && r!=-1);
	    forkslave(forksock[1],&fsb,savedir,chroot_to);
	    fchdir(savedir);
	  }
	}
	break;
      default:
	close(forksock[1]);
	break;
      }
    }
  }

#if 0
  {	/* debug test for the forkslave code */
    int64 fd;
    uint32 a; uint16 b;
    char* req="GET /?/ HTTP/1.0\r\nHost: localhost:80\r\n\r\n";
    char* dir="default";
    char* ra="127.0.0.1";
    a=strlen(req); write(forksock[0],&a,4);
    a=strlen(dir); write(forksock[0],&a,4);
    a=strlen(ra); write(forksock[0],&a,4);
    write(forksock[0],req,strlen(req));
    write(forksock[0],dir,strlen(dir));
    write(forksock[0],ra,strlen(ra));
    b=12345; write(forksock[0],&b,2);
    b=80; write(forksock[0],&b,2);

    read(forksock[0],&a,4);
    buffer_puts(buffer_1,"code ");
    buffer_putulong(buffer_1,a);
    buffer_putnlflush(buffer_1);

    read(forksock[0],&a,4);
    if (a) {
      char* c=alloca(a+1);
      read(forksock[0],c,a);
      buffer_put(buffer_1,c,a);
      buffer_putnlflush(buffer_1);
    } else {
      read(forksock[0],&a,4); /* PID */
      fd=io_receivefd(forksock[0]);
      if (fd==-1)
	buffer_putsflush(buffer_2,"received no file descriptor for CGI\n");
      else {
	char buf[1024];
	int l;
	while ((l=read(fd,buf,sizeof buf))) {
	  write(1,buf,l);
	}
      }
    }
  }
  exit(0);
#endif
#endif

  s=socket_tcp6();
#ifdef __broken_itojun_v6__
#ifdef SUPPORT_FTP
  f4=socket_tcp4();
#endif
  s4=socket_tcp4();
#endif

#ifndef __MINGW32__
  signal(SIGPIPE,SIG_IGN);

  {
    struct sigaction sa;
    byte_zero(&sa,sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler=sighandler;
    sigaction(SIGINT,&sa,0);
    sigaction(SIGHUP,&sa,0);
  }

  if (!geteuid()) {
    struct rlimit orig,rl;
    long l;
    getrlimit(RLIMIT_NOFILE,&orig);
#ifdef RLIMIT_NPROC
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
#endif
    for (l=orig.rlim_max; l<20000; l+=500) {
      rl.rlim_cur=l; rl.rlim_max=l;
      if (setrlimit(RLIMIT_NOFILE,&rl)==-1) {
	if (errno==EPERM) {
	  /* We run as root but we still get EPERM?  That only happens
	   * on linux-vserver.  There is no good way to handle this, so
	   * we'll set the soft limit to the hard limit */
	  orig.rlim_cur=orig.rlim_max;
	  setrlimit(RLIMIT_NOFILE,&orig);
	}
	break;
      }
    }
  }
#endif

  byte_zero(ip,16);
  port=0; fport=0; sport=0; scope_id=0;

  logging=1;

#if !defined(__linux__)
  optind=1;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  optreset=1;
#endif
#endif

  for (;;) {
    int i;
    int c=getopt(argc,argv,"HP:hnfFi:p:vVdDtT:c:u:Uaw:sSO:C:lLeEr:o:N:m:A:X:I:");
    if (c==-1) break;
    switch (c) {
    case 'L':
      limit_to_lan=1;
      break;
    case 'U':
      nouploads=1;
      break;
    case 'a':
      chmoduploads=1;
      break;
    case 'n':
      logging=0;
      break;
    case 'u':
      new_uid=optarg;
      break;
    case 'c':
      chroot_to=optarg;
      break;
    case 'm':
      mimetypesfilename=optarg;
      break;
    case 'P':
      i=scan_ulonglong(optarg,&prefetchquantum);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse prefetch quantum");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      if (optarg[i]=='M') prefetchquantum*=1024*1024;
      if (optarg[i]=='G') prefetchquantum*=1024*1024*1024;
      break;
    case 'i':
      i=scan_ip6if(optarg,ip,&scope_id);
      if (optarg[i]!=0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse IP address ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'I':
      defaultindex=optarg;
      break;
    case 'p':
      if (lastopt==FTP)
	i=scan_ushort(optarg,&fport);
      else if (lastopt==SMB)
	i=scan_ushort(optarg,&sport);
#ifdef SUPPORT_HTTPS
      else if (lastopt==HTTPS)
	i=scan_ushort(optarg,&httpsport);
#endif
      else
	i=scan_ushort(optarg,&port);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse port ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'v': virtual_hosts=1; break;
    case 'V': virtual_hosts=-1; break;
    case 't': transproxy=1; break;
    case 'd': directory_index=1; break;
    case 'D': directory_index=-1; break;
#ifdef SUPPORT_FTP
    case 'f': doftp=1; lastopt=FTP; break;
    case 'F': doftp=-1; break;
    case 'l':
      askforpassword=1;
      break;
#endif
#ifdef SUPPORT_HTTPS
    case 'e': dohttps=1; lastopt=HTTPS; break;
    case 'E': dohttps=-1; break;
    case 'X': sshd=optarg;
	      if (isdigit(sshd[0])) {
		i=scan_ulong(optarg,&ssh_timeout);
		if (sshd[i]!=',' && sshd[i]!=' ') goto usage;
		sshd+=i+1;
	      } else ssh_timeout=2;
	      break;
#endif
    case 'H': dohttp=-1; break;
    case 's': dosmb=1; lastopt=SMB; break;
    case 'S': dosmb=-1; break;
    case 'T':
      i=scan_ulong(optarg,doftp?&ftptimeout_secs:&timeout_secs);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse timeout in seconds ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
#ifdef SUPPORT_SMB
    case 'w':
      if (str_len(optarg)>12)
	buffer_putsflush(buffer_2,"gatling: workgroup name too long (12 max)\n");
      else
	str_copy(workgroup,optarg);
      break;
#endif
#ifdef SUPPORT_CGI
    case 'C':
      errno=0;
      if (add_cgi(optarg)) {
	if (errno==ENOMEM)
	  buffer_putmflush(buffer_2,"gatling: out of memory\n");
	else
	  buffer_putmflush(buffer_2,"gatling: could not parse `",optarg,"': expected something like `\\.cgi$'\n");
      }
      break;
#endif
#ifdef SUPPORT_PROXY
    case 'O':
      errno=0;
      if (add_proxy(optarg)) {
	if (errno==ENOMEM)
	  buffer_putmflush(buffer_2,"gatling: out of memory\n");
	else
	  buffer_putmflush(buffer_2,"gatling: could not parse `",optarg,"': expected something like `127.0.0.1/8001/\\.jsp'\n");
      }
      break;
#endif
#ifdef SUPPORT_FALLBACK_REDIR
    case 'r':
      if (strstr(optarg,"://"))
	redir=optarg;
      else
	buffer_putmflush(buffer_2,"gatling: -r needs something like http://fallback.example.com as argument!\n");
      break;
#endif
#ifdef SUPPORT_MULTIPROC
    case 'N':
      i=scan_ulong(optarg,&instances);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse instances at ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
#endif
    case 'A':
      i=scan_uint(optarg,&max_requests_per_minute);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse max_requests_per_minute at ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;

#ifdef SUPPORT_THREADED_OPEN
    case 'o':
#endif
    default:
    case '?':
    case 'h':
usage:
      buffer_putsflush(buffer_2,
		  "usage: gatling [-hnvVtdDfFUa] [-i bind-to-ip] [-p bind-to-port] [-T seconds]\n"
		  "               [-u uid] [-c dir] [-w workgroup] [-P bytes] [-O ip/port/regex]\n"
		  "               [-r redirurl] [-N processes] [-I filename]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-v\tenable virtual hosting mode\n"
		  "\t-V\tdisable virtual hosting mode\n"
		  "\t\t(default is to try both)\n"
		  "\t-t\ttransproxy mode: do not replace :port in Host headers\n"
		  "\t-d\tgenerate directory index\n"
		  "\t-D\tdo not generate directory index\n"
		  "\t\t(default is -d unless in virtual hosting mode)\n"
		  "\t-T n\tset timeout in seconds (0 to disable, default 23)\n"
		  "\t-u uid\tswitch to this UID after binding\n"
		  "\t-c dir\tchroot to dir after binding\n"
		  "\t-n\tdo not produce logging output\n"
		  "\t-f\tprovide FTP (default); next -p is meant for the FTP port (default: 21)\n"
		  "\t-F\tdo not provide FTP\n"
		  "\t-U\tdisallow FTP uploads, even to world writable directories\n"
		  "\t-a\tchmod go+r uploaded files, so they can be downloaded immediately\n"
		  "\t-P n\tenable experimental prefetching code (may actually be slower)\n"
		  "\t-l\task for password (FTP server; work around buggy proxies)\n"
		  "\t-m fn\tparse fn as mime.types style mime type database\n"
		  "\t-A rpm\ttarpit clients if they have more than rpm request per minute\n"
#ifdef SUPPORT_MULTIPROC
		  "\t-N n\tfork n instances of gatling\n"
#endif
#ifdef SUPPORT_CGI
		  "\t-C regex\tregex for local CGI execution (\"\\.cgi\")\n"
		  "\t\tuse -C+x to assume executables are CGIs\n"
#endif
		  "\t-I name\talso try name, used for \"index.php\" etc\n"
#ifdef SUPPORT_PROXY
		  "\t-O [flag/]ip/port/regex\tregex for proxy mode (\"F/127.0.0.1/8001/\\.jsp$\")\n"
		  "\t-O [flag/]|filename|regex\tregex for proxy mode (\"F/|/tmp/php.sock|\\.jsp$\")\n"
		  "\t\tflags: F - FastCGI, S - SCGI, J - JSP\n"
#endif
#ifdef SUPPORT_SMB
		  "\t-s\tprovide SMB service (default)\n"
		  "\t-S\tdo not provide SMB service\n"
		  "\t-w name\tset SMB workgroup\n"
#endif
#ifdef SUPPORT_HTTPS
		  "\t-e\tprovide encryption (https://...)\n"
		  "\t-E\tdo not provide encryption\n"
		  "\t-X timeout,sshd (\"2,/opt/diet/sbin/sshd -u0\")\n"
		  "\t\tforward TLS socket to sshd if no activity after connect\n"
#endif
#ifdef SUPPORT_FALLBACK_REDIR
		  "\t-r url\tinstead of a 404, generate a redirect to url+localpart\n"
#endif
		  "\t-L\tonly accept connections from localhost or link/site local reserved IP addresses\n"
		  );
      return 0;
    }
  }
#ifdef SUPPORT_SMB
  {
    iconv_t i=iconv_open("UTF-16LE","ISO-8859-1");
    size_t X,Y;
    char* x,* y;
    X=str_len(workgroup)+1;
    Y=sizeof(workgroup_utf16);
    x=workgroup;
    y=workgroup_utf16;
#ifdef __sun__
    if (iconv(i,(const char**)&x,&X,&y,&Y)) panic("UTF-16 conversion of workgroup failed.\n");
#else
    if (iconv(i,&x,&X,&y,&Y)) panic("UTF-16 conversion of workgroup failed.\n");
#endif
    wglen=str_len(workgroup);
    wglen16=sizeof(workgroup_utf16)-Y;
    iconv_close(i);

  }
  {
    extern iconv_t wc2utf8;
    extern iconv_t utf82wc2;
    wc2utf8=iconv_open("UTF-8","UTF-16LE");
    utf82wc2=iconv_open("UTF-16LE","UTF-8");
  }
#endif
  if (!directory_index)
    directory_index=virtual_hosts<1;
  else if (directory_index==-1)
    directory_index=0;

  if (timeout_secs) {
    taia_now(&last);
    byte_copy(&next,sizeof(next),&last);
    next.sec.x += timeout_secs;
    byte_copy(&nextftp,sizeof(next),&last);
    nextftp.sec.x += ftptimeout_secs;
#ifdef SUPPORT_HTTPS
    if (ssh_timeout) {
      byte_copy(&nexthttps,sizeof(now),&now);
      nexthttps.sec.x += ssh_timeout;
    } else
      byte_copy(&nexthttps,sizeof(next),&next);
#endif
    byte_copy(&tick,sizeof(next),&last);
    ++tick.sec.x;
  }

  {
#ifdef __MINGW32__
    int euid=0;
#else
    uid_t euid=geteuid();
#endif
    if (port==0)
      port=euid?8000:80;
    if (fport==0)
      fport=euid?2121:21;
#ifdef SUPPORT_SMB
    if (sport==0)
      sport=445;
#endif
#ifdef SUPPORT_HTTPS
    if (httpsport==0)
      httpsport=euid?4433:443;
#endif
  }
#ifdef __broken_itojun_v6__
  if (byte_equal(ip,12,V4mappedprefix) || byte_equal(ip,16,V6any)) {
    if (byte_equal(ip,16,V6any)) {
      if (dohttp==-1) {
	close(s); s=-1;
      } else {
	if (socket_bind6_reuse(s,ip,port,scope_id)==-1 || socket_listen(s,16)==-1)
	  panic("socket_bind6_reuse for http");
      }
#ifdef SUPPORT_FTP
      f=socket_tcp6();
      if (doftp>=0)
	if (socket_bind6_reuse(f,ip,fport,scope_id)==-1 || socket_listen(f,16)==-1) {
	  if (doftp==1)
	    panic("socket_bind6_reuse for ftp");
	  buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	  io_close(f); f=-1;
	}
#endif
    } else {
      io_close(s); s=-1;
    }
    if (socket_bind4_reuse(s4,ip+12,port)==-1 || socket_listen(s4,16)==-1)
      panic("socket_bind4_reuse");
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind4_reuse(f4,ip+12,fport)==-1 || socket_listen(f4,16)==-1) {
	if (doftp==1)
	  panic("socket_bind4_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f4); f4=-1;
      }
#endif
  } else {
    if (dohttp==-1) {
      close(s);
      s=-1;
    } else {
      if (socket_bind6_reuse(s,ip,port,scope_id)==-1 || socket_listen(s,16)==-1)
	panic("socket_bind6_reuse");
    }
    s4=-1;
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind6_reuse(f,ip,fport,scope_id)==-1 || socket_listen(f,16)==-1) {
	if (doftp==1)
	  panic("socket_bind6_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f); f=-1;
      }
    f4=-1;
#endif
  }
  buffer_putsflush(buffer_2,"WARNING: We are taking heavy losses working around itojun KAME madness here.\n"
		            "         Please consider using an operating system with real IPv6 support instead!\n");
#else
  if (dohttp==-1) {
    close(s);
    s=-1;
  } else {
#ifndef __linux__
    socket_deferaccept(s,HTTPIN);
#endif
    if (socket_bind6_reuse(s,ip,port,0)==-1 || socket_listen(s,16)==-1)
      panic("socket_bind6_reuse");
  }
#ifdef SUPPORT_FTP
  if (doftp>=0) {
    f=socket_tcp6();
    if (socket_bind6_reuse(f,ip,fport,scope_id)==-1 || socket_listen(f,16)==-1) {
      if (doftp==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
      io_close(f); f=-1;
    }
  }
#endif
#ifdef SUPPORT_SMB
  if (dosmb>=0) {
    smbs=socket_tcp6();
#ifndef __linux__
    socket_deferaccept(smbs,DATAIN);
#endif
    if (socket_bind6_reuse(smbs,ip,sport,scope_id)==-1 || socket_listen(smbs,16)) {
      if (dosmb==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to SMB port; SMB will be unavailable.\n");
      io_close(smbs); smbs=-1;
    }
  }
#endif
#ifdef SUPPORT_HTTPS
  if (dohttps>=0) {
    httpss=socket_tcp6();
#ifndef __linux__
    if (ssh_timeout==0)
      socket_deferaccept(httpss,DATAIN);
#endif
    if (socket_bind6_reuse(httpss,ip,httpsport,scope_id)==-1 || socket_listen(httpss,16)) {
      if (dohttps==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to HTTPS port; HTTPS will be unavailable.\n");
      io_close(httpss); httpss=-1;
    }
  }
#endif
#endif

#ifndef __MINGW32__
  if (prepare_switch_uid(new_uid)==-1)
    goto usage;
  if (chroot_to) {
    if (chroot(chroot_to)==-1)
      panic("chroot");
    if (chdir("/")==-1)
      panic("chdir");
  }
  if (new_uid && switch_uid()==-1)
    panic("switch_uid");

#endif

#ifdef __MINGW32__
  _getcwd(origdir,sizeof(origdir));
  strncpy(serverroot,origdir,sizeof(serverroot));
//  printf("origdir is \"%s\"\n",origdir);
#else
  /* get fd for . so we can always fchdir back */
  if (!io_readfile(&origdir,".")) panic("open()");
  /* note the server root path for CGI $SCRIPT_FILENAME */
  if (!getcwd(serverroot,sizeof(serverroot))) {
    serverroot[0]='.';
    serverroot[1]=0;
  }
#endif

#ifdef SUPPORT_MULTIPROC

  if (instances>1) {
    unsigned long i;
    --instances;

    if (instances>100) instances=100;
    Instances=alloca(instances*sizeof(pid_t));
    for (i=0; i<instances; ++i) {
      if ((Instances[i]=fork()) == -1)
	panic("fork failed");
      else if (Instances[i] == 0) {
	instances=0;
	break;
      }
    }

#ifdef __broken_itojun_v6__
    prepare_listen(s,&ct);
    prepare_listen(s4,&ct4);
    prepare_listen(f,&fct);
    prepare_listen(f4,&fct4);
#else
    prepare_listen(s,&ct);
#ifdef SUPPORT_FTP
    prepare_listen(f,&fct);
#endif
#ifdef SUPPORT_SMB
    prepare_listen(smbs,&sct);
#endif
#ifdef SUPPORT_HTTPS
    prepare_listen(httpss,&httpsct);
#endif
#endif

  } else {
#endif
#ifdef SUPPORT_MULTIPROC
    Instances=0;
    instances=0;
#endif

#ifdef __broken_itojun_v6__
    prepare_listen(s,&ct);
    prepare_listen(s4,&ct4);
    prepare_listen(f,&fct);
    prepare_listen(f4,&fct4);
#else
    prepare_listen(s,&ct);
#ifdef SUPPORT_FTP
    prepare_listen(f,&fct);
#endif
#ifdef SUPPORT_SMB
    prepare_listen(smbs,&sct);
#endif
#ifdef SUPPORT_HTTPS
    prepare_listen(httpss,&httpsct);
#endif
#endif

#ifdef SUPPORT_MULTIPROC
  }
#endif

  {
    char buf[IP6_FMT];
    if (s!=-1) {
      buffer_puts(buffer_1,"starting_up 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
    }
    if (f!=-1) {
      buffer_puts(buffer_1,"start_ftp 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,fport);
      buffer_putnlflush(buffer_1);
    }
#ifdef SUPPORT_SMB
    if (smbs!=-1) {
      buffer_puts(buffer_1,"start_smb 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,sport);
      buffer_putnlflush(buffer_1);
    }
#endif
#ifdef SUPPORT_HTTPS
    if (httpss!=-1) {
      buffer_puts(buffer_1,"start_https 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,httpsport);
      buffer_putnlflush(buffer_1);
    }
#endif
  }

  connections=1;

#if !defined(__OPTIMIZE__) && defined(__linux__)
  /* This happens only if the code was compiled without optimization */
  /* make sure we can dump core even if we switched uid */
  prctl(PR_SET_DUMPABLE,1,0,0);
  /* and make sure we don't have a core dump size limit in place */
  {
    struct rlimit orig;
    orig.rlim_cur=orig.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_CORE,&orig);
  }
#endif

  for (;;) {
    int events;		/* accept new connections asap */
    int64 i;
    events=0;

    if (fini==2) {
      --connections;
      io_close(s);
#ifdef __broken_itojun_v6__
      io_close(s4);
#endif
#ifdef SUPPORT_FTP
      io_close(f);
#ifdef __broken_itojun_v6__
      io_close(f4);
#endif
#endif
#ifdef SUPPORT_SMB
      io_close(smbs);
#endif
      buffer_puts(buffer_1,"closing_server_sockets ");
      buffer_putulong(buffer_1,connections);
      buffer_putnlflush(buffer_1);
      fini=0;
    }
    if (!connections) fini=1;
    if (fini) {
      buffer_putsflush(buffer_1,"stopping\n");
      break;
    }

    if (timeout_secs)
      io_waituntil(tick);
    else
      io_wait();

    taia_now(&now);
    if (timeout_secs) {
      if (now.sec.x != last.sec.x) {
	cps=cps1; cps1=0;
	rps=rps1; rps1=0;
	eps=eps1; eps1=0;
	tin=tin1; tin1=0;
	tout=tout1; tout1=0;
	byte_copy(&last,sizeof(now),&now);
	byte_copy(&next,sizeof(now),&now);
	next.sec.x += timeout_secs;
	byte_copy(&nextftp,sizeof(now),&now);
	nextftp.sec.x += ftptimeout_secs;
#if defined(SUPPORT_HTTPS) && !defined(SUPPORT_MULTIPROC)
	if (ssh_timeout) {
	  byte_copy(&nexthttps,sizeof(now),&now);
	  nexthttps.sec.x += ssh_timeout;
	} else
	  byte_copy(&nexthttps,sizeof(next),&next);
#endif
	byte_copy(&tick,sizeof(next),&now);
	++tick.sec.x;
	while ((i=io_timeouted())!=-1) {
	  struct http_data* x;
#if defined(SUPPORT_HTTPS) && !defined(SUPPORT_MULTIPROC)
	  if (ssh_timeout && (x=io_getcookie(i)) && x->t == HTTPSACCEPT_CHECK) {
	    if (logging) {
	      char numbuf[FMT_ULONG];
	      numbuf[fmt_ulong(numbuf,i)]=0;
	      buffer_putmflush(buffer_1,"timeout/sshd ",numbuf,"\n");
	    }
	    {
	      uint32 a=0;
	      write(forksock[0],&a,4);
	      io_passfd(forksock[0],i);
	    }
	    --https_connections;
	  }
#endif
	  if (logging) {
	    /* shut up in the tarpit case, don't give them the
	     * satisfaction of spamming our logs too much */
	    if ((x=io_getcookie(i)) && x->t != PUNISHMENT) {
	      char numbuf[FMT_ULONG];
	      numbuf[fmt_ulong(numbuf,i)]=0;
	      buffer_putmflush(buffer_1,"timeout ",numbuf,"\nclose/timeout ",numbuf,"\n");
	    }
	  }
	  cleanup(i);
	}
      }
    }

    /* HANDLE READ EVENTS */
    while ((i=io_canread())!=-1) {
      struct http_data* H=io_getcookie(i);

      ++eps1;
      if (!H) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"canthappen ",a,": got read event on socket with no cookie!\n");
	io_dontwantread(i);
	io_close(i);
	continue;
      }

#ifdef SMDEBUG
      {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"DEBUG: fd ",a," got READ event, state is ",state2string(H->t),"!\n");
      }
#endif

      /* This is a speed hack.  If we have a LOT of connections, we
       * might get swamped handling events and it might take a while for
       * us to get around to accepting new connections.  Unfortunately,
       * the kernel has a limited number of connections that can be
       * incoming but not accepted; if more attempts come in, the kernel
       * just drops them, and they then run into a timeout and try
       * again.  To avoid this, we try accepting connections even
       * without any events. */
      if (++events==10) {
	events=0;
	if (s!=-1) accept_server_connection(s,(struct http_data*)&ct,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f!=-1) accept_server_connection(f,(struct http_data*)&fct,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss!=-1) {
	  if (ssh_timeout)
	    accept_server_connection(httpss,(struct http_data*)&httpsct,ssh_timeout,nexthttps);
	  else
	    accept_server_connection(httpss,(struct http_data*)&httpsct,ftptimeout_secs,nextftp);
	}
#endif
#ifdef __broken_itojun_v6__
	if (s4!=-1) accept_server_connection(s4,(struct http_data*)&ct4,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f4!=-1) accept_server_connection(f4,(struct http_data*)&fct4,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss4!=-1) {
	  if (ssh_timeout)
	    accept_server_connection(httpss4,(struct http_data*)&httpsct4,ssh_timeout,nexthttps);
	  else
	    accept_server_connection(httpss4,(struct http_data*)&httpsct4,ftptimeout_secs,nextftp);
	}
#endif
#endif
      }

      if (H->t == HTTPREQUEST
#ifdef SUPPORT_FTP
	  || H->t == FTPSLAVE
#endif
#ifdef SUPPORT_SMB
	  || H->t == SMBREQUEST
#endif
#ifdef SUPPORT_HTTPS
	  || H->t == HTTPSRESPONSE
#endif
	 )
	H->sent_until=H->prefetched_until=0;

#ifdef SUPPORT_PROXY
	/* read on PROXYPOST means the CGI sent some data */
      if (H->t==PROXYPOST)
	handle_read_proxypost(i,H);
      else if (H->t==HTTPPOST
#ifdef SUPPORT_HTTPS
	    || H->t==HTTPSPOST
#endif
			      )
	/* read on HTTPPOST means the browser sent some more POST data */
	handle_read_httppost(i,H);
      else
#endif
#ifdef SUPPORT_FTP
      if (H->t==FTPPASSIVE)
	handle_read_ftppassive(i,H);
      else
#endif
#ifdef SUPPORT_HTTPS
      if (H->t==HTTPSACCEPT || H->t==HTTPSACCEPT_CHECK)
	do_sslaccept(i,H,1);
      else
#endif
      if (is_server_connection(H->t)) {
#ifdef SUPPORT_HTTPS
	if (ssh_timeout && (H->t == HTTPSSERVER6 || H->t == HTTPSSERVER4))
	  accept_server_connection(i,H,ssh_timeout,nexthttps);
	else
#endif
	accept_server_connection(i,H,ftptimeout_secs,nextftp);
      }
      else {
#ifdef SUPPORT_HTTPS
	/* This looks wrong but isn't.  SSL has renegotiation.
	   If that happens, we can be waiting for read when we are actually trying to write something */
	if (H->t == HTTPSRESPONSE)
	  handle_write_misc(i,H,prefetchquantum);
	else
#endif
	handle_read_misc(i,H,ftptimeout_secs,nextftp);
      }
    }

    /* HANDLE WRITABLE EVENTS */
    while ((i=io_canwrite())!=-1) {
      struct http_data* h=io_getcookie(i);
      ++eps1;
      if (!h) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"canthappen ",a,": got write event on socket with no cookie!\n");
	io_dontwantwrite(i);
	io_close(i);
	continue;
      }

#ifdef SMDEBUG
      {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"DEBUG: fd ",a," got WRITE event, state is ",state2string(h->t),"!\n");
      }
#endif

      if (++events==10) {
	events=0;
	accept_server_connection(s,(struct http_data*)&ct,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f!=-1) accept_server_connection(f,(struct http_data*)&fct,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss!=-1) {
	  if (ssh_timeout)
	    accept_server_connection(httpss,(struct http_data*)&httpsct,ssh_timeout,nexthttps);
	  else
	    accept_server_connection(httpss,(struct http_data*)&httpsct,ftptimeout_secs,nextftp);
	}
#endif
#ifdef __broken_itojun_v6__
	if (s4!=-1) accept_server_connection(s4,(struct http_data*)&ct4,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f4!=-1) accept_server_connection(f4,(struct http_data*)&fct4,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss4!=-1) {
	  if (ssh_timeout)
	    accept_server_connection(httpss4,(struct http_data*)&httpsct4,ssh_timeout,nexthttps);
	  else
	    accept_server_connection(httpss4,(struct http_data*)&httpsct4,ftptimeout_secs,nextftp);
	}
#endif
#endif
      }

#ifdef SUPPORT_FTP
      if (h->t==FTPCONTROL4 || h->t==FTPCONTROL6) {
	if (ftptimeout_secs)
	  io_timeout(i,nextftp);
      } else
#endif
      if (timeout_secs) {
	io_timeout(i,next);
	if (h->buddy>0) {
#ifdef SUPPORT_FTP
	  if (h->t==FTPSLAVE) {
	    io_timeout(h->buddy,nextftp);
	  } else
#endif
	    io_timeout(h->buddy,next);
	}
      }

#ifdef SUPPORT_PROXY
      if (h->t==PROXYSLAVE)
	handle_write_proxyslave(i,h);
      else if (h->t==PROXYPOST)
	handle_write_proxypost(i,h);
      else if (h->t==HTTPPOST
#ifdef SUPPORT_HTTPS
	    || h->t==HTTPSPOST
#endif
			      )
	handle_write_httppost(i,h);
      else
#endif
#ifdef SUPPORT_HTTPS
      if (h->t==HTTPSACCEPT)
	do_sslaccept(i,h,0);
      else if (h->t == HTTPSREQUEST)
	handle_read_misc(i,h,ftptimeout_secs,nextftp);
      else
#endif
#ifdef SUPPORT_FTP
      if (h->t==FTPACTIVE)
	handle_write_ftpactive(i,h);
      else
#endif
	handle_write_misc(i,h,prefetchquantum);
    }
  }
#ifdef SUPPORT_MULTIPROC
  if (instances) {
    unsigned long i;
    for (i=0; i<instances; ++i)
      kill(Instances[i],15);
  }
#endif
  io_finishandshutdown();
#ifdef SUPPORT_HTTPS
#ifdef USE_OPENSSL
  ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ASN1_STRING_TABLE_cleanup();
  ERR_free_strings();
#endif
#endif
#ifdef SUPPORT_SMB
  {
    extern iconv_t wc2utf8;
    extern iconv_t utf82wc2;
    iconv_close(wc2utf8);
    iconv_close(utf82wc2);
  }
#endif
  _exit(0);
  return 0;
}

#if 0
int epoll_create(int i) { return -1; }
#endif
