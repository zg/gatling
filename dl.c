#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include "socket.h"
#include "byte.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "io.h"
#include "case.h"
#include "stralloc.h"
#include "textcode.h"
#include "uint16.h"
#include "uint64.h"
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <utime.h>
#ifdef __MINGW32__
#include <windows.h>
#include <fcntl.h>
#else
#include <sys/resource.h>
#include <sys/uio.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#ifdef __MINGW32__
#include "windows.h"
#include <malloc.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "havealloca.h"
#endif
#include <assert.h>
#include <ctype.h>
#include <string.h>

#ifndef __linux__
char *strndup(const char *s,size_t n) {
  char *tmp=!(n+1)?0:(char *)malloc(n+1);
  if (!tmp) return 0;
  strncpy(tmp,s,n);
  tmp[n]=0;
  return tmp;
}
#endif

int dostats;
int dosync;
time_t ims=0;
int verbose=0;
int ignoreeof;

char* todel;

void alarm_handler(int dummy) {
  (void)dummy;
  if (todel) unlink(todel);
  exit(1);
}

static void clearstats();

static void carp(const char* routine) {
  clearstats();
  buffer_puts(buffer_2,"dl: ");
  buffer_puts(buffer_2,routine);
  if (routine[0] && routine[str_len(routine)-1]!='\n') {
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
  } else
    buffer_flush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

static unsigned long long int total;
static unsigned long long resumeofs;

static int statsprinted;

void printstats(unsigned long long nextchunk,int fd) {
  static unsigned long long int finished;
  static struct timeval start,now,prev;
  finished+=nextchunk;
  if (start.tv_sec==0) {
    gettimeofday(&start,0); now=start; prev=start;
    return;
  }
  prev=now; gettimeofday(&now,0);
  if (prev.tv_sec!=now.tv_sec) {
    char received[FMT_ULONG], totalsize[FMT_ULONG], timedone[FMT_ULONG], percent[10];
    char speed[FMT_ULONG+20];
    size_t i,j;
#ifndef __MINGW32__
    if (dosync) fsync(fd);
#endif
    if (!dostats) return;
    if (total) {
      if (total>1000000000)
	i=finished/(total/10000);
      else
	i=finished*10000/total;
      j=fmt_ulong(percent,i/100);
      percent[j]='.';
      percent[j+1]=((i/10)%10)+'0';
      percent[j+2]=(i%10)+'0';
      percent[j+3]=0;
    } else
      strcpy(percent,"100.00");
    j=fmt_humank(received,resumeofs+finished);
    if (received[j-1]<='9') received[j++]='i';
    received[j]=0;
    j=fmt_humank(totalsize,resumeofs+total);
    if (totalsize[j-1]<='9') totalsize[j++]='i';
    totalsize[j]=0;

    if (now.tv_sec-start.tv_sec>=60) {
      j=fmt_ulong(timedone,(now.tv_sec-start.tv_sec)/60);
      timedone[j]=':';
      i=(now.tv_sec-start.tv_sec)%60;
      timedone[j+1]=(i/10)+'0';
      timedone[j+2]=(i%10)+'0';
      timedone[j+3]=0;
    } else {
      j=fmt_ulong(timedone,now.tv_sec-start.tv_sec);
      j+=fmt_str(timedone+j," sec");
      timedone[j]=0;
    }

    if (now.tv_sec-start.tv_sec>1 && total) {
      unsigned long timediff=(now.tv_sec-start.tv_sec)*100;
      timediff += (now.tv_usec-start.tv_usec)/10000;

      i=finished*100/timediff;
      j=fmt_str(speed," (");
      j+=fmt_humank(speed+j,i);
      j+=fmt_str(speed+j,"iB/sec)"+(i>1000));
      speed[j]=0;
    } else
      speed[0]=0;

    if (now.tv_sec > start.tv_sec+3 && now.tv_sec-start.tv_sec) {
      unsigned long long int bps=finished/(now.tv_sec-start.tv_sec);
      size_t k=(total-finished)/bps;
      char lm[FMT_ULONG];

      if (k>=60) {
	j=fmt_ulong(lm,k/60);
	lm[j]=':';
	i=k%60;
	lm[j+1]=(i/10)+'0';
	lm[j+2]=(i%10)+'0';
	lm[j+3]=0;
      } else {
	j=fmt_ulong(lm,k);
	j+=fmt_str(lm+j," sec");
	lm[j]=0;
      }

      buffer_putm(buffer_2,"\r",percent,"% done; got ",received,"B ");
      if (total)
	buffer_putm(buffer_2,"of ",totalsize,"B ");
      buffer_putmflush(buffer_2,"in ",timedone,speed,", ",lm," to go.    ");
    } else {
      buffer_putm(buffer_2,"\r",percent,"% done; got ",received,"B ");
      if (total)
	buffer_putm(buffer_2,"of ",totalsize,"B ");
      buffer_putmflush(buffer_2,"in ",timedone,speed,".    ");
    }
    statsprinted=1;
  }
}

static void clearstats() {
  if (statsprinted) buffer_putsflush(buffer_2,"\r\e[K");
}


static int make_connection(char* ip,uint16 port,uint32 scope_id) {
  int v6=byte_diff(ip,12,V4mappedprefix);
  int s;
  if (v6) {
    s=socket_tcp6b();
    if (socket_connect6(s,ip,port,scope_id)==-1) {
#if 0
      char a[100],b[100],c[100];
      a[fmt_ulong(a,port)]=0;
      b[fmt_ulong(b,scope_id)]=0;
      c[fmt_ip6c(c,ip)]=0;
      printf("socket_connect6(%s,%s,%s) failed!\n",c,a,b);
#endif
      carp("socket_connect6");
      close(s);
      return -1;
    }
  } else {
    s=socket_tcp4b();
    if (socket_connect4(s,ip+12,port)==-1) {
      carp("socket_connect4");
      close(s);
      return -1;
    }
  }
#ifdef TCP_NODELAY
  {
    int one=1;
    setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  }
#endif
  return s;
}

struct cookie {
  const char* domain, * path, * name, * value;
  struct cookie* next;
}* cookies;

void addcookie(const char* s,const char* curdomain) {
  struct cookie* n;
  char* x;
  char* t=strchr(s,'\n');
  if (!t) t=strchr(s,0);
  if (t>s && t[-1]=='\r') --t;
  if (case_starts(s,"set-cookie:")) {
    s += sizeof("set-cookie");
    while (*s==' ' || *s=='\t') ++s;
  }
  if (s==t) return;
  if (!(x=strndup(s,t-s))) return;
  if (!(n=malloc(sizeof(*n)))) goto kaputt2;
  n->name=x;
  while (*x && *x!='=') ++x;
  if (*x!='=') {
kaputt:
    free(n);
kaputt2:
    free(x);
    return;
  }
  *x=0;
  n->value=++x;
  while (*x && *x!=';' && *x!=' ' && *x!='\t') ++x;
  n->domain=curdomain; n->path="/";
  if (*x) {
    if (*x!=';') goto kaputt;
    *x=0;
    ++x;
    while (*x) {
      char next;
      while (*x==' ' || *x=='\t') ++x;
      if (!(t=strchr(x,';'))) t=strchr(x,0);
      next=*t; *t=0;
      if (case_starts(x,"path=")) {
	x+=sizeof("path");
	n->path=x;
      } else if (case_starts(x,"domain=")) {
	x+=sizeof("domain");
	n->domain=x;
      }
      if (!next) break;
      x=t+1;
    }
  }
  /* check if the domain is valid */
  if (n->domain != curdomain) {
    size_t i,a;
    /* n->domain must be a suffic of curdomain or the other way around */
    i=strlen(n->domain);
    a=strlen(curdomain);
    if (i<=a && case_diffs(n->domain,curdomain+a-i)) goto kaputt;
    if (a<i && case_diffs(n->domain+i-a,curdomain)) goto kaputt;
    /* can't set cookie for TLD */
    for (i=a=0; n->domain[i]; ++i)
      if (n->domain[i]=='.') ++a;
    if (a<2) goto kaputt;
    /* here we would have to check for cases like ".co.uk", but since
     * this is just a trivial downloader without persistent cookies,
     * I'll pass, knowingly breaking ".x.org" */
    if (strlen(n->domain)<sizeof(".co.uk")) goto kaputt;
  }
//  printf("Cookie: \"%s\" = \"%s\", domain=\"%s\", path=\"%s\"\n",n->name,n->value,n->domain,n->path);
  /* now see if the same cookie is already there */
  {
    struct cookie** c;
    for (c=&cookies; *c; c=&((*c)->next)) {
      if (!strcmp((*c)->name,n->name) && !strcmp((*c)->domain,n->domain)) {
	(*c)->name=n->name;
	(*c)->value=n->value;
	(*c)->path=n->path;
	(*c)->domain=n->domain;
	free(n);
	return;
      }
    }
    *c=n;
    n->next=0;
  }
}

size_t fmt_cookies(char* dest,const char* domain,const char* path) {
  struct cookie* c;
  size_t sum=0;
  size_t l=strlen(domain);
  sum+=fmt_str(dest,"Cookie: ");
  for (c=cookies; c; c=c->next) {
    size_t k=strlen(c->domain);
    if (l<k) continue;
    if (case_equals(domain+l-k,c->domain) && case_starts(path,c->path))
      sum+=fmt_strm(dest?dest+sum:0,c->name,"=",c->value,"; ");
  }
  if (sum>8) {
    if (dest) {
      dest[sum-2]='\r';
      dest[sum-1]='\n';
    }
    return sum;
  } else
    return 0;
}


struct utimbuf u;

char* location;

static int readanswer(int s,const char* filename,const char* curdomain,int onlyprintlocation,uint16_t port) {
  char buf[8192];
  int i,j,body=-1,r;
  int64 d;
  unsigned long httpcode;
  unsigned long long rest;
  int nocl;
  i=0; d=-1; httpcode=0; todel=(char*)filename;
  while ((r=read(s,buf+i,sizeof(buf)-i)) > 0) {
    i+=r;
    for (j=0; j+3<i; ++j) {
      if (buf[j]=='\r' && buf[j+1]=='\n' && buf[j+2]=='\r' && buf[j+3]=='\n') {
	unsigned long code;
	body=j+4;
	if (scan_ulong(buf+9,&code))
	  httpcode=code;
	else
	  goto kaputt;
	if (onlyprintlocation && (code/10 != 30)) return 0;
	if (ims) {
	  /* some crappy web servers (*cough* dl.google.com *cough*) do
	   * not support If-Modified-Since, so do checking ourselves */
	  size_t i;
	  for (i=0; i+sizeof("Last-Modified: Fri, 22 Jan 2010 21:00:00")<j; ++i) {
	    if (case_starts(buf+i,"Last-Modified:")) {
	      i+=sizeof("Last-Modified:");
	      while (i<j && (buf[i]==' ' || buf[i]=='\t')) ++i;
	      if (buf[i+scan_httpdate(buf+i,&u.actime)]=='\r') {
		if (u.actime<=ims) {
		  if (verbose)
		    buffer_putmflush(buffer_2,"File not modified (but server ignores If-Modified-Since), aborting download...\n");
		  close(d);
		  return 0;
		}
	      }
	    }
	  }
	}
	if ((resumeofs && code==206 && io_appendfile(&d,filename)==0) ||
	    (!resumeofs && code==200 && ((strcmp(filename,""))?io_createfile(&d,filename)==0:((d=1)-1))))
	  panic("creat");
	if (d==-1) {
	  if (httpcode==301 || httpcode==302 || httpcode==303) {
	    char* l=buf;
	    buf[r]=0;
	    /* extract cookies */
	    while ((l=strchr(l,'\n'))) {
	      ++l;
	      if (case_starts(l,"set-cookie:"))
		addcookie(l,curdomain);
	    }
	    /* extract and go to location */
	    if ((l=strstr(buf,"\nLocation:"))) {
	      l+=10;
	      while (*l == ' ' || *l == '\t') ++l;
	      location=l;
	      while (*l && *l != '\r' && *l != '\n') ++l;
	      *l=0;
	      if (*location=='/') {
		char portbuf[FMT_ULONG];
		l=location;
		/* *sigh* relative redirect, take parts from old url */
		location=malloc(l-location+strlen(curdomain)+100);
		if (location) {
		  portbuf[fmt_ulong(portbuf,port)]=0;
		  location[fmt_strm(location,"http://",curdomain,":",portbuf,l)]=0;
		}
	      } else
		location=strndup(location,l-location);
	      return -2;
	    }
	    return -1;
	  }
	  for (j=0; buf[j]!='\n'; ++j) ;
	  write(2,buf,j+1);
	  return 0;
	}
	if (i-j-4)
	  if (write(d,buf+body,i-j-4)!=i-j-4) panic("write");
	break;
      }
    }
    if (body!=-1) {
      if (byte_diff(buf,7,"HTTP/1.")) {
kaputt:
	buffer_putsflush(buffer_2,"invalid HTTP response!\n");
	return -1;
      }
      break;
    }
  }
  if (r==-1) return -1;
  if (d==1) dostats=!isatty(1);
  if (httpcode!= (resumeofs?206:200)) return 0;
  rest=-1; nocl=1;
  buf[r]=0;
  for (j=0; j<r; j+=str_chr(buf+j,'\n')) {
    if (j+17<r && case_equalb(buf+j,17,"\nContent-Length: ")) {
      char* c=buf+j+17;
      if (c[scan_ulonglong(c,&rest)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Content-Length header!\n");
	return -1;
      }
      nocl=0;
    } else if (j+16<r && case_equalb(buf+j,16,"\nLast-Modified: ")) {
      char* c=buf+j+16;
      if (c[scan_httpdate(c,&u.actime)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Last-Modified header!\n");
	return -1;
      }
    }
    ++j;
  }
  total=rest;
  rest-=(r-body);
  printstats(total-rest,d);
  while (nocl || rest) {
    r=read(s,buf,nocl?sizeof(buf):(rest>sizeof(buf)?sizeof(buf):rest));
    if (r<1) {
      if (r==-1)
	carp("read from HTTP socket");
      else {
	if (ignoreeof) nocl=1;
	if (nocl) break;
	buffer_puts(buffer_2,"early HTTP EOF; expected ");
	buffer_putulong(buffer_2,rest);
	buffer_putsflush(buffer_2," more bytes!\n");
	return -1;
      }
    } else {
      printstats(r,d);
      if (write(d,buf,r)!=r)
	panic("write");
      rest-=r;
    }
  }
  close(d);
  chmod(filename,0644);
  return 0;
}

static stralloc ftpresponse;

static int readftpresponse(buffer* b) {
  char c;
  int i,res,cont=0,num;
  if (!stralloc_copys(&ftpresponse,"")) panic("malloc");
  for (i=res=0; i<3; ++i) {
    if (buffer_getc(b,&c)!=1) panic("ftp command response read error");
    if (c<'0' || c>'9') panic("invalid ftp command response\n");
    res=res*10+c-'0';
  }
  num=3;
  for (i=3; ; ++i) {
    if (buffer_getc(b,&c)!=1) panic("ftp command response read error");
    if (!stralloc_append(&ftpresponse,&c)) panic("malloc");
    if (i==0) {
      cont=0; num=0;
      if (c==' ' || c=='\t') cont=1;
    }
    if (i<3 && c>='0' && c<='9') ++num;
    if (i==3 && num==3) cont=(c=='-');
    if (c=='\n') {
      if (cont) i=-1; else break;
    }
  }
  return res;
}

static int ftpcmd(int s,buffer* b,const char* cmd) {
  int l=str_len(cmd);
  if (write(s,cmd,l)!=l) panic("ftp command write error");
  return readftpresponse(b);
}

static int ftpcmd2(int s,buffer* b,const char* cmd,const char* param) {
  int l=str_len(cmd);
  int l2=str_len(param);
#ifdef __MINGW32__
  char* buf=alloca(l+l2+3);
  memcpy(buf,cmd,l);
  memcpy(buf+l,param,l2);
  memcpy(buf+l+l2,"\r\n",2);
  if (write(s,buf,l+l2+2)!=l+l2+2) panic("ftp command write error");
#else
  struct iovec v[3];
  v[0].iov_base=(char*)cmd;	v[0].iov_len=l;
  v[1].iov_base=(char*)param;	v[1].iov_len=l2;
  v[2].iov_base="\r\n";		v[2].iov_len=2;
  if (writev(s,v,3)!=l+l2+2) panic("ftp command write error");
#endif
  return readftpresponse(b);
}

static int scan_int2digit(const char* s, int* i) {
  if (s[0]<'0' || s[0]>'9' || s[1]<'0' || s[1]>'9') return 0;
  *i=(s[0]-'0')*10 + s[1]-'0';
  return 2;
}

static inline int issafe(unsigned char c) {
  return (c!='"' && c>' ' && c!='+');
}

size_t fmt_urlencoded(char* dest,const char* src,size_t len) {
  register const unsigned char* s=(const unsigned char*) src;
  unsigned long written=0,i;
  for (i=0; i<len; ++i) {
    if (!issafe(s[i])) {
      if (dest) {
	dest[written]='%';
	dest[written+1]=fmt_tohex(s[i]>>4);
	dest[written+2]=fmt_tohex(s[i]&15);
      }
      written+=3;
    } else {
      if (dest) dest[written]=s[i]; ++written;
    }
  }
  return written;
}

static int validatesmb(char* buf,size_t wanted,unsigned char type,unsigned char wordcount,
		unsigned short bytecount,unsigned short tid,unsigned short mid) {
  if (wanted<wordcount*2+0x23+bytecount) return -1;	// too short?
  if (!byte_equal(buf,4,"\xffSMB")) return -1;		// SMB magic?
  if ((unsigned char)buf[4]!=type) return -1;				// wrong message type?
  if (uint16_read(buf+12)!=0) return -1;		// process id high == 0?
  if (uint16_read(buf+24)!=tid) return -1;		// right tree id?
  if (uint16_read(buf+26)!=23) return -1;		// right process id?
  if (uint16_read(buf+30)!=mid) return -1;		// right multiplex id?
  if (buf[0x20]<wordcount) return -1;
  if (uint16_read(buf+0x20+wordcount*2)<bytecount) return -1;
  if (wanted<wordcount*2+0x22+uint16_read(buf+0x21+wordcount*2)) return -1;	// too short
  return 0;
}

static void readnetbios(buffer* b,char* buf,size_t* wanted) {
  if (buffer_get(b,buf,4)!=4) panic("short read\n");
  *wanted=(unsigned char)buf[1] * 65535 +
	  (unsigned char)buf[2] * 256 +
	  (unsigned char)buf[3];
}

static int negotiatesocksconnection(int sock,const char* host,unsigned short port,char* sockname,unsigned short* socknameport) {
  char buf[300];
  size_t hl=strlen(host);
  if (verbose)
    buffer_putsflush(buffer_1,"SOCKS handshake... ");
  /* version 5, 1 auth method, auth method none */
  if (write(sock,"\x05\x01\x00",3)!=3 ||
      read(sock,buf,2)!=2 ||
      buf[0]!=5 || buf[1]!=0) {
    buffer_putsflush(buffer_2,"dl: SOCKS handshake failed\n");
    return -1;
  }
  if (verbose)
    buffer_putsflush(buffer_1,"SOCKS connect... ");
  /* version 5, command: connect (1), reserved (0), address type: domain name (3) */
  memcpy(buf,"\x05\x01\x00\x03",4);
  if (hl>255) {
    buffer_putsflush(buffer_2,"dl: host name too long (SOCKS only supports up to 255)\n");
    return -1;
  }
  buf[4]=hl;
  memcpy(buf+5,host,hl);
  uint16_pack_big(buf+5+hl,port);
  if (write(sock,buf,5+hl+2)!=5+hl+2 ||
    read(sock,buf,4)!=4 ||
    buf[0]!=5 || buf[2]!=0) {
kaputt:
    buffer_putsflush(buffer_2,"dl: received invalid reply to SOCKS connect request\n");
    return -1;
  }
  switch (buf[1]) {
  case 0: errno=0; break;
  case 2: errno=EACCES; break;
  case 3: errno=ENETUNREACH; break;
  case 4: errno=EHOSTUNREACH; break;
  case 5: errno=ECONNREFUSED; break;
  case 6: errno=ETIMEDOUT; break;
  default: errno=EINVAL;
  }
  if (errno) panic("SOCKS connect");
  {
    size_t r;
    switch (buf[3]) {
    case 1: r=6; break;
    case 4: r=18; break;
    default:
      goto kaputt;
    }
    if (read(sock,buf+4,r)!=r) goto kaputt;
    if (verbose) {
      if (buf[3]==1) {
	if (sockname) {
	  memcpy(sockname,V4mappedprefix,12);
	  memcpy(sockname+12,buf+4,4);
	}
	if (socknameport) *socknameport=uint16_read_big(buf+4+4);
	buf[100+fmt_ip4(buf+100,buf+4)]=0;
	buf[200+fmt_ulong(buf+200,uint16_read_big(buf+4+4))]=0;
      } else if (buf[3]==4) {
	if (sockname) memcpy(sockname,buf+4,16);
	if (socknameport) *socknameport=uint16_read_big(buf+4+16);
	buf[100+fmt_ip6(buf+100,buf+4)]=0;
	buf[200+fmt_ulong(buf+200,uint16_read_big(buf+4+16))]=0;
      }
      buffer_putmflush(buffer_1,"success! Bound to ",buf+100," port ",buf+200,".\n");
    }
  }
  return 0;
}

static void fmt_num2(char *dest,int i) {
  dest[0]=i/10+'0';
  dest[1]=i%10+'0';
}

int main(int argc,char* argv[]) {
  int useport=0;
  int usev4=0;
  int newer=0;
  int resume=0;
  int keepalive=0;
  int imode=0;
  int longlist=0;
  int onlyprintlocation=0;
  char ip[16];
  uint16 port=80, proxyport=0, connport=0, socksport=1080;
  uint32 scope_id=0;
  stralloc ips={0};
  int s;
  char* request=0;
  int rlen=0;
  char* filename=0;
  char* pathname=0;
  char* output=0;
  char* useragent="dl/1.0";
  char* referer=0;
  enum {HTTP, FTP, SMB} mode;
  int skip;
  buffer ftpbuf;
  char* host,* proxyhost=0,* connhost=0;
  char* socksproxyhost=0;
  char externalsocksip[16];
  unsigned short externalsocksport;

#if 0
  addcookie("Set-cookie: RMID=0478b6d1254f4816a29724b0; expires=Wednesday, 29-Apr-2009 04:22:47 GMT; path=/; domain=.nytimes.com\r\n","www.nytimes.com");
  addcookie("Set-cookie: NYT_GR=4816a747-xr4Bk90ylLV96+EIoKqc+A; path=/; domain=.nytimes.com","www.nytimes.com");
  addcookie("Set-cookie: NYT-S=0MOZ7vC0h8ZsDDXrmvxADeHCpDcwlNkC5FdeFz9JchiAI6GpR90PNu0YV.Ynx4rkFI; path=/; domain=.nytimes.com","www.nytimes.com");
  {
    char buf[1024];
    size_t l;
    l=fmt_cookies(0,"www.nytimes.com","/2008/04/29/washington/29scotus.html?partner=rssnyt&emc=rss");
    printf("l=%zu\n",l);
    if (l<1024) {
      buf[fmt_cookies(buf,"www.nytimes.com","/2008/04/29/washington/29scotus.html?partner=rssnyt&emc=rss")]=0;
      printf("buf=\"%s\" (%zu)\n",buf,strlen(buf));
    }
  }
#endif

  dostats=isatty(2);

#ifndef __MINGW32__
  signal(SIGPIPE,SIG_IGN);
#endif

  for (;;) {
    int c=getopt(argc,argv,"i:ko4nvra:O:U:R:lsLI");
    if (c==-1) break;
    switch (c) {
    case 'k':
      keepalive=1;
      break;
    case 'I':
      ignoreeof=1;
      break;
    case 'n':
      newer=1;
      break;
    case 'i':
      {
	struct stat ss;
	if (stat(optarg,&ss)==0) {
	  ims=ss.st_mtime;
	  imode=1;
	}
      }
      break;
    case 'r':
      resume=1;
      break;
    case 'o':
      useport=1;
      break;
    case '4':
      usev4=1;
      break;
    case 'v':
      verbose=1;
      break;
    case 'O':
      output=optarg;
      break;
    case 'U':
      useragent=optarg;
      break;
    case 'R':
      referer=optarg;
      break;
    case 'l':
      onlyprintlocation=1;
      break;
    case 's':
      dosync=1;
      break;
    case 'L':
      longlist=1;
      break;
    case 'a':
#ifndef __MINGW32__
      {
	unsigned long n;
	signal(SIGALRM,alarm_handler);
	if (optarg[scan_ulong(optarg,&n)]==0)
	  alarm(n);
	break;
      }
#endif
    case '?':
usage:
      buffer_putsflush(buffer_2,"usage: dl [-i file] [-no4v] url\n"
		       "	-i fn	only fetch file if it is newer than fn\n"
		       "	-n	only fetch file if it is newer than local copy\n"
		       "	-r	resume\n"
		       "	-4	use PORT and PASV instead of EPRT and EPSV, only connect using IPv4\n"
		       "	-o	use PORT and EPRT instead of PASV and EPSV\n"
		       "	-a n	abort after n seconds\n"
		       "	-O fn	write output to fn\n"
		       "	-U s	set User-Agent HTTP header\n"
		       "	-R s	set Referer HTTP header\n"
		       "	-l	just print value of Location: header\n"
		       "	-L	long ftp directory listing, not just names\n"
		       "	-s	sync after local write\n"
		       "	-I	do not treat early HTTP EOF as error\n"
		       "	-v	be verbose\n");
      return 0;
    }
  }
#ifdef __MINGW32__
  _fmode=O_BINARY;
#endif

  if (!argv[optind]) goto usage;
again:
  {
    static int redirects=0;
    if (++redirects>5) panic("too many redirects!\n");
  }

  {	// unescape url
    size_t i,j;
    i=scan_urlencoded2(argv[optind],argv[optind],&j);
    if (argv[optind][i]) panic("invalid urlencoding in url!\n");
    argv[optind][j]=0;
  }

  mode=HTTP;
  if (byte_diff(argv[optind],skip=7,"http://")) {
    if (byte_diff(argv[optind],skip=6,"ftp://")) {
      if (byte_diff(argv[optind],skip=6,"smb://")) goto usage;
      mode=SMB;
      port=445;
    } else {
      mode=FTP;
      proxyhost=getenv("ftp_proxy");
      port=21;
    }
  } else
    proxyhost=getenv("http_proxy");
  socksproxyhost=getenv("SOCKS5_SERVER");
  if (!socksproxyhost) socksproxyhost=getenv("SOCKS_SERVER");
  if (socksproxyhost) {
    char* c=strchr(socksproxyhost,':');
    if (c) {
      *c=0;
      if (c[1+scan_ushort(c+1,&socksport)]) {
	buffer_putsflush(buffer_2,"invalid socks proxy environment syntax\n");
	return 1;
      }
    }
  }

  /* do we have a proxy? */
  if (proxyhost && !proxyport) {
    size_t i;
    /* expect format "http://localhost:3128" */
    if (byte_equal(proxyhost,7,"http://")) proxyhost+=7;
    i=str_chr(proxyhost,'/');
    if (proxyhost[i]=='/') proxyhost[i]=0;
    i=str_rchr(proxyhost,':');
    if (proxyhost[i]!=':' ||
        proxyhost[i+1+scan_ushort(proxyhost+i+1,&proxyport)]) {
      buffer_putsflush(buffer_2,"invalid proxy environment syntax\n");
      return 1;
    }
    proxyhost[i]=0;
    connhost=proxyhost;
    connport=proxyport;
    mode=HTTP;
  }

  {
    int colon;
    int slash;
    char* c;
    host=argv[optind]+skip;
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
      if (c[scan_ushort(c,&port)]!='/') goto usage;
      *c=0;
    }
//    host[colon]=0;
    c=host+slash;
    pathname=c;
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
	  buffer_puts(buffer_2,"dl: warning: network interface ");
	  buffer_puts(buffer_2,host+tmp+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      }
    }

    if (!proxyhost) {
      connhost=host;
      connport=port;
    }

    {
      struct addrinfo hints, *ai, *aitop;
      int gaierr;
      char p[FMT_ULONG];
      const char* tolookup=socksproxyhost?socksproxyhost:connhost;
      p[fmt_ulong(p,connport)]=0;
      memset(&hints,0,sizeof(hints));
      hints.ai_family=AF_UNSPEC;
      hints.ai_flags=0;
      hints.ai_socktype=0;

      ips.len=0;
      if ((gaierr=scan_ip6(tolookup,ip)) && tolookup[gaierr]==0) {
	/* ip given, no dns needed */
	stralloc_catb(&ips,ip,16);
	goto nodns;
      }
      if (verbose) buffer_putsflush(buffer_1,"DNS lookup... ");
      if ((gaierr = getaddrinfo(tolookup,p,&hints,&aitop)) != 0 || !aitop) {
	buffer_puts(buffer_2,"dl: could not resolve IP: ");
	buffer_puts(buffer_2,tolookup);
	buffer_putnlflush(buffer_2);
	return 1;
      }
      ai=aitop;
      while (ai) {
	uint32_t scopeid;
	if (ai->ai_family==AF_INET6) {
	  char* addr;
	  stralloc_catb(&ips,addr=(char*)&(((struct sockaddr_in6*)ai->ai_addr)->sin6_addr),16);
	  scopeid=((struct sockaddr_in6*)ai->ai_addr)->sin6_scope_id;
	  if (scopeid==0 || byte_diff(addr,8,"\xfe\x80\x00\x00\x00\x00\x00\x00")) scopeid=scope_id;
	} else {
	  stralloc_catb(&ips,V4mappedprefix,12);
	  stralloc_catb(&ips,(char*)&(((struct sockaddr_in*)ai->ai_addr)->sin_addr),4);
	  scopeid=0;
	}
	stralloc_catb(&ips,(char*)&scopeid,4);
	ai=ai->ai_next;
      }
      if (verbose) buffer_putsflush(buffer_1,"done\n");
    }
nodns:

    if (output)
      filename=strcmp(output,"-")?output:"";
    else
      filename=c+str_rchr(c,'/')+1;
    if (resume || newer) {
      struct stat ss;
      if (stat(filename,&ss)==0) {
	if (resume) {
	  resumeofs=ss.st_size;
	  if (verbose) {
	    buffer_puts(buffer_1,"Resuming from ");
	    buffer_putulonglong(buffer_1,resumeofs);
	    buffer_putsflush(buffer_1,"...\n");
	  }
	} else if (newer) {
	  if (verbose) buffer_putsflush(buffer_1,"Found old file as If-Modified-Since reference.\n");
	  ims=ss.st_mtime;
	}
      } else
	resume=0;
    }

    if (mode==HTTP) {
      size_t cookielen=fmt_cookies(0,host,c);
      size_t referlen=referer?str_len(referer)+20:0;
      if (proxyhost) c=argv[optind];
      request=malloc(300+str_len(host)+3*str_len(c)+str_len(useragent)+referlen+cookielen);

      if (!request) panic("malloc");
      {
	int i;
	if (onlyprintlocation)
	  i=fmt_str(request,"HEAD ");
	else
	  i=fmt_str(request,"GET ");
	i+=fmt_urlencoded(request+i,c,str_len(c));
	i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
	i+=fmt_str(request+i,host);
	if (port!=80) {
	  i+=fmt_str(request+i,":");
	  i+=fmt_ulong(request+i,port);
	}
	if (ims) {
	  i+=fmt_str(request+i,"\r\nIf-Modified-Since: ");
	  i+=fmt_httpdate(request+i,ims);
	}
	if (resumeofs) {
	  i+=fmt_str(request+i,"\r\nRange: bytes=");
	  i+=fmt_ulonglong(request+i,resumeofs);
	  i+=fmt_str(request+i,"-");
	}
	i+=fmt_str(request+i,"\r\nAccept: */*\r\nUser-Agent: ");
	i+=fmt_str(request+i,useragent);
	if (referer) {
	  i+=fmt_str(request+i,"\r\nReferer: ");
	  i+=fmt_str(request+i,referer);
	}
	i+=fmt_str(request+i,"\r\nConnection: ");
	i+=fmt_str(request+i,keepalive?"keep-alive":"close");
	i+=fmt_str(request+i,"\r\n");
	i+=fmt_cookies(request+i,host,c);
	i+=fmt_str(request+i,"\r\n");
	rlen=i; request[rlen]=0;
      }
    }
  }

  {
    int i;
    s=-1;
    for (i=0; i+20<=ips.len; i+=20) {
      uint32_t scopeid;
      if (usev4 && !ip6_isv4mapped(ips.s+i)) continue;
      if (verbose) {
	char buf[IP6_FMT];
	buffer_puts(buffer_1,"connecting to ");
	buffer_put(buffer_1,buf,fmt_ip6c(buf,ips.s+i));
	buffer_puts(buffer_1," port ");
	buffer_putulong(buffer_1,socksproxyhost?socksport:connport);
	buffer_putnlflush(buffer_1);
      }
      byte_copy((char*)&scopeid,4,ips.s+i+16);
      s=make_connection(ips.s+i,socksproxyhost?socksport:connport,scopeid);
      if (s!=-1) {
	byte_copy(ip,16,ips.s+i);
	break;
      }
    }
    if (s==-1)
      return 1;
  }
  /* connected; if we are in socks mode, negotiate connection */
  if (socksproxyhost)
    if (negotiatesocksconnection(s,connhost,connport,externalsocksip,&externalsocksport))
      return 1;

  if (mode==HTTP) {
    if (write(s,request,rlen)!=rlen) panic("write");
    switch (readanswer(s,filename,host,onlyprintlocation,port)) {
    case -1: exit(1);
    case -2: free(referer);
	     referer=strdup(argv[optind]);
	     argv[optind]=location;
	     if (onlyprintlocation) {
	       buffer_puts(buffer_1,location);
	       buffer_putnlflush(buffer_1);
	       return 0;
	     }
	     if (verbose) {
	       buffer_puts(buffer_1,"redirected to ");
	       buffer_puts(buffer_1,location);
	       buffer_putsflush(buffer_1,"...\n");
	     }
	     location=0;
	     goto again;
    }

  } else if (mode==FTP) {
    char ip3[16];
    char buf[2048];
    int i;
    int srv=-1,dataconn=-1;
    buffer_init(&ftpbuf,(void*)read,s,buf,sizeof buf);
    if (verbose) buffer_putsflush(buffer_1,"Waiting for FTP greeting...");
    if ((readftpresponse(&ftpbuf)/100)!=2) panic("no 2xx ftp greeting.\n");
    if (verbose) buffer_putsflush(buffer_1,"\nUSER anonymous...");
    if ((i=(ftpcmd(s,&ftpbuf,"USER anonymous\r\n")/100))>3) panic("ftp login failed.\n");
    if (i!=2) {
      if (verbose) buffer_putsflush(buffer_1,"\nPASS luser@...");
      if ((i=(ftpcmd(s,&ftpbuf,"PASS luser@\r\n")/100))!=2) panic("ftp login failed.\n");
    }

    if (verbose) buffer_putsflush(buffer_1,"\nTYPE I");
    if ((i=(ftpcmd(s,&ftpbuf,"TYPE I\r\n")/100))!=2) panic("Switching to binary mode failed.\n");

    if (verbose) {
      buffer_puts(buffer_1,"\nMDTM ");
      buffer_puts(buffer_1,pathname);
      buffer_putsflush(buffer_1,"... ");
    }
    if (ftpcmd2(s,&ftpbuf,"MDTM ",pathname)==213) {
      char* c=ftpresponse.s+1;
      struct tm t;
      int ok=1;
      if (ftpresponse.len>15) {
	int i=0;
	if (c[0]=='1' && c[1]=='9' && c[15]>='0') {
	  /* y2k bug; "19100" instead of "2000" */
	  if (scan_int2digit(c+3,&i)!=2) ok=0;
	  t.tm_year=i;
	  ++c;
	} else {
	  if (scan_int2digit(c,&i)!=2) ok=0;
	  t.tm_year=i*100;
	  if (scan_int2digit(c+2,&i)!=2) ok=0;
	  t.tm_year+=i;
	  t.tm_year-=1900;
	}
	c+=4;
	if (scan_int2digit(c   ,&i)!=2) ok=0; t.tm_mon=i-1;
	if (scan_int2digit(c+2 ,&i)!=2) ok=0; t.tm_mday=i;
	if (scan_int2digit(c+4 ,&i)!=2) ok=0; t.tm_hour=i;
	if (scan_int2digit(c+6 ,&i)!=2) ok=0; t.tm_min=i;
	if (scan_int2digit(c+8 ,&i)!=2) ok=0; t.tm_sec=i;
	if (c[10]!='\r') ok=0;
	if (ok) {
	  time_t r=mktime(&t);
	  u.actime=r;
	  if (verbose) buffer_putsflush(buffer_1,"ok.\n");
	  if (ims && r<=ims) {
	    if (verbose) buffer_puts(buffer_1,"Remote file is not newer, skipping download.");
	    goto skipdownload;
	  }
	} else
	  if (verbose) buffer_putsflush(buffer_1,"could not parse MDTM response.\n");
      } else
	if (verbose) buffer_putsflush(buffer_1,"invalid response format.\n");
    } else
      if (verbose) buffer_putsflush(buffer_1,"failed.\n");

    if (resume) {
      char* buf=alloca(str_len(filename)+10);
      int i;
      i=fmt_str(buf,"REST ");
      i+=fmt_ulonglong(buf+i,resumeofs);
      i+=fmt_str(buf+i,"\r\n");
      buf[i]=0; ++i;
      if (verbose) {
	buffer_put(buffer_1,buf,i-3);
	buffer_putsflush(buffer_1,"... ");
      }
      if (ftpcmd(s,&ftpbuf,buf)!=350) {
	buffer_putsflush(buffer_1,verbose?"FAILED!\n":"Resume failed!\n");
	exit(1);
      }
    }

    if (useport) {
      uint16 port;
      char ip2[16];
      char buf[200];
      if (usev4) {
	int i,j;
	/* TODO: if (socksproxyhost) socks_bind_request (rfc1928) */
	srv=socket_tcp4b();
	if (srv==-1) panic("socket");
	socket_listen(srv,1);
	if (socket_local4(s,ip2,0)) panic("getsockname");
	if (socket_local4(srv,0,&port)) panic("getsockname");
	i=fmt_str(buf,"PORT ");
	for (j=0; j<4; ++j) {
	  i+=fmt_uint(buf+i,ip2[j]&0xff);
	  i+=fmt_str(buf+i,",");
	}
	i+=fmt_uint(buf+i,port>>8);
	i+=fmt_str(buf+i,",");
	i+=fmt_uint(buf+i,port&0xff);
	i+=fmt_str(buf+i,"\r\n");
	buf[i]=0;
	if (verbose) buffer_putsflush(buffer_1,buf);
	if (ftpcmd(s,&ftpbuf,buf) != 200) panic("PORT reply is not 200\n");
      } else {
	int i;
	/* TODO: if (socksproxyhost) socks_bind_request (rfc1928) */
	srv=socket_tcp6b();
	if (srv==-1) panic("socket");
	socket_listen(srv,1);
	if (socket_local6(s,ip2,0,0)) panic("getsockname");
	if (socket_local6(srv,0,&port,0)) panic("getsockname");
	i=fmt_str(buf,"EPRT |");
	if (byte_equal(ip2,12,V4mappedprefix))
	  i+=fmt_str(buf+i,"1|");
	else
	  i+=fmt_str(buf+i,"2|");
	i+=fmt_ip6c(buf+i,ip2);
	i+=fmt_str(buf+i,"|");
	i+=fmt_ulong(buf+i,port);
	i+=fmt_str(buf+i,"|\r\n");
	buf[i]=0;
	if (verbose) buffer_putsflush(buffer_1,buf);
	if (ftpcmd(s,&ftpbuf,buf) != 200) panic("EPRT reply is not 200\n");
      }
    } else {
      int srv;
tryv4:
      if (usev4) {
	int i;
	if (verbose) buffer_putsflush(buffer_1,"PASV... ");
	if (ftpcmd(s,&ftpbuf,"PASV\r\n")!=227) panic("PASV reply is not 227\n");
	/* Passive Mode OK (127,0,0,1,204,228) */
	for (i=0; i<ftpresponse.len-1; ++i) {
	  if (ftpresponse.s[i]==',' && ftpresponse.s[i+1]>='0' && ftpresponse.s[i+1]<='9') {
	    unsigned long j;
	    if (scan_ulong(ftpresponse.s+i+1,&j) && j<256)
	      port=port*256+j;
	  }
	}
	/* TODO: if (socksproxyhost) socks_connect (rfc1928) */
	if ((srv=socket_tcp4b())==-1) panic("socket");
	if (verbose) buffer_putsflush(buffer_1,"connecting... ");
	if (socket_connect4(srv,ip+12,port)==-1) panic("connect");
	if (verbose) buffer_putsflush(buffer_1,"done.\n");
	dataconn=srv;
      } else {
	if (verbose) buffer_putsflush(buffer_1,"EPSV... ");
	if (ftpcmd(s,&ftpbuf,"EPSV\r\n")!=229) {
	  usev4=1;
	  goto tryv4;
	  panic("EPSV reply is not 229\n");
	}
	/* Passive Mode OK (|||52470|) */
	for (i=0; i<ftpresponse.len-1; ++i) {
	  if (ftpresponse.s[i]>='0' && ftpresponse.s[i]<='9') {
	    unsigned long j;
	    if (scan_ulong(ftpresponse.s+i,&j) && j<65536) {
	      port=j;
	      break;
	    }
	  }
	}
	/* TODO: if (socksproxyhost) socks_connect (rfc1928) */
	if ((srv=socket_tcp6b())==-1) panic("socket");
	if (verbose) buffer_putsflush(buffer_1,"connecting... ");
	if (socket_connect6(srv,ip,port,scope_id)==-1) panic("connect");
	if (verbose) buffer_putsflush(buffer_1,"done.\n");
	dataconn=srv;
      }
    }
    if (!filename[0]) {
      if (verbose) {
	buffer_puts(buffer_1,"CWD ");
	buffer_puts(buffer_1,pathname);
	buffer_putsflush(buffer_1,"... ");
      }
      if ((ftpcmd2(s,&ftpbuf,"CWD ",pathname)/100)!=2) goto tryretr;
      if (longlist) {
	if (verbose) buffer_putsflush(buffer_2,"\nLIST\n");
	if (((i=ftpcmd(s,&ftpbuf,"LIST\r\n"))!=150) && i!=125) panic("No 125/150 response to LIST\n");
      } else {
	if (verbose) buffer_putsflush(buffer_2,"\nNLST\n");
	if (((i=ftpcmd(s,&ftpbuf,"NLST\r\n"))!=150) && i!=125) panic("No 125/150 response to NLST\n");
      }
    } else
tryretr:
    {
      int i;
      if (verbose) {
	buffer_puts(buffer_1,"RETR ");
	buffer_puts(buffer_1,pathname);
	buffer_putsflush(buffer_1,"... ");
      }
      if (((i=ftpcmd2(s,&ftpbuf,"RETR ",pathname))!=150) && i!=125) {
	stralloc_0(&ftpresponse);
	buffer_puts(buffer_2,"dl: RETR failed:");
	buffer_putsaflush(buffer_2,&ftpresponse);
	return 1;
      }
      if (verbose) buffer_putsflush(buffer_1,"ok.  Downloading...\n");
      total=0;
      if (stralloc_0(&ftpresponse)) {
	char* c=strchr(ftpresponse.s,'(');
	if (c) {
	  ++c;
	  if (!scan_ulonglong(c,&total))
	    total=0;
	}
      }
    }

    /* if we were in active mode, accept connection now */
    if (useport) {
      if (usev4) {
	if (verbose) buffer_putsflush(buffer_1,"Waiting for connection...");
	dataconn=socket_accept4(srv,ip3,0);
	if (verbose) buffer_putsflush(buffer_1," there it is.\n");
	if (byte_diff(ip3,4,ip+12)) panic("PORT stealing attack!\n");
      } else {
	if (verbose) buffer_putsflush(buffer_1,"Waiting for connection...");
	dataconn=socket_accept6(srv,ip3,0,0);
	if (verbose) buffer_putsflush(buffer_1," there it is.\n");
	if (byte_diff(ip3,16,ip)) panic("EPRT stealing attack!\n");
      }
      close(srv);
    }

    {
      char buf[8192];
      unsigned int l;
      int64 d;
      if (filename[0]) {
	if ((resume?io_appendfile(&d,filename):io_createfile(&d,filename))==0)
	  panic("creat");
      } else {
	d=1;
	dostats=!isatty(1);
      }
      while ((l=read(dataconn,buf,sizeof buf))>0) {
	printstats(l,d);
	if (d==1) {
	  unsigned int i,j;
	  for (i=j=0; i<l; ++i)
	    if (buf[i]!='\r') {
	      buf[j]=buf[i];
	      ++j;
	    }
	  l=j;
	}
	if (write(d,buf,l) != l) panic("short write");
      }
      if (l==-1) panic("read");
      if (d!=1) close(d);
    }
    close(dataconn);
    if (verbose) buffer_putsflush(buffer_1,"Download finished... Waiting for server to acknowledge... ");
    if ((readftpresponse(&ftpbuf)/100)!=2) panic("no 2xx ftp retr response.\n");
skipdownload:
    if (verbose) buffer_putsflush(buffer_1,"\nQUIT\n");
    ftpcmd(s,&ftpbuf,"QUIT\r\n");

  } else if (mode==SMB) {

    unsigned int mid=4;
    char inbuf[65*1024];
    char buf[8192];
    char* readbuf;
    char domain[200];
    size_t dlen;
    size_t wanted;
    unsigned short uid,tid,fid;
    size_t readsize;
    unsigned long long filesize;
    buffer ib=BUFFER_INIT(read,s,inbuf,sizeof(inbuf));

    /* Step 1: Negotiate dialect.  We only offer one */
    if (verbose) buffer_putsflush(buffer_1,"Negotiating SMB dialect... ");
    if (write(s,"\x00\x00\x00\x2f"	// NetBIOS
	        "\xffSMB"		// SMB
		"\x72\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x01\x00\x00\x0c"
		"\x00\x02NT LM 0.12",0x2f+4)!=0x2f+4) panic("Protocol negotiation request short write\n");

    readnetbios(&ib,buf,&wanted);

    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Protocol negotiation response short read\n");
    if (validatesmb(buf,wanted,0x72,17,0,0,1)) panic("Received invalid SMB response\n");
    if (uint16_read(buf+0x21)!=0) panic("Server requested invalid dialect\n");

    {
      char* x=buf+0x20+2*17;
      char* max=x+3+uint16_read(x+1);
      x+=3+(unsigned char)x[0];
      if (max>x && max-x<sizeof(domain)) {
	dlen=max-x;			// we are opportunistic bastards
	byte_copy(domain,dlen,x);	// in session setup we claim to come from the server's workgroup
	if (verbose) {
	  int i;
	  buffer_puts(buffer_1,"ok, got domain \"");
	  for (i=0; i<dlen; i+=2) {
	    if (domain[i+1] || !isprint(domain[i])) {
	      if (domain[i]==0) break;
	      buffer_put(buffer_1,".",1);
	    } else
	      buffer_put(buffer_1,domain+i,1);
	  }
	  buffer_putsflush(buffer_1,"\".\nSession Setup... ");
	}
      } else
	dlen=0;
    }

    if ((buf[0x33]&0x40)==0x40)
      readsize=64000;
    else {
      readsize=uint32_read(buf+0x27);
      if (readsize>64000) readsize=64000;
    }
    readbuf=malloc(readsize+300);
    if (!readbuf) panic("out of memory");

    /* Step 2: Session Setup. */
    {
      char *x;
      static char req[300]=
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\x73\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x02\x00\x0d\xff"
		"\x00\x00\x00\xff\xff\x02\x00\x17\x00\x17"
		"\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00"
		"\x00\x5c\x00\x00\x00"
		"\x00\x00"	// byte count
		"\x00\x00\x00"
		"G\x00U\x00""E\x00S\x00T\x00\x00\x00";	// "GUEST"
      size_t i;
      x=req+8+50+5+2+3+6*2;
      if (dlen) {
	byte_copy(x,dlen,domain);
	x+=dlen;
      }
      byte_copy(x,11,"U\x00n\x00i\x00x\x00\x00\x00\x00");
      x+=11;
      for (i=0; useragent[i]; ++i) {
	*x++=useragent[i];
	*x++=0;
      }
      x[0]=x[1]=x[2]=0;
      x+=3;
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+50+5;
	uint16_pack(y,x-y-2);
      }
      if (write(s,req,x-req) != x-req) panic("Session Setup request short write");
    }

    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Session Setup response short read\n");
    if (validatesmb(buf,wanted,0x73,3,0,0,2)) panic("Received invalid SMB response\n");
    uid=uint16_read(buf+0x1c);

    if (verbose) {
      char* x,*y, * max;
      x=buf+0x20;
      x+=1+(unsigned char)x[0]*2;
      max=x+2+uint16_read(x);
      buffer_puts(buffer_1,"ok");
      x+=2;
      if ((uintptr_t)x&1) ++x;
      y=x;
      while (y<max && *y) y+=2;
      y+=2;
      if (y<max) {
	buffer_puts(buffer_1,", server \"");
	while (y<max) {
	  if (y[1] || !isprint(y[0])) {
	    if (!y[0]) break;
	    buffer_put(buffer_1,".",1);
	  } else
	    buffer_put(buffer_1,y,1);
	  y+=2;
	}
	buffer_puts(buffer_1,"\" on \"");
	while (x<max) {
	  if (x[1] || !isprint(x[0])) {
	    if (!x[0]) break;
	    buffer_put(buffer_1,".",1);
	  } else
	    buffer_put(buffer_1,x,1);
	  x+=2;
	}
      }
      buffer_putsflush(buffer_1,"\".\nTree Connect... ");
    }

    /* Step 3: Tree Connect */
    {
      char *x;
      char req[200+(strlen(host)+strlen(pathname))*2];
      size_t i;
      byte_copy(req,8+30+7+2+1,
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\x75\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x03\x00\x04\xff"
		"\x00\x00\x00\x00\x00\x01\x00"
		"\x00\x00"	// byte count
		"\x00");
      x=req+8+30+7+2+1;
      x[0]=x[2]='\\';
      x[1]=x[3]=0;
      x+=4;
      for (i=0; host[i]; ++i) {
	x[0]=host[i];
	x[1]=0;
	x+=2;
      }
      x[0]='\\'; x[1]=0; x+=2;
      if (*pathname=='/' || *pathname=='\\') ++pathname;
      for (i=0; pathname[i] && pathname[i]!='/' && pathname[i]!='\\'; ++i) {
	x[0]=pathname[i];
	x[1]=0;
	x+=2;
      }
      byte_copy(x,8,"\x00\x00?????");
      x+=8;
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+30+7;
	uint16_pack(y,x-y-2);
      }
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,x-req) != x-req) panic("Tree Connect request short write");
    }

    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Tree Connect response short read\n");
    tid=uint16_read(buf+24);
    if (validatesmb(buf,wanted,0x75,3,0,tid,3)) panic("Received invalid SMB response\n");
    if (verbose) {
      buffer_puts(buffer_1,"ok, tid=");
      buffer_putulong(buffer_1,tid);
      buffer_putsflush(buffer_1,".\nCreateFile... ");
    }

    /* Step 4: CreateFile */
    {
      char *x,*y;
      char req[200+(strlen(pathname))*2];
      byte_copy(req,8+80+2,
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\xa2\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x04\x00\x18\xff"
		"\x00\x00\x00\x00\xFE\xFE\x10\x00\x00\x00"
		"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x07\x00\x00\x00\x01\x00\x00\x00\x40\x00"
		"\x00\x00\x01\x00\x00\x00\x01"
		"\x00\x00"	// byte count
		"\x00\\\x00");
      uint16_pack(req+4+24,tid);
      uint16_pack(req+4+0x1c,uid);
      x=req+8+80+2;
      y=pathname;

      while (*y=='/' || *y=='\\') ++y;
      while (*y && *y!='/' && *y!='\\') ++y;
      while (*y=='/' || *y=='\\') ++y;

      uint16_pack(req+8+34,(strlen(y)+1)*2);
      while (*y) {
	x[0]=*y;
	if (x[0]=='/') x[0]='\\';
	x[1]=0;
	x+=2;
	++y;
      }
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+77;
	uint16_pack(y,x-y-2);
      }
      if (write(s,req,x-req) != x-req) panic("CreateFile request short write");
    }
    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("CreateFile response short read\n");
    if (validatesmb(buf,wanted,0xa2,34,0,tid,4)) panic("Received invalid SMB response\n");
    fid=uint16_read(buf+0x20+6);
    filesize=uint64_read(buf+0x58);
    u.actime=(uint64_read(buf+0x44) / 10000000ll) - 11644473600ll;
    if (verbose) {
      char tbuf[30];
      tbuf[fmt_httpdate(tbuf,u.actime)]=0;
      buffer_putm(buffer_1,"ok, is a ",buf[0x20+68]==0?"file":"directory",", fid=");
      buffer_putulong(buffer_1,fid);
      buffer_puts(buffer_1,", size=");
      buffer_putulonglong(buffer_1,filesize);
      buffer_putmflush(buffer_1,", mtime=",tbuf,".\n");
    }

    if (buf[0x20+68]==1) {
      // is a directory, do FindFirst/FindNext instead of ReadFile

      time_t now;
      char *x,*y;
      char req[200+2048];
      char* filename=0;

      if (strlen(pathname)>1024) panic("file name too long\n");

      now=time(0);

      byte_copy(req,4+78,
		"\x00\x00\x00\x58"	// 0	NetBIOS
		"\xffSMB"		// 4+0	SMB
		"\x32\x00\x00\x00\x00\x08\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00"		// 4+24	Tree ID
		"\x17\x00"		// 4+26	Process ID
		"\x00\x00"		// 4+28	User ID
		"\x00\x00"		// 4+30	Multiplex ID
		// Trans2 Request
		"\x0f"			// 4+32	Word Count (15)
		"\x12\x00"		// 4+33	Total Parameter Count (18)
		"\x00\x00\x0a\x00\x38\x1f\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00"
		"\x12\x00"		// 4+51	Parameter Count (18)
		"\x42\x00"		// 4+53	Parameter Offset (66)
		"\x00\x00"		// 4+55	Data Count
		"\x58\x00"		// 4+57	Data Offset (88)
		"\x01\x00"
		"\x01\x00"		// 4+61 FIND_FIRST2
		// word count from 4+32 points here
		"\x15\x00"		// 4+63	Byte Count, starts counting here
		"\x00"			// Padding
		// FIND_FIRST2 Parameters; 4+53 points here, parameter count from 4+33 and 4+51 starts counting here
		"\x17\x00"		// 4+66	search attributes: +hidden +system +directory +readonly
		"\x56\x05"		// 4+68	search count: 1366 (!?!?)
		"\x06\x00"		// 4+70	flags: return resume keys + close on eos
		"\x04\x01"		// 4+72	level of interest: find file both directory info (260)
		"\x00\x00\x00\x00");	// 4+74	storage type

      uint16_pack(req+4+24,tid);
      uint16_pack(req+4+28,uid);
      uint16_pack(req+4+30,++mid);

      x = req + 4+78;
      y = pathname;

      {
	uint32_t ch;
	size_t i,pathlen;

	y = pathname;
	while (*y=='/' || *y=='\\') ++y;
	while (*y && *y!='/' && *y!='\\') ++y;
	while (*y=='/' || *y=='\\') ++y;

	for (i=0; y[i]; ) {
	  size_t r;
	  r=scan_utf8(y+i,5,&ch);
	  if (r)
	    y+=r;
	  else {
	    ch=(unsigned char)y[i];
	    ++y;
	  }
	  uint16_pack(x,ch);
	  x+=2;
	}
	if (ch!='\\') {
	  uint16_pack(x,'\\');
	  x+=2;
	}
	uint16_pack(x,'*');
	x+=2;
	uint16_pack(x,0);
	x+=2;
	pathlen=x-(req+4+78);	// length in bytes

	uint16_pack(req+4+63, 13+pathlen);	// byte count
	uint16_pack(req+4+33, 12+pathlen);	// total parameter count
	uint16_pack(req+4+51, 12+pathlen);	// parameter count
	uint16_pack(req+4+57, 76+pathlen);	// data offset
	uint32_pack_big(req,x-req-4);
	if (write(s,req,x-req) != x-req) panic("FindFirst request short write");
      }

      for (;;) {
	int end_of_search;
	uint32_t fnlen=0;
	uint16_t search_id=0;

	readnetbios(&ib,buf,&wanted);
	if (wanted>sizeof(buf)) panic("packet too large");
	if (buffer_get(&ib,buf,wanted)!=wanted) panic(filename?"FindNext response short read\n":"FindFirst response short read\n");
	if (validatesmb(buf,wanted,0x32,filename?8:10,0,tid,mid)) panic("Received invalid SMB response\n");

	// Unfortunately, the reply does not say whether it is replying to a FIND_FIRST2 or a FIND_NEXT2
	// So we look at the parameter count.  For FIND_FIRST2 it is 10, for FIND_NEXT2 it is 8.
	{
	  char* x=buf+0x20;
	  size_t pcount=uint16_read(x+1);
	  size_t pofs=uint16_read(x+9);
	  size_t dcount=uint16_read(x+13);
	  size_t dofs=uint16_read(x+15);
	  size_t bcount=uint16_read(x+21);
	  if (dofs+dcount>wanted || 0x20+21+bcount>wanted)
	    panic("SMB protocol violation: data count does not fit into packet\n");
	  if (pofs+pcount>dofs)
	    panic("SMB protocol violation: parameters overlap with data\n");
	  if (pcount != uint16_read(x+7))
	    panic("SMB protocol violation: parameter count != total parameter count\n");
	  if (dcount != uint16_read(x+3))
	    panic("SMB protocol violation: byte count != total data count\n");
	  if (pofs<56)
	    panic("SMB protocol violation: parameter offset too small\n");
	  if (buf[0x21]==10) {
	    search_id = uint16_read(buf+pofs);
	    end_of_search = uint16_read(buf+pofs+4);
	  } else
	    end_of_search = uint16_read(buf+pofs+2);
	}

	/* we got a superficially valid looking reply; dump all the file names */
	{
	  char* x=buf+0x20;
	  char* last=buf+wanted;
	  size_t datacount = uint16_read(x+3);
	  x = buf+uint16_read(x+15);
	  if (x+datacount > last)
	    panic("SMB protocol violation: data + datacount > packet\n");
	  while (x+4<last) {
	    time_t mtime;
	    uint64_t filesize;
	    uint32_t attr;
	    uint32_t ofs=uint32_read(x);
	    if (ofs>datacount || ofs<(120-26) || x+ofs>last)
	      panic("SMB protocol violation: invalid ofs in filename record\n");
	    mtime=(uint64_read(x+24) / 10000000ll) - 11644473600ll;
	    filesize=uint64_read(x+40);
	    attr=uint32_read(x+56);
	    fnlen=uint32_read(x+60);
	    filename=x+94;
	    if (filename+fnlen > x+ofs)
	      panic("SMB protocol violation: invalid file name length in filename record\n");
	    {
	      char a[FMT_ULONG];
	      char b[100];
	      char buf[11];
	      size_t n;
	      struct tm* T;
	      static char *smonths[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
	      char* fn;
	      a[n=fmt_ulonglong(a,filesize)]=0;
	      b[fmt_pad(b,a,n,10,20)]=0;
	      T=localtime(&mtime);
	      memset(buf,' ',sizeof(buf));
	      fmt_num2(buf+1,T->tm_mday);
	      if (buf[1]=='0') buf[1]=' ';
	      if (mtime>now||now-mtime>60*60*24*365/2) {
		fmt_num2(buf+5,(T->tm_year+1900)/100);
		fmt_num2(buf+7,(T->tm_year+1900)%100);
	      } else {
		fmt_num2(buf+4,T->tm_hour);
		buf[6]=':';
		fmt_num2(buf+7,T->tm_min);
	      }
	      buf[10]=0;
	      if (attr&0x10)
		buffer_puts(buffer_1,"drwxr-xr-x");
	      else if (attr&1)
		buffer_puts(buffer_1,"-r-xr-xr-x");
	      else
		buffer_puts(buffer_1,"-rwxr-xr-x");
	      buffer_putm(buffer_1,"  1 root     root     ",b," ",smonths[T->tm_mon],buf," ");
	      fn=filename;
	      y=fn+fnlen;
	      while (fn<y) {
		uint32_t ch=uint16_read(fn);
		buffer_put(buffer_1,b,fmt_utf8(b,ch));
		fn+=2;
	      }
	      buffer_putnlflush(buffer_1);
	    }
	    x+=ofs;
	  }
	}

	/* now see if there is a continuation or not */
	if (end_of_search) break;

	/* there are more file names, we need to send a FIND_NEXT2 */
	if (fnlen>2048) panic("filename too long\n");

	byte_copy(req,4+78,
		"\x00\x00\x00\x6c"	// 0	NetBIOS
		"\xffSMB"		// 4+0	SMB
		"\x32\x00\x00\x00\x00\x08\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00"		// 4+24	Tree ID
		"\x17\x00"		// 4+26	Process ID
		"\x00\x00"		// 4+28	User ID
		"\x00\x00"		// 4+30	Multiplex ID
		// Trans2 Request
		"\x0f"			// 4+32	Word Count (15)
		"\x26\x00"		// 4+33	Total Parameter Count (38)
		"\x00\x00\x0a\x00\x38\x1f\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00"
		"\x26\x00"		// 4+51	Parameter Count (38)
		"\x42\x00"		// 4+53	Parameter Offset (66)
		"\x00\x00"		// 4+55	Data Count
		"\x6c\x00"		// 4+57	Data Offset (108)
		"\x01\x00"
		"\x02\x00"		// 4+61 FIND_NEXT2
		// word count from 4+32 points here
		"\x2b\x00"		// 4+63	Byte Count, starts counting here
		"\x00"			// Padding
		// FIND_FIRST2 Parameters; 4+53 points here, parameter count from 4+33 and 4+51 starts counting here
		"\x01\x00"		// 4+66	search id (comes from FIND_FIRST2 response)
		"\x56\x05"		// 4+68	search count: 1366 (!?!?)
		"\x04\x01"		// 4+70	level of interest: find file both directory info (260)
		"\x00\x00\x00\x00"	// 4+72	resume key
		"\x06\x00");		// 4+76	flags

	uint16_pack(req+4+24,tid);
	uint16_pack(req+4+28,uid);
	uint16_pack(req+4+30,++mid);
	uint16_pack(req+4+66,search_id);

	x=req+4+78; byte_copy(x,fnlen,filename);
	x+=fnlen; byte_copy(x,2,"\x00\x00");
	x+=2;

	uint16_pack(req+4+63, 13+fnlen+2);	// byte count
	uint16_pack(req+4+33, 12+fnlen+2);	// total parameter count
	uint16_pack(req+4+51, 12+fnlen+2);	// parameter count
	uint16_pack(req+4+57, 76+fnlen+2);	// data offset
	uint32_pack_big(req,x-req-4);
	if (write(s,req,x-req) != x-req) panic("FindNext request short write");

      }

      goto closeanddone;
    }

    if (filesize<=resumeofs) {
      if (verbose) buffer_putsflush(buffer_1,"File already fully transmitted.\n");
      goto closeanddone;
    }
    if (ims && u.actime<=ims) {
      if (verbose) buffer_putsflush(buffer_1,"The local file is as new as the remote file.\n");
      goto closeanddone;
    }

    /* Step 5: ReadFile */
    {
      static char req[]=
		"\x00\x00\x00\x3b"	// NetBIOS
		"\xffSMB"		// SMB
		"\x2e\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x05\x00\x0c\xff"
		"\x00\x00\x00w0u0__\x00"
		"\xf0\x00\xf0\x00\x00\x00\x00\x00\xf0u"
		"1__\x00\x00";
      size_t rest;
      size_t gotten;
      unsigned long long curofs=resumeofs;
      int nextwritten=0;
      int64 d;
      uint16_pack(req+4+0x1c,uid);
      uint16_pack(req+4+24,tid);
      uint16_pack(req+8+33,fid);
      if (filename[0]) {
	if ((resume?io_appendfile(&d,filename):io_createfile(&d,filename))==0)
	  panic("creat");
      } else {
	d=1;
	dostats=!isatty(1);
      }
      total=filesize-resumeofs;
      while (curofs<filesize) {
	size_t dataofs;

	uint16_pack(req+30+4,++mid);
	uint32_pack(req+8+33+2,resumeofs&0xffffffff);
	uint32_pack(req+8+49,resumeofs>>32);
	rest=(filesize-curofs>readsize)?readsize:filesize-curofs;
	uint16_pack(req+8+33+2+4,rest);
	uint16_pack(req+8+33+2+6,rest);
	uint16_pack(req+8+47,rest);

	if (!nextwritten) {
	  if (write(s,req,0x3b+4)!=0x3b+4) panic("ReadFile request short write");
	}
	readnetbios(&ib,buf,&wanted);
	if (wanted>readsize+300) panic("packet too large");
	if (wanted<0x20+12*2+3) panic("SMB (ReadFile): Received invalid SMB response\n");
	if (buffer_get(&ib,readbuf,0x20+12*2+3)!=0x20+12*2+3) panic("ReadFile response short read\n");

	if (validatesmb(readbuf,wanted,0x2e,12,0,tid,mid)) panic("SMB (ReadFile): Received invalid SMB response\n");
	gotten=uint16_read(readbuf+0x39);
	dataofs=uint16_read(readbuf+0x2d);
	if (dataofs+gotten>wanted) panic("invalid dataofs in ReadFile response");
	if (gotten<rest) break;	// someone truncated the file while we read?

	/* pipeline next read request */
	curofs+=gotten;
	if (curofs<filesize) {
	  uint16_pack(req+30+4,mid+1);
	  uint32_pack(req+8+33+2,curofs&0xffffffff);
	  uint32_pack(req+8+49,curofs>>32);
	  rest=(filesize-curofs>readsize)?readsize:filesize-curofs;
	  uint16_pack(req+8+33+2+4,rest);
	  uint16_pack(req+8+33+2+6,rest);
	  uint16_pack(req+8+47,rest);
	  if (write(s,req,0x3b+4)!=0x3b+4) panic("ReadFile request short write");
	  nextwritten=1;
	}

	if (buffer_get(&ib,readbuf+0x20+12*2+3,wanted-(0x20+12*2+3))!=wanted-(0x20+12*2+3)) panic("ReadFile response short read\n");
	if (write(d,readbuf+dataofs,gotten)!=gotten) panic("short write.  disk full?\n");
	printstats(gotten,d);
      }

      io_close(d);
    }

closeanddone:

    if (verbose) buffer_putsflush(buffer_1,"Close... ");

    /* Step 6: Close */
    {
      static char req[]=
		"\x00\x00\x00\x29"	// NetBIOS
		"\xffSMB"		// SMB
		"\x04\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xFE\xFE\x17\x00\x00\x00\x05\x00\x03\xFE"
		"\xFE\xff\xff\xff\xff\x00\x00";
      uint16_pack(req+30+4,++mid);
      uint16_pack(req+8+29,fid);
      uint16_pack(req+8+20,tid);
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,8+37)!=8+37) panic("Close request short write");
      readnetbios(&ib,buf,&wanted);
      if (wanted>sizeof(buf)) panic("packet too large");
      if (buffer_get(&ib,buf,wanted)!=wanted) panic("Close response short read\n");
      if (validatesmb(buf,wanted,0x04,0,0,tid,mid)) panic("SMB (CloseFile): Received invalid SMB response\n");
    }

    if (verbose) buffer_putsflush(buffer_1,"ok.\nTree Disconnect... ");

    /* Step 7: Tree Disconnect */
    {
      static char req[]=
		"\x00\x00\x00\x23"	// NetBIOS
		"\xffSMB"		// SMB
		"\x71\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x05\x00\x00\x00";
      uint16_pack(req+30+4,++mid);
      uint16_pack(req+8+33,fid);
      uint16_pack(req+28,tid);
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,0x23+4)!=0x23+4) panic("Tree Disconnect request short write");
      readnetbios(&ib,buf,&wanted);
      if (wanted>sizeof(buf)) panic("packet too large");
      if (buffer_get(&ib,buf,wanted)!=wanted) panic("Tree Disconnect response short read\n");
      if (validatesmb(buf,wanted,0x71,0,0,tid,mid)) panic("SMB (Tree Disconnect): Received invalid SMB response\n");
    }
    if (verbose) buffer_putsflush(buffer_1,"ok.\n");

  } else
    panic("invalid mode\n");
  close(s);
  if (filename[0] && u.actime) {
    u.modtime=u.actime;
    if (strcmp(filename,"-") && utime(filename,&u)==-1)
      if (errno!=ENOENT || !imode)
	panic("utime");
  }
  clearstats();
  return 0;
}
