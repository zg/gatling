#include "gatling.h"

#include "fmt.h"
#include "ip6.h"
#include "buffer.h"
#include "case.h"
#include "socket.h"
#include "str.h"
#include "ip4.h"
#include "scan.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fnmatch.h>
#include <assert.h>

#include "havealloca.h"

#ifdef SUPPORT_FTP
/*
  __ _
 / _| |_ _ __
| |_| __| '_ \
|  _| |_| |_) |
|_|  \__| .__/
        |_|
*/

int askforpassword;

static int ftp_vhost(struct http_data* h) {
  int r=ip_vhost(h);
  if (r==-1)
    h->hdrbuf="425 no such virtual host.\r\n";
  return r;
}

static int ftp_open(struct http_data* h,const char* s,int forreading,int sock,const char* what,struct stat* ss) {
  int l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  int64 fd;

  /* first, append to path */
  if (s[0]!='/' && h->ftppath)
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h)) return -1;

  errno=0; fd=-1;
  h->hdrbuf=forreading?"550 No such file or directory.\r\n":"550 Uploading not permitted here!\r\n";
  if (x[1]) {
    switch (forreading) {
    case 1: open_for_reading(&fd,x+1,ss); break;
    case 0: open_for_writing(&fd,x+1); break;
    case 2: fd=mkdir(x+1,0777);
	    if (!fd) chmod(x+1,0777);
	    break;
    }
  }
#ifdef DEBUG
  if (forreading<2)
    if (logging) {
      buffer_puts(buffer_1,"ftp_open_file ");
      buffer_putulong(buffer_1,sock);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      buffer_puts(buffer_1,x+1);
      buffer_putnlflush(buffer_1);
    }
#endif

  if (logging && what) {
    buffer_puts(buffer_1,what);
    if (fd==-1) buffer_puts(buffer_1,"/404");
    buffer_putspace(buffer_1);
    buffer_putulong(buffer_1,sock);
    buffer_putspace(buffer_1);
    buffer_putlogstr(buffer_1,x[1]?x:"/");
    buffer_putspace(buffer_1);
  }
  return fd;
}

static int ftp_retrstor(struct http_data* h,const char* s,int64 sock,int forwriting) {
  uint64 range_first,range_last;
  struct stat ss;
  struct http_data* b;

  char buf[IP6_FMT+10];
  int x;
  x=fmt_ip6c(buf,h->myip);
  x+=fmt_str(buf+x,"/");
  x+=fmt_ulong(buf+x,h->myport);
  buf[x]=0;

  if (h->buddy==-1 || !(b=io_getcookie(h->buddy))) {
    h->hdrbuf="425 Could not establish data connection.\r\n";
    return -1;
  }
  if (b->filefd!=-1) { io_close(b->filefd); b->filefd=-1; }
  b->filefd=ftp_open(h,s,forwriting^1,sock,forwriting?"STOR":"RETR",&ss);
  if (forwriting) ss.st_size=0;
  if (b->filefd==-1) {
    if (logging) {
      buffer_putulonglong(buffer_1,0);
      buffer_putspace(buffer_1);
      buffer_putlogstr(buffer_1,buf);
      buffer_putnlflush(buffer_1);
    }
    return -1;
  }

  if (!forwriting) {
    if (fstat(b->filefd,&ss)==-1)
      range_last=0;
    else
      range_last=ss.st_size;
    range_first=h->ftp_rest; h->ftp_rest=0;
    if (range_first>range_last) range_first=range_last;
    iob_addfile_close(&b->iob,b->filefd,range_first,range_last-range_first);
    if (logging) {
      buffer_putulonglong(buffer_1,range_last-range_first);
      buffer_putspace(buffer_1);
    }
    b->filefd=-1;	/* iob_addfile_close will close the fd, we don't want cleanup() to close it twice */
  }

  if (logging) {
    buffer_putlogstr(buffer_1,buf);
    buffer_putnlflush(buffer_1);
  }

  h->f=WAITCONNECT;
  h->hdrbuf=malloc(100);
  b->f=forwriting?UPLOADING:DOWNLOADING;
  if (!h->hdrbuf) {
    h->hdrbuf=(b->t==FTPSLAVE)?"125 go on\r\n":"150 go on\r\n";
    return -1;
  } else {
    int i;
    if (b->t==FTPSLAVE) {
      i=fmt_str(h->hdrbuf,"125 go on (");
      if (forwriting)
	io_wantread(h->buddy);
      else
	io_wantwrite(h->buddy);
      h->f=LOGGEDIN;
    } else if (b->t==FTPACTIVE)
      i=fmt_str(h->hdrbuf,"150 connecting (");
    else
      i=fmt_str(h->hdrbuf,"150 listening (");
    if (forwriting)
      i+=fmt_str(h->hdrbuf+i,"for upload)\r\n");
    else {
      i+=fmt_ulonglong(h->hdrbuf+i,ss.st_size);
      i+=fmt_str(h->hdrbuf+i," bytes)\r\n");
    }
    h->hdrbuf[i]=0;
  }

  return 0;
}

static int ftp_mdtm(struct http_data* h,const char* s) {
  struct stat ss;
  int fd;
  int i;
  struct tm* t;
  if ((fd=ftp_open(h,s,1,0,0,&ss))==-1) return -1;
  io_close(fd);
  t=gmtime(&ss.st_mtime);
  h->hdrbuf=malloc(100);
  if (!h->hdrbuf) {
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  i=fmt_str(h->hdrbuf,"213 ");
  i+=fmt_2digits(h->hdrbuf+i,(t->tm_year+1900)/100);
  i+=fmt_2digits(h->hdrbuf+i,(t->tm_year+1900)%100);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_mon+1);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_mday);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_hour);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_min);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_sec);
  i+=fmt_str(h->hdrbuf+i,"\r\n");
  h->hdrbuf[i]=0;
  return 0;
}

static int ftp_size(struct http_data* h,const char* s) {
  struct stat ss;
  int fd;
  int i;
  if ((fd=ftp_open(h,s,1,0,0,&ss))==-1) return -1;
  io_close(fd);
  h->hdrbuf=malloc(100);
  if (!h->hdrbuf) {
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  i=fmt_str(h->hdrbuf,"213 ");
  i+=fmt_ulonglong(h->hdrbuf+i,ss.st_size);
  i+=fmt_str(h->hdrbuf+i,"\r\n");
  h->hdrbuf[i]=0;
  return 0;
}


static void ftp_ls(array* x,const char* s,const struct stat* const ss,time_t now,const char* pathprefix) {
  char buf[2048];
  int i,j;
  struct tm* t;
  {
    int i,m=ss->st_mode;
    for (i=0; i<10; ++i) buf[i]='-';
    if (S_ISDIR(m)) buf[0]='d'; else
    if (S_ISLNK(m)) buf[0]='l';	/* other specials not supported */
    if (m&S_IRUSR) buf[1]='r';
    if (m&S_IWUSR) buf[2]='w';
    if (m&S_IXUSR) buf[3]='x';
    if (m&S_IRGRP) buf[4]='r';
    if (m&S_IWGRP) buf[5]='w';
    if (m&S_IXGRP) buf[6]='x';
    if (m&S_IROTH) buf[7]='r';
    if (m&S_IWOTH) buf[8]='w';
    if (m&S_IXOTH) buf[9]='x';
    buf[10]=' ';
  }
  array_catb(x,buf,11);

  i=j=fmt_ulong(buf,ss->st_nlink);
  if (i<3) j=3;
  array_catb(x,buf+100,fmt_pad(buf+100,buf,i,j,j));
  array_cats(x," root     root     ");

  buf[i=fmt_ulonglong(buf,ss->st_size)]=' ';
  j=++i; if (i<8) j=8;
  array_catb(x,buf+100,fmt_pad(buf+100,buf,i,j,j));

  {
    t=localtime(&ss->st_mtime);
    array_catb(x,months+3*t->tm_mon,3);
    array_cats(x," ");
    array_catb(x,buf,fmt_2digits(buf,t->tm_mday));
    array_cats(x," ");
    if (ss->st_mtime<=now && ss->st_mtime>=now-60*60*12*356) {
      array_catb(x,buf,fmt_2digits(buf,t->tm_hour));
      array_cats(x,":");
      array_catb(x,buf,fmt_2digits(buf,t->tm_min));
    } else {
      array_cats(x," ");
      array_catb(x,buf,fmt_ulong0(buf,t->tm_year+1900,4));
    }
  }
  array_cats(x," ");
  array_cats(x,pathprefix);
  array_cats(x,s);
  if (S_ISLNK(ss->st_mode)) {
    array_cats(x," -> ");
    array_cats(x,readlink(s,buf,sizeof(buf))?"[error]":buf);
  }
  array_cats(x,"\r\n");
}

static int ftp_list(struct http_data* h,char* s,int _long,int sock) {
  int i,l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  DIR* D;
  struct dirent* d;
  int rev=0;
  int what=0;
  time_t now;

  char* pathprefix="";
  char* match=0;

  unsigned long o,n;
  int (*sortfun)(de*,de*);
  array a,b,c;
  de* ab;

  if (h->buddy==-1 || !io_getcookie(h->buddy)) {
    h->hdrbuf="425 Could not establish data connection\r\n";
    return -1;
  }

  i=str_len(s);
  if (i>1) {
    if (s[i-1]=='\n') --i;
    if (s[i-1]=='\r') --i;
    s[i]=0;
  }

  byte_zero(&a,sizeof(a));
  byte_zero(&b,sizeof(b));
  byte_zero(&c,sizeof(c));
  o=n=0;

  if (s[0]=='-') {
    for (++s; *s && *s!=' '; ++s) {
      switch (*s) {
      case 'l': _long=1; break;
      case 'r': rev=1; break;
      case 'S': what=1; break;
      case 't': what=2; break;
      }
    }
    while (*s==' ') ++s;
  }
  {
    switch (what) {
    case 1: sortfun=rev?sort_size_a:sort_size_d; break;
    case 2: sortfun=rev?sort_mtime_a:sort_mtime_d; break;
    default: sortfun=rev?sort_name_d:sort_name_a; break;
    }
  }

  /* first, append to path */
  if (h->ftppath && s[0]!='/')
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h)) return 0;

  /* cases:
   *   it's a directory
   *     -> opendir(foo/bar), ...
   *   foo/$fnord
   *     -> pathprefix="foo/"; chdir(foo); opendir(...); fnmatch($fnord)
   *   /pub/$fnord
   *     -> pathprefix="/pub/"; chdir(/pub); opendir(...); fnmatch($fnord)
   */

  if (!x[1] || chdir(x+1)==0) {		/* it's a directory */
    pathprefix="";
    match=0;
  } else {
    if (s[0]!='/') {	/* foo/$fnord */
      int z=str_rchr(s,'/');
      if (s[z]!='/') {
	pathprefix="";
	match=s;
      } else {
	pathprefix=alloca(z+2);
	byte_copy(pathprefix,z,s);
	pathprefix[z]='/';
	pathprefix[z+1]=0;
	match=0;
	z=str_rchr(x,'/');
	x[z]=0;
	if (x[0]=='/' && x[1] && chdir(x+1)==-1) {
notfound:
	  h->hdrbuf="450 no such file or directory.\r\n";
	  return -1;
	}
	x[z]='/';
	match=x+z+1;
      }
    } else {		/* /pub/$fnord */
      int z=str_rchr(x,'/');
      x[z]=0;
      if (x[0]=='/' && x[1] && chdir(x+1)==-1) goto notfound;
      match=x+z+1;
      pathprefix=alloca(z+2);
      byte_copy(pathprefix,z,x);
      pathprefix[z]='/';
      pathprefix[z+1]=0;
    }
  }

  D=opendir(".");
  if (!D)
    goto notfound;
  else {
    while ((d=readdir(D))) {
      de* X=array_allocate(&a,sizeof(de),n);
      if (!X) break;
      X->name=o;
      if (lstat(d->d_name,&X->ss)==-1) continue;
      if (!match || fnmatch(match,d->d_name,FNM_PATHNAME)==0) {
	array_cats0(&b,d->d_name);
	o+=str_len(d->d_name)+1;
	++n;
      }
    }
    closedir(D);
  }
  if (array_failed(&a) || array_failed(&b)) {
    array_reset(&a);
    array_reset(&b);
nomem:
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  base=array_start(&b);
  qsort(array_start(&a),n,sizeof(de),(int(*)(const void*,const void*))sortfun);

  ab=array_start(&a);
  now=time(0);
  for (i=0; i<n; ++i) {
    char* name=base+ab[i].name;

    if (name[0]=='.') {
      if (name[1]==0) continue; /* skip "." */
      if (name[1]!='.' || name[2]!=0)	/* skip dot-files */
	continue;
    } else if (name[0]==':')
      name[0]='.';
    if (_long)
      ftp_ls(&c,name,&ab[i].ss,now,pathprefix);
    else {
      array_cats(&c,pathprefix);
      array_cats(&c,name);
      array_cats(&c,"\r\n");
    }
  }
  array_reset(&a);
  array_reset(&b);
  if (array_failed(&c)) goto nomem;
  if (array_bytes(&c)==0) {
    h->hdrbuf="450 no match\r\n";
    return -1;
  } else {
    struct http_data* b=io_getcookie(h->buddy);
    assert(b);
    if (b) {
      iob_addbuf_free(&b->iob,array_start(&c),array_bytes(&c));
      b->f=DOWNLOADING;
      h->f=WAITCONNECT;
      if (b->t==FTPSLAVE) {
	h->hdrbuf="125 go on\r\n";
	io_wantwrite(h->buddy);
	h->f=LOGGEDIN;
      } else if (b->t==FTPACTIVE)
	h->hdrbuf="150 connecting\r\n";
      else
	h->hdrbuf="150 I'm listening\r\n";
    }
  }
  if (logging) {
    buffer_puts(buffer_1,_long?"LIST ":"NLST ");
    buffer_putulong(buffer_1,sock);
    buffer_putspace(buffer_1);
    buffer_putlogstr(buffer_1,x[1]?x:"/");
    buffer_putspace(buffer_1);
    buffer_putulong(buffer_1,array_bytes(&c));
    buffer_putspace(buffer_1);
    {
      char buf[IP6_FMT+10];
      int x;
      x=fmt_ip6c(buf,h->peerip);
      x+=fmt_str(buf+x,"/");
      x+=fmt_ulong(buf+x,h->peerport);
      buffer_put(buffer_1,buf,x);
    }
    buffer_putnlflush(buffer_1);
  }
  return 0;
}

static int ftp_cwd(struct http_data* h,char* s) {
  int l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  /* first, append to path */
  if (s[0]!='/' && h->ftppath)
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h))
    return -1;

  if (x[1] && chdir(x+1)) {
    h->hdrbuf="525 directory not found.\r\n";
    return -1;
  }
  y=realloc(h->ftppath,l+1);
  if (!y) {
    h->hdrbuf="500 out of memory.\r\n";
    return -1;
  }
  y[fmt_str(y,x)]=0;
  h->ftppath=y;
  h->hdrbuf="250 ok.\r\n";
  return 0;
}

static int ftp_mkdir(struct http_data* h,const char* s) {
  if (ftp_open(h,s,2,0,"mkdir",0)==-1) return -1;
  h->hdrbuf="257 directory created.\r\n";
  return 0;
}

void ftpresponse(struct http_data* h,int64 s) {
  char* c;
  h->filefd=-1;

  ++rps1;
  c=array_start(&h->r);
  {
    char* d,* e=c+array_bytes(&h->r);

/*    write(1,c,e-c); */

    for (d=c; d<e; ++d) {
      if (*d=='\n') {
	if (d>c && d[-1]=='\r') --d;
	*d=0;
	break;
      }
      if (*d==0) *d='\n';
    }
  }
  if (case_equals(c,"QUIT")) {
    h->hdrbuf="221 Goodbye.\r\n";
    h->keepalive=0;
  } else if (case_equals(c,"ABOR") ||
	     case_equals(c,"\xff\xf4\xff\xf2""ABOR") ||
	     case_equals(c,"\xff\xf4\xff""ABOR")) {
    /* for some reason, on Linux 2.6 the trailing \xf2 sometimes does
     * not arrive although it is visible in the tcpdump */
    if (h->buddy==-1)
      h->hdrbuf="226 Ok.\r\n";
    else {
      io_close(h->buddy);
      h->buddy=-1;
      h->hdrbuf="426 Ok.\r\n226 Connection closed.\r\n";
    }
  } else if (case_starts(c,"USER ")) {
    c+=5;
    if (case_equals(c,"ftp") || case_equals(c,"anonymous")) {
      if (askforpassword)
	h->hdrbuf="331 User name OK, please use your email address as password.\r\n";
      else
	h->hdrbuf="230 No need for passwords, you're logged in now.\r\n";
    } else {
      if (askforpassword)
	h->hdrbuf="331 I only serve anonymous users.  But I'll make an exception.\r\n";
      else
	h->hdrbuf="230 I only serve anonymous users.  But I'll make an exception.\r\n";
    }
    h->f=LOGGEDIN;
  } else if (case_starts(c,"PASS ")) {
    h->hdrbuf="230 If you insist...\r\n";
  } else if (case_starts(c,"TYPE ")) {
    h->hdrbuf="200 yeah, whatever.\r\n";
  } else if (case_equals(c,"PASV") || case_equals(c,"EPSV")) {
    int epsv=(*c=='e' || *c=='E');
    char ip[16];
    uint16 port;
#ifdef __broken_itojun_v6__
#warning fixme
#endif
    if (h->buddy!=-1) {
      if (logging) {
	buffer_puts(buffer_1,"close/olddataconn ");
	buffer_putulong(buffer_1,h->buddy);
	buffer_putnlflush(buffer_1);
      }
      io_close(h->buddy);
    }
    h->buddy=socket_tcp6();
    if (h->buddy==-1) {
      h->hdrbuf="425 socket() failed.\r\n";
      goto ABEND;
    }
    if (socket_bind6_reuse(h->buddy,h->myip,0,h->myscope_id)==-1) {
closeandgo:
      io_close(h->buddy);
      h->hdrbuf="425 socket error.\r\n";
      goto ABEND;
    }
    if (socket_local6(h->buddy,ip,&port,0)==-1) goto closeandgo;
    if (!(h->hdrbuf=malloc(100))) goto closeandgo;
    if (epsv==0) {
      c=h->hdrbuf+fmt_str(h->hdrbuf,"227 Passive Mode OK (");
      {
	int i;
	for (i=0; i<4; ++i) {
	  c+=fmt_ulong(c,h->myip[12+i]&0xff);
	  c+=fmt_str(c,",");
	}
      }
      c+=fmt_ulong(c,(port>>8)&0xff);
      c+=fmt_str(c,",");
      c+=fmt_ulong(c,port&0xff);
      c+=fmt_str(c,")\r\n");
    } else {
      c=h->hdrbuf+fmt_str(h->hdrbuf,"229 Passive Mode OK (|||");
      c+=fmt_ulong(c,port);
      c+=fmt_str(c,"|)\r\n");
    }
    *c=0;
    if (io_fd(h->buddy)) {
      struct http_data* x=malloc(sizeof(struct http_data));
      if (!x) {
freecloseabort:
	free(h->hdrbuf);
	c=0;
	goto closeandgo;
      }
      byte_zero(x,sizeof(struct http_data));
      x->buddy=s; x->filefd=-1;
      changestate(x,FTPPASSIVE);
//      x->t=FTPPASSIVE;
#ifdef STATE_DEBUG
      x->myfd=h->buddy;
#endif
      io_setcookie(h->buddy,x);
      socket_listen(h->buddy,1);
      io_wantread(h->buddy);
      if (logging) {
	buffer_puts(buffer_1,epsv?"epsv_listen ":"pasv_listen ");
	buffer_putulong(buffer_1,s);
	buffer_putspace(buffer_1);
	buffer_putulong(buffer_1,h->buddy);
	buffer_putspace(buffer_1);
	buffer_putulong(buffer_1,port);
	buffer_putnlflush(buffer_1);
      }
    } else
      goto freecloseabort;
  } else if (case_starts(c,"PORT ") || case_starts(c,"EPRT ")) {
    int eprt=(*c=='e' || *c=='E');
    char ip[16];
    uint16 port;
#ifdef __broken_itojun_v6__
#warning fixme
#endif
    if (h->buddy!=-1) {
      if (logging) {
	buffer_puts(buffer_1,"close/olddataconn ");
	buffer_putulong(buffer_1,h->buddy);
	buffer_putnlflush(buffer_1);
      }
      io_close(h->buddy);
      h->buddy=-1;
    }
    c+=5;
    if (eprt) {
      /* |1|10.0.0.4|1025| or @2@::1@1026@ */
      char sep;
      int i;
      if (!(sep=*c)) goto syntaxerror;
      if (c[2]!=sep) goto syntaxerror;
      if (c[1]=='1') {
	byte_copy(ip,12,V4mappedprefix);
	if (c[3+(i=scan_ip4(c+3,ip+12))]!=sep || !i) goto syntaxerror;
      } else if (c[1]=='2') {
	if (c[3+(i=scan_ip6(c+3,ip))]!=sep || !i) goto syntaxerror;
      } else goto syntaxerror;
      c+=i+4;
      if (c[i=scan_ushort(c,&port)]!=sep || !i) goto syntaxerror;
    } else {
      /* 10,0,0,1,4,1 -> 10.0.0.1:1025 */
      unsigned long l;
      int r,i;
      for (i=0; i<4; ++i) {
	if (c[r=scan_ulong(c,&l)]!=',' || l>255) {
syntaxerror:
	  h->hdrbuf="501 Huh?  What?!  Where am I?\r\n";
	  goto ABEND;
	}
	c+=r+1;
	ip[12+i]=l;
	byte_copy(ip,12,V4mappedprefix);
      }
      if (c[r=scan_ulong(c,&l)]!=',' || l>255) goto syntaxerror;
      c+=r+1;
      port=l<<8;
      r=scan_ulong(c,&l); if (l>255) goto syntaxerror;
      port+=l;
    }
    h->buddy=socket_tcp6();
    if (h->buddy==-1) {
      h->hdrbuf="425 socket() failed.\r\n";
      goto ABEND;
    }
    if (byte_diff(h->peerip,16,ip)) {
      h->hdrbuf="425 Sorry, but I will only connect back to your own IP.\r\n";
      io_close(h->buddy);
      goto ABEND;
    }
    h->hdrbuf="200 Okay, go ahead.\r\n";
    if (io_fd(h->buddy)) {
      struct http_data* x=malloc(sizeof(struct http_data));
      if (!x) goto closeandgo;
      byte_zero(x,sizeof(struct http_data));
      x->buddy=s; x->filefd=-1;
      changestate(x,FTPACTIVE);
//      x->t=FTPACTIVE;
      x->destport=port;
      byte_copy(x->peerip,16,ip);

#ifdef STATE_DEBUG
      x->myfd=h->buddy;
#endif
      io_setcookie(h->buddy,x);
    } else
      goto closeandgo;

    socket_connect6(h->buddy,ip,port,h->myscope_id);

    if (logging) {
      buffer_puts(buffer_1,eprt?"eprt ":"port ");
      buffer_putulong(buffer_1,s);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,h->buddy);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
    }
    io_dontwantread(h->buddy);
    io_wantwrite(h->buddy);
  } else if (case_equals(c,"PWD") || case_equals(c,"XPWD") /* fsck windoze */) {
    c=h->ftppath; if (!c) c="/";
    h->hdrbuf=malloc(50+str_len(c));
    if (h->hdrbuf) {
      c=h->hdrbuf;
      c+=fmt_str(c,"257 \"");
      c+=fmt_str(c,h->ftppath?h->ftppath:"/");
      c+=fmt_str(c,"\" \r\n");
      *c=0;
    } else
      h->hdrbuf="500 out of memory\r\n";
  } else if (case_starts(c,"CWD ")) {
    ftp_cwd(h,c+4);
  } else if (case_equals(c,"CDUP") || case_equals(c,"XCUP")) {
    ftp_cwd(h,"..");
  } else if (case_starts(c,"MDTM ")) {
    c+=5;
    if (ftp_mdtm(h,c)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"SIZE ")) {
    c+=5;
    if (ftp_size(h,c)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"MKD ")) {
    c+=4;
    ftp_mkdir(h,c);
  } else if (case_equals(c,"FEAT")) {
    h->hdrbuf="211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n211 End\r\n";
  } else if (case_equals(c,"SYST")) {
    h->hdrbuf="215 UNIX Type: L8\r\n";
  } else if (case_starts(c,"REST ")) {
    unsigned long long x;
    c+=5;
    if (!c[scan_ulonglong(c,&x)]) {
      h->hdrbuf="350 ok.\r\n";
      h->ftp_rest=x;
    } else
      h->hdrbuf="501 invalid number\r\n";
  } else if (case_starts(c,"RETR ")) {
    c+=5;
    if (ftp_retrstor(h,c,s,0)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"STOR ")) {
    if (nouploads)
      h->hdrbuf="553 no upload allowed here.\r\n";
    else {
      c+=5;
      if (ftp_retrstor(h,c,s,1)==0)
	c=h->hdrbuf;
    }
  } else if (case_starts(c,"LIST")) {
    c+=4;
    if (*c==' ') ++c;
    ftp_list(h,c,1,s);
  } else if (case_starts(c,"NLST")) {
    c+=4;
    if (*c==' ') ++c;
    ftp_list(h,c,0,s);
  } else if (case_equals(c,"NOOP")) {
    h->hdrbuf="200 no reply.\r\n";
  } else if (case_starts(c,"HELP")) {
    h->hdrbuf="214-This is gatling (www.fefe.de/gatling/); No help available.\r\n214 See http://cr.yp.to/ftp.html for FTP help.\r\n";
  } else {
    static int funny;
    switch (++funny) {
    case 1: h->hdrbuf="550 The heck you say.\r\n"; break;
    case 2: h->hdrbuf="550 No, really?\r\n"; break;
    case 3: h->hdrbuf="550 Yeah, whatever...\r\n"; break;
    case 4: h->hdrbuf="550 How intriguing!\r\n"; break;
    default: h->hdrbuf="550 I'm just a simple FTP server, you know?\r\n"; funny=0; break;
    }
  }
ABEND:
  {
    char* d=array_start(&h->r);
    if (c>=d && c<=d+array_bytes(&h->r))
      iob_addbuf(&h->iob,h->hdrbuf,str_len(h->hdrbuf));
    else
      iob_addbuf_free(&h->iob,h->hdrbuf,str_len(h->hdrbuf));
  }
  io_dontwantread(s);
  io_wantwrite(s);
}

void handle_read_ftppassive(int64 i,struct http_data* H) {
  /* This is the server socket for a passive FTP data connections.
    * A read event means the peer established a TCP connection.
    * accept() it and close server connection */
  struct http_data* h;
  int n;
  h=io_getcookie(H->buddy);
  if (!h) {
    /* This used to be an assert() but it turns out it can be triggered.
     * I can't actually reproduce this but I think it happens if someone
     * does PASV and sends the connection but then drops the control
     * connection and we get that drop event before we get the read
     * event here signalling the incoming connection.  Now, if this
     * happens, just drop everything.  We got conned. */
    if (logging) {
      buffer_puts(buffer_1,"pasv_accept_without_buddy ");
      buffer_putulong(buffer_1,i);
      buffer_puts(buffer_1,"\nclose/statefail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    cleanup(i);
    return;
  }
  n=socket_accept6(i,H->myip,&H->myport,&H->myscope_id);
  if (n==-1) {
pasverror:
    if (logging) {
      buffer_puts(buffer_1,"pasv_accept_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/acceptfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    h->buddy=-1;
    free(H);
    io_close(i);
  } else {
    if (!io_fd_canwrite(n)) goto pasverror;
    io_nonblock(n);
    if (logging) {
      buffer_puts(buffer_1,"pasv_accept ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,n);
      buffer_puts(buffer_1,"\nclose/accepted ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    h->buddy=n;
#ifdef STATE_DEBUG
    H->myfd=n;
#endif
    io_setcookie(n,H);
    io_close(i);
    changestate(H,FTPSLAVE);
//    H->t=FTPSLAVE;
#ifdef TCP_NODELAY
    {
      int x=1;
      setsockopt(n,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));
    }
#endif
    if (h->f==WAITCONNECT) {
      h->f=LOGGEDIN;
      if (H->f==DOWNLOADING)
	io_wantwrite(h->buddy);
      else
	io_wantread(h->buddy);
    }
  }
}

void handle_write_ftpactive(int64 i,struct http_data* h) {
  struct http_data* H;
  H=io_getcookie(h->buddy);
  assert(H);
  if (socket_connect6(i,h->peerip,h->destport,h->myscope_id)==-1 && errno!=EISCONN) {
    if (logging) {
      buffer_puts(buffer_1,"port_connect_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/connectfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    H->buddy=-1;
    free(h);
    io_close(i);
  } else {
    if (logging) {
      char buf[IP6_FMT];
      buffer_puts(buffer_1,"port_connect ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_put(buffer_1,buf,fmt_ip6c(buf,h->peerip));
      buffer_putspace(buffer_1);
      buffer_put(buffer_1,buf,fmt_ulong(buf,h->destport));
      buffer_putnlflush(buffer_1);
    }
    changestate(h,FTPSLAVE);
//    h->t=FTPSLAVE;
#ifdef TCP_NODELAY
    {
      int x=1;
      setsockopt(i,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));
    }
#endif
    if (h->f != DOWNLOADING)
      io_dontwantwrite(i);
    if (H->f==WAITCONNECT) {
      H->f=LOGGEDIN;
      if (h->f==DOWNLOADING)
	io_wantwrite(H->buddy);
      else
	io_wantread(H->buddy);
    }
  }
}

#endif /* SUPPORT_FTP */


