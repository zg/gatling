#ifndef __FreeBSD__
#define _XOPEN_SOURCE 500
#endif

#include "gatling.h"

#include "buffer.h"
#include "fmt.h"
#include "ip6.h"
#include "mmap.h"
#include "str.h"
#include "textcode.h"
#include "scan.h"
#include "socket.h"
#include "case.h"
#include "ip4.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#ifdef __dietlibc__
#include <md5.h>
#elif defined(USE_POLARSSL)
#include <polarssl/md5.h>
#define MD5_CTX md5_context
#define MD5Init md5_starts
#define MD5Update md5_update
#define MD5Final(out,ctx) md5_finish(ctx,out)
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ctype.h>
#include <sys/socket.h>
#include <limits.h>

#include "havealloca.h"

char* defaultindex;

MD5_CTX md5_ctx;

char* http_header_blob(char* b,long l,char* h) {
  long i;
  long sl=str_len(h);
  for (i=0; i+sl+2<l; ++i)
    if (b[i]=='\n' && b[i+sl+1]==':' && case_equalb(b+i+1,sl,h)) {
      b+=i+sl+2;
      while (*b==' ' || *b=='\t') ++b;
      return b;
    }
  return 0;
}

char* http_header(struct http_data* r,char* h) {
  return http_header_blob(array_start(&r->r),array_bytes(&r->r),h);
}

static inline int issafe(unsigned char c) {
  return (c!='"' && c!='%' && (c>=' ' && c<0x7f) && c!='+' && c!=':' && c!='#');
}

size_t fmt_urlencoded(char* dest,const char* src,size_t len) {
  register const unsigned char* s=(const unsigned char*) src;
  size_t written=0,i;
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

void catencoded(array* a,char* s) {
  unsigned int len=str_len(s);
  char* buf=alloca(fmt_urlencoded(0,s,len));
  array_catb(a,buf,fmt_urlencoded(buf,s,len));
}

void cathtml(array* a,char* s) {
  unsigned int len=str_len(s);
  char* buf=alloca(fmt_html(0,s,len));
  array_catb(a,buf,fmt_html(buf,s,len));
}

void cathtmlutf8(array* a,char* s) {
  /* The purpose of this function is to convert a file name into UTF-8
   * and escape HTML-relevant characters such as '<' and '&'. Chars that
   * are not valid UTF-8 are assumed to be latin1 and converted */
  size_t i,l,r;
  char* buf;
  r=0;
  /* This will be a short string, a file name, so assuming all chars are
   * '&', the max expansion is '&amp;', i.e. *5. */
  l=strlen(s);
  buf=alloca(l*5);
  for (i=0; i<l; ++i) {
    if (s[i]&0x80) {
      size_t n=scan_utf8(s+i,l-i,NULL);
      if (n==0) {
	r+=fmt_utf8(buf+r,(unsigned char)(s[i]));
      } else {
	memcpy(buf+r,s+i,n);
	i+=n-1;
	r+=n;
      }
    } else {
      const char* x=0;
      size_t n;
      switch (s[i]) {
      case '&': x="&amp;"; n=5; break;
      case '<': x="&lt;"; n=4; break;
      case '>': x="&gt;"; n=4; break;
      case '\n': x="<br>"; n=4; break;
      }
      if (x) {
	memcpy(buf+r,x,n);
	r+=n;
      } else
	buf[r++]=s[i];
    }
  }
  array_catb(a,buf,r);
}


int http_dirlisting(struct http_data* h,DIR* D,const char* path,const char* arg) {
  long i,o,n;
  struct dirent* d;
  int (*sortfun)(de*,de*);
  array a,b,c;
  de* ab;
  byte_zero(&a,sizeof(a));
  byte_zero(&b,sizeof(b));
  byte_zero(&c,sizeof(c));
  o=n=0;
  while ((d=readdir(D))) {
    de* x=array_allocate(&a,sizeof(de),n);
    if (!x) break;
    x->name=o;
#ifdef __MINGW32__
    if (stat(d->d_name,&x->ss)==-1) continue;
#else
    if (lstat(d->d_name,&x->ss)==-1) continue;
    if (S_ISLNK(x->ss.st_mode)) {
      struct stat tmp;
      if (stat(d->d_name,&tmp)==0)
	if (S_ISDIR(tmp.st_mode))
	  x->todir=1;
    }
#endif
    array_cats0(&b,d->d_name);
    o+=str_len(d->d_name)+1;
    ++n;
  }
  closedir(D);
  if (array_failed(&a) || array_failed(&b)) {
    array_reset(&a);
    array_reset(&b);
    return 0;
  }
  base=array_start(&b);
  sortfun=sort_name_a;
  if (arg) {
    if (str_equal(arg,"N=D")) sortfun=sort_name_d;
    else if (str_equal(arg,"N=A")) sortfun=sort_name_a;
    else if (str_equal(arg,"M=A")) sortfun=sort_mtime_a;
    else if (str_equal(arg,"M=D")) sortfun=sort_mtime_d;
    else if (str_equal(arg,"S=A")) sortfun=sort_size_a;
    else if (str_equal(arg,"S=D")) sortfun=sort_size_d;
  }
  qsort(array_start(&a),n,sizeof(de),(int(*)(const void*,const void*))sortfun);
  array_cats(&c,"<title>Index of ");
  array_cats(&c,path);
  array_cats(&c,"</title>\n<h1>Index of ");
  array_cats(&c,path);
  {
    char* tmp=http_header(h,"User-Agent");
    /* don't give wget the column sorting interface so wget -m does not
     * mirror it needlessly */
    if (tmp && byte_equal(tmp,5,"Wget/"))
      array_cats(&c,"</h1>\n<table><tr><th>Name<th>Last Modified<th>Size\n");
    else {
      array_cats(&c,"</h1>\n<table><tr><th><a href=\"?N=");
      array_cats(&c,sortfun==sort_name_a?"D":"A");
      array_cats(&c,"\">Name</a><th><a href=\"?M=");
      array_cats(&c,sortfun==sort_mtime_a?"D":"A");
      array_cats(&c,"\">Last Modified</a><th><a href=\"?S=");
      array_cats(&c,sortfun==sort_size_a?"D":"A");
      array_cats(&c,"\">Size</a>\n");
    }
  }
  ab=array_start(&a);
  for (i=0; i<n; ++i) {
    char* name=base+ab[i].name;
    char buf[31];
    int j;
    struct tm* x=localtime(&ab[i].ss.st_mtime);
    if (name[0]=='.') {
      if (name[1]==0) continue; /* skip "." */
      if (name[1]!='.' || name[2]!=0)	/* skip dot-files */
	continue;
    }
    if (name[0]==':') name[0]='.';
    array_cats(&c,"<tr><td><a href=\"");
    catencoded(&c,base+ab[i].name);
    if (S_ISDIR(ab[i].ss.st_mode) || ab[i].todir) array_cats(&c,"/");
    array_cats(&c,"\">");
    cathtmlutf8(&c,base+ab[i].name);
#ifndef __MINGW32__
    if (S_ISLNK(ab[i].ss.st_mode)) array_cats(&c,"@"); else
#endif
    if (S_ISDIR(ab[i].ss.st_mode)) array_cats(&c,"/");
    array_cats(&c,"</a><td>");

    j=fmt_2digits(buf,x->tm_mday);
    j+=fmt_str(buf+j,"-");
    byte_copy(buf+j,3,months+3*x->tm_mon); j+=3;
    j+=fmt_str(buf+j,"-");
    j+=fmt_2digits(buf+j,(x->tm_year+1900)/100);
    j+=fmt_2digits(buf+j,(x->tm_year+1900)%100);
    j+=fmt_str(buf+j," ");
    j+=fmt_2digits(buf+j,x->tm_hour);
    j+=fmt_str(buf+j,":");
    j+=fmt_2digits(buf+j,x->tm_min);

    array_catb(&c,buf,j);
    array_cats(&c,"<td align=right>");
    array_catb(&c,buf,fmt_humank(buf,ab[i].ss.st_size));
  }
  array_cats(&c,"</table>");
  array_reset(&a);
  array_reset(&b);
  if (array_failed(&c)) return 0;
  h->bodybuf=array_start(&c);
  h->blen=array_bytes(&c);
  return 1;
}

int buffer_putlogstr(buffer* b,const char* s) {
  unsigned long l;
  char* x;
  for (l=0; s[l] && s[l]!='\r' && s[l]!='\n'; ++l) ;
  if (!l) return 0;
  x=alloca(l);
  return buffer_put(b,x,fmt_foldwhitespace(x,s,l));
}

#ifdef SUPPORT_PROXY
int add_proxy(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  int i;
  if (!x) return -1;
  byte_zero(x,sizeof(struct cgi_proxy));
  if (c[1]=='/') {
    if (c[0]=='F')
      x->proxyproto=FASTCGI;
    else if (c[0]=='S')
      x->proxyproto=SCGI;
    else if (c[0]=='H')
      x->proxyproto=HTTP;
    else
      goto nixgut;
    c+=2;
  }
  if (*c=='|') {
    const char* d;
    ++c;
    d=strchr(c,'|');
    if (!d) goto nixgut;
    if (d-c>sizeof(x->uds.sun_path)) goto nixgut;
    x->port=-1;
    x->uds.sun_family=AF_UNIX;
    memcpy(x->uds.sun_path,c,d-c);
    c=d+1;
  } else {
    uint16 tmp;
    i=scan_ip6if(c,x->ip,&x->scope_id);
    if (c[i]!='/') { nixgut: free(x); return -1; }
    c+=i+1;
    i=scan_ushort(c,&tmp);
    x->port=tmp;
    if (c[i]!='/') goto nixgut;
    c+=i+1;
  }
  if (regcomp(&x->r,c,REG_EXTENDED)) goto nixgut;
  if (!last)
    cgis=last=x;
  else
    last->next=x; last=x;
  return 0;
}

static size_t fmt_strblob(char* dst,const char* str,const char* blob,size_t n) {
  size_t x;
  if (!dst) return strlen(str)+n+1;
  x=fmt_str(dst,str);
  memcpy(dst+x,blob,n);
  x+=n;
  dst[x]='\n';
  return x+1;
}

static size_t fmt_cgivars(char* dst,struct http_data* h,const char* uri,size_t urilen,const char* vhostdir,size_t* headers) {
  /* input:
   *   dst: destination buffer, may be NULL
   *   h: http context, used to get to HTTP request
   *   uri: pointer to decoded URI, truncated at '?', after leading '/'
   *   urilen: last char in regex match
   *     uri="script.php/path_info"
   *                    ^ uri+urilen
   *   vhostdir: virtual hosting dir, e.g. "www.fefe.de:80" or "default"
   *   needs global: char serverroot[]
   * output:
   *   returns number of bytes written to dst
   *   if dst is NULL, returns number of buffer size needed
   *   writes environment entries to dst, separated by \n
   *   writes count of headers written to *headers if non-NULL
   */
  char remoteaddr[IP6_FMT];
  char myaddr[IP6_FMT];
  char tmp[FMT_ULONG];
  size_t n,s,hc;
  s=0;

  while (urilen && uri[0]=='/') { ++uri; --urilen; }

  remoteaddr[fmt_ip6c(remoteaddr,h->peerip)]=0;
  myaddr[fmt_ip6c(myaddr,h->myip)]=0;

  {
    char* x=http_header(h,"Content-Length");
    if (x) {
      size_t j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
      n=fmt_strblob(dst,"CONTENT_LENGTH=",x,j);
    } else {
      n=fmt_str(dst,"CONTENT_LENGTH=0\n");
    }
    s+=n; if (dst) dst+=n;
  }

  n=fmt_strm(dst,"SERVER_SOFTWARE=gatling\n"); s+=n; if (dst) dst+=n;
  {
    char* x=http_header(h,"Host");
    if (x) {
      size_t j;
      for (j=0; x[j]!=':' && x[j]!='\r' && x[j]!='\n'; ++j) ;
      n=fmt_strblob(dst,"SERVER_NAME=",x,j);
    } else
      n=fmt_strm(dst,"SERVER_NAME=",remoteaddr,"\n");
    s+=n; if (dst) dst+=n;
  }
  n=fmt_strm(dst,"SERVER_ADDR=",myaddr,"\n"); s+=n; if (dst) dst+=n;
  tmp[fmt_ulong(tmp,h->myport)]=0;
  n=fmt_strm(dst,"SERVER_PORT=",tmp,"\n"); s+=n; if (dst) dst+=n;
  n=fmt_strm(dst,"REMOTE_ADDR=",remoteaddr,"\n"); s+=n; if (dst) dst+=n;
  tmp[fmt_ulong(tmp,h->peerport)]=0;
  n=fmt_strm(dst,"REMOTE_PORT=",tmp,"\n"); s+=n; if (dst) dst+=n;
  n=fmt_strm(dst,"DOCUMENT_ROOT=",serverroot,"/",vhostdir,"\n"); s+=n; if (dst) dst+=n;
  n=fmt_strm(dst,"GATEWAY_INTERFACE=CGI/1.1\nSERVER_PROTOCOL=HTTP/1.1\n"); s+=n; if (dst) dst+=n;
  {
    char* x=array_start(&h->r);
    size_t z,y=str_chr(x,' ');
    n=fmt_strblob(dst,"REQUEST_METHOD=",x,y); s+=n; if (dst) dst+=n;
    x+=y+1;
    y=str_chr(x,' ');
    /* REQUEST_URI is not actually part of the CGI 1.1 spec (RFC3875) */
    n=fmt_strblob(dst,"REQUEST_URI=",x,y); s+=n; if (dst) dst+=n;
    z=byte_chr(x,y,'?')+1;
    if (z<y) {
      n=fmt_strblob(dst,"QUERY_STRING=",x+z,y-z); s+=n; if (dst) dst+=n;
    }

    n=fmt_strblob(dst,"SCRIPT_NAME=/",uri,urilen); s+=n; if (dst) dst+=n;
    n=fmt_strm(dst,"SCRIPT_FILENAME=",serverroot,"/",vhostdir); s+=n; if (dst) dst+=n;
    n=fmt_strblob(dst,"/",uri,urilen); s+=n; if (dst) dst+=n;

    if (uri[urilen]=='/') {	/* we have a PATH_INFO */
      /* the situation is like this:
	 uri="script.cgi/pathinfo"
	                ^urilen
      */

      n=fmt_strm(dst,"PATH_INFO=",uri+urilen,"\n"); s+=n; if (dst) dst+=n;

      /* PATH_TRANSLATED is "$PWD$PATH_INFO" */
      while (uri[urilen]=='/') ++urilen;
      n=fmt_strm(dst,"PATH_TRANSLATED=",serverroot,"/",vhostdir,"/",uri+urilen,"\n"); s+=n; if (dst) dst+=n;
    }

  }

  hc=17;
  if (h->proxyproto==SCGI) {
    n=fmt_strm(dst,"SCGI=1\n"); s+=n; if (dst) dst+=n;
    ++hc;
  }

#ifdef SUPPORT_HTTPS
  if (h->t == HTTPSPOST) {
    n=fmt_strm(dst,"HTTPS=1\n"); s+=n; if (dst) dst+=n;
    ++hc;
  }
#endif

  /* now translate all header lines into HTTP_* */
  /* for example Accept: -> HTTP_ACCEPT= */
  {
    char* x=array_start(&h->r);
    char* max=x+array_bytes(&h->r);
    for (; x<max && *x!='\n'; ++x) ;
    while (x) {
      char* olddst=dst;
      ++x;
      if (*x<=' ') break;
      if (!case_starts(x,"Content-Length:") && !case_starts(x,"Content-Type:")) {
	n=fmt_strm(dst,"HTTP_"); s+=n; if (dst) dst+=n;
      }
      while (*x!=':') {
	char c=*x;
	if (c>='a' && c<='z') c-='a'-'A';	/* toupper */
	if (c=='-') c='_'; else
	if (c<'A' || c>'Z') {
	  dst=olddst;
	  goto skipheader;
	}
	if (dst) { *dst=c; ++dst; } ++s;
	++x;
      }
      if (dst) { *dst='='; ++dst; } ++s;
      ++x; while (*x==' ') ++x;
      {
	char* start=x;
	while (*x && *x!='\r' && *x!='\n') ++x;
	n=x-start;
	if (dst) { byte_copy(dst,n,start); dst+=n+1; dst[-1]='\n'; } s+=n+1;
      }
      ++hc;
skipheader:
      x=strchr(x,'\n');
    }
    if (headers) *headers=hc;
  }
  return s;
}

static int proxy_connection(int sockfd,char* c,const char* dir,struct http_data* ctx_for_sockfd,int isexec,const char* args) {
  /* c is the filename
   * dir is the virtual hosting dir ("www.fefe.de:80")
   * the current working directory is inside the virtual hosting dir */
  struct cgi_proxy* x=cgis;
  struct stat ss;
  regmatch_t matches;

  /* if isexec is set, we already found that .proxy is there */
  if (!isexec && stat(".proxy",&ss)==-1) return -3;
  while (x) {
    if (x->file_executable && (!isexec || x->port)) {
      x=x->next;
      continue;
    }

    matches.rm_so=matches.rm_eo=0;
    if (x->file_executable || regexec(&x->r,c,1,&matches,0)==0) {
      /* if the port is zero, then use local execution proxy mode instead */
      int fd_to_gateway;
      struct http_data* ctx_for_gatewayfd;
      char* d=c;
      while (*d=='/') ++d;

      ctx_for_sockfd->proxyproto=x->proxyproto;

      if (!(ctx_for_gatewayfd=(struct http_data*)malloc(sizeof(struct http_data)))) return -1;
      byte_zero(ctx_for_gatewayfd,sizeof(struct http_data));
      ctx_for_gatewayfd->filefd=-1;

      if (!x->file_executable) {

#if 0
	printf("%u %u\n",matches.rm_so,matches.rm_eo);
	printf("got data \"%s\"\n",c+matches.rm_eo);
#endif

	/* for SCGI and FASTCGI we expect the file to exist */
	if (x->proxyproto == SCGI || x->proxyproto == FASTCGI) {
	  struct stat ss;
	  /* does the file actually exist? */
	  if (stat(d,&ss)) {
	    if (errno==ENOTDIR) {	/* we have PATH_INFO */
	      char save=c[matches.rm_eo];
	      int r;
	      c[matches.rm_eo]=0;
	      r=stat(d,&ss);
	      c[matches.rm_eo]=save;
	      if (r) goto freeandfail;
	    } else {
freeandfail:
	      free(ctx_for_gatewayfd);
	      return -1;
	    }
	  }
	}
	ctx_for_gatewayfd->proxyproto=x->proxyproto;
	if (x->proxyproto == SCGI) {
	  size_t l=fmt_cgivars(0,ctx_for_sockfd,c,matches.rm_eo,dir,0);
	  char* x,* y;
	  /* array_allocate gets the index of the last element you want
	   * to access, not the number of bytes; so +1, not +2 */
	  if (!array_allocate(&ctx_for_gatewayfd->r,1,l+fmt_ulong(0,l)+1))
	    goto freeandfail;
	  x=array_start(&ctx_for_gatewayfd->r);
	  x+=fmt_ulong(x,l);
	  *x++=':';
	  y=x;
	  x+=fmt_cgivars(x,ctx_for_sockfd,c,matches.rm_eo,dir,0);

	  /* fmt_cgivars uses "FOO=bar\n" but we want "FOO\000bar\000" */
	  while (y<x) {
	    if (*y=='=') {
	      *y=0;
	      while (y<x) {
		if (*y=='\n') { *y=0; break; }
		++y;
	      }
	    }
	    ++y;
	  }

	  *x=',';
	} else if (x->proxyproto == FASTCGI) {
	  size_t hc;
	  size_t l=fmt_cgivars(0,ctx_for_sockfd,c,matches.rm_eo,dir,&hc);
	  char* x,* y;
	  /* fmt_cgivars writes "FOO=barbaz\n" but we need
	   * "\003\006FOObarbaz"; if a key or value is longer than 127,
	   * the length takes up four bytes instead of one.  A
	   * conservative upper bound on additional space used is 
	   * thus the number of headers (hc) times 6. */

	  /* space calculation with fastcgi boilerplate overhead:
	   * 16 for {FCGI_BEGIN_REQUEST,   1, {FCGI_RESPONDER, 0}}
	   * 8 for {FCGI_PARAMS,          1, ...}
	   * l for the actual params
	   * 8 for {FCGI_PARAMS,          1, ""}
	   * 8 for {FCGI_STDIN,           1, ""}
	   */
	  if (!array_allocate(&ctx_for_gatewayfd->r,1,l+hc*6+16+8+8+8+2))
	    goto freeandfail;
	  x=array_start(&ctx_for_gatewayfd->r);
	  byte_copy(x,24,"\x01\x01\x00\x01\x00\x08\x00\x00" /* FCGI_Record: FCGI_BEGIN_REQUEST (1) */
			 "\x00\x01\x00\x00\x00\x00\x00\x00" /* FCGI_BeginRequestBody */
			 "\x01\x04\x00\x01\x00\x00\x00\x00" /* FCGI_Record: FCGI_PARAMS (4) */
			);
	  /* We need to convert the key-value pairs, but unfortunately
	   * that expansion may require more space than the unexpanded
	   * version.  So we allocate for the worst case and write the
	   * original towards the end of the allocated space, so we can
	   * expand inside the same buffer. */
	  y=x+hc*6+16+8+8+8+2;
	  fmt_cgivars(y,ctx_for_sockfd,c,matches.rm_eo,dir,&hc);
	  x+=24;
	  {
	    size_t a=0;
	    size_t b;
	    size_t kl,vl,prev;
	    for (b=kl=vl=prev=0; b<l; ++b) {
	      if (y[b]=='=' && kl==0) {
		kl=b-prev;
		prev=b+1;
	      } else if (y[b]=='\n') {
		vl=b-prev;
		prev=b+1;
		if (kl<127) {
		  x[a]=kl;
		  ++a;
		} else {
		  uint32_pack_big(x+a,kl|0x80000000u);
		  a+=4;
		}
		if (vl<127) {
		  x[a]=vl;
		  ++a;
		} else {
		  uint32_pack_big(x+a,vl|0x80000000u);
		  a+=4;
		}
		byte_copy(x+a,kl,y+b-vl-kl-1); a+=kl;
		byte_copy(x+a,vl,y+b-vl); a+=vl;
		kl=0; vl=0;
	      }
	    }
	    x[a]=x[a+1]=0; a+=2;
	    x[-4]=a>>8;	/* adjust length field in FCGI_Record */
	    x[-3]=a&0xff;
	    array_truncate(&ctx_for_gatewayfd->r,1,a+24+8+8);
	    x+=a;
	    byte_copy(x,8,"\x01\x04\x00\x01\x00\x00\x00\x00"); /* FCGI_Record: FCGI_PARAMS (4) */
	    x+=8;

	    {
	      char* cl=http_header(ctx_for_sockfd,"Content-Length");
	      unsigned long long content_length=0;
	      if (cl) {
		char c;
		if ((c=cl[scan_ulonglong(cl,&content_length)])!='\r' && c!='\n') content_length=0;
	      }
	      if (content_length)
		array_truncate(&ctx_for_gatewayfd->r,1,a+24+8); /* shave off 8 bytes */
	      else {
		byte_copy(x,8,"\x01\x05\x00\x01\x00\x00\x00\x00"); /* FCGI_Record: FCGI_STDIN (5) */
		x+=8;
	      }
	    }
	  }
	} else if (x->proxyproto==HTTP) {
	  size_t size_of_header=header_complete(ctx_for_sockfd,sockfd);
	  size_t i;
	  char* x=array_start(&ctx_for_sockfd->r);
	  for (i=0; i<size_of_header && x[i]!='\n'; ++i)
	    if (x[i]==0) x[i]=' ';
	  array_catb(&ctx_for_gatewayfd->r,x,size_of_header);
	}
      }

      if (logging) {
	char buf[IP6_FMT+10];
	char* tmp;
	const char* method="???";
	{
	  int x;
	  x=fmt_ip6c(buf,ctx_for_gatewayfd->myip);
	  x+=fmt_str(buf+x,"/");
	  x+=fmt_ulong(buf+x,ctx_for_gatewayfd->myport);
	  buf[x]=0;
	}
	tmp=array_start(&ctx_for_sockfd->r);
#ifdef SUPPORT_HTTPS
	switch (*tmp) {
	case 'H': method=(ctx_for_sockfd->t==HTTPREQUEST)?"HEAD":"HEAD/SSL"; break;
	case 'G': method=(ctx_for_sockfd->t==HTTPREQUEST)?"GET":"GET/SSL"; break;
	case 'P':
		  if (tmp[1]=='O')
		    method=(ctx_for_sockfd->t==HTTPREQUEST)?"POST":"POST/SSL";
#ifdef SUPPORT_DAV
		  else if (tmp[1]=='R')
		    method=(ctx_for_sockfd->t==HTTPREQUEST)?"PROPFIND":"PROPFIND/SSL";
#endif
		  else
		    method=(ctx_for_sockfd->t==HTTPREQUEST)?"PUT":"PUT/SSL";
		  break;
	}
#else
	switch (*tmp) {
	case 'H': method="HEAD"; break;
	case 'G': method="GET"; break;
	case 'P': method=(tmp[1]=='O')?"POST":
#ifdef SUPPORT_DAV
		  ((tmp[1]=='R')?"PROPFIND":"PUT");
#else
		  "PUT";
#endif
		  break;
	}
#endif
	buffer_putm(buffer_1,method,x->port?"/PROXY ":"/CGI ");
	buffer_putulong(buffer_1,sockfd);
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,c);
	if (args) {
	  buffer_puts(buffer_1,"?");
	  buffer_putlogstr(buffer_1,args);
	}
	buffer_puts(buffer_1," 0 ");
	buffer_putlogstr(buffer_1,(tmp=http_header(ctx_for_sockfd,"User-Agent"))?tmp:"[no_user_agent]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(ctx_for_sockfd,"Referer"))?tmp:"[no_referrer]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(ctx_for_sockfd,"Host"))?tmp:buf);
	buffer_putsflush(buffer_1,"\n");
      }
      ++rps1;

      if (x->port) {
	/* proxy mode */
	if (x->port>0xffff) {	/* unix domain socket mode */
	  fd_to_gateway=socket(AF_UNIX,SOCK_STREAM,0);
	} else
	  fd_to_gateway=socket_tcp6();
#ifdef STATE_DEBUG
	ctx_for_gatewayfd->myfd=fd_to_gateway;
#endif
	if (fd_to_gateway==-1) goto punt2;
	changestate(ctx_for_gatewayfd,PROXYSLAVE);
	if (!io_fd(fd_to_gateway)) {
punt:
	  io_close(fd_to_gateway);
punt2:
	  array_reset(&ctx_for_gatewayfd->r);
	  free(ctx_for_gatewayfd);
	  return -1;
	}
	io_block(fd_to_gateway);
	io_eagain(fd_to_gateway);
	if (x->port>0xffff) {
	  if (connect(fd_to_gateway,(struct sockaddr*)&x->uds,sizeof(x->uds))==-1)
	    if (errno!=EINPROGRESS)
	      goto punt;
	} else {
	  if (socket_connect6(fd_to_gateway,x->ip,x->port,x->scope_id)==-1)
	    if (errno!=EINPROGRESS)
	      goto punt;
	}
	io_fd_canwrite(fd_to_gateway);
	if (logging) {
	  char tmp[100];
	  char bufsockfd[FMT_ULONG];
	  char bufs[FMT_ULONG];
	  char bufport[FMT_ULONG];

	  bufsockfd[fmt_ulong(bufsockfd,sockfd)]=0;
	  bufs[fmt_ulong(bufs,fd_to_gateway)]=0;
	  if (x->port>0xffff) {
	    buffer_putm(buffer_1,"proxy_connect ",bufsockfd," ",bufs," ",x->uds.sun_path," ");
	  } else {
	    bufport[fmt_ulong(bufport,x->port)]=0;
	    tmp[fmt_ip6ifc(tmp,x->ip,x->scope_id)]=0;

	    buffer_putm(buffer_1,"proxy_connect ",bufsockfd," ",bufs," ",tmp,"/",bufport," ");
	  }
	  buffer_putlogstr(buffer_1,c);
	  buffer_putnlflush(buffer_1);
	}
	io_wantwrite(fd_to_gateway);
#ifdef SUPPORT_CGI
      } else {
	/* local CGI mode */
	uint32 a,len; uint16 b;
	pid_t pid;
	size_t reqlen;
	char* req=array_start(&ctx_for_sockfd->r); /* "GET /t.cgi/foo/bar?fnord HTTP/1.0\r\nHost: localhost:80\r\n\r\n"; */
	char ra[IP6_FMT];
	req[strlen(req)]=' ';

	{
	  char* tmp;
	  reqlen=0;
	  for (tmp=req; tmp; tmp=strchr(tmp,'\n')) {
	    if (tmp[1]=='\r' && tmp[2]=='\n') {
	      reqlen=tmp+2-req;
	      break;
	    } else if (tmp[1]=='\n') {
	      reqlen=tmp+1-req;
	      break;
	    }
	    ++tmp;
	  }
	}

	ctx_for_sockfd->keepalive=0;
	ra[fmt_ip6c(ra,ctx_for_sockfd->peerip)]=0;
	a=reqlen; write(forksock[0],&a,4);
	a=strlen(dir); write(forksock[0],&a,4);
	a=strlen(ra); write(forksock[0],&a,4);
	write(forksock[0],req,reqlen);
	write(forksock[0],dir,strlen(dir));
	write(forksock[0],ra,strlen(ra));
	b=ctx_for_sockfd->peerport; write(forksock[0],&b,2);
	b=ctx_for_sockfd->myport; write(forksock[0],&b,2);
#ifdef SUPPORT_HTTPS
	{
	  char ssl=ctx_for_sockfd->t==HTTPSREQUEST;
	  write(forksock[0],&ssl,1);
	}
#endif

	read(forksock[0],&a,4);		/* code; 0 means OK */
	read(forksock[0],&len,4);	/* length of error message */
	read(forksock[0],&pid,sizeof(pid));
	if (len) {
	  char* c=alloca(len+1);
	  read(forksock[0],c,len);
	  c[len]=0;
	  httperror(ctx_for_sockfd,"502 Gateway Broken",c,*ctx_for_sockfd->r.p=='H'?1:0);
	  free(ctx_for_gatewayfd);
	  return -1;
	} else {
	  fd_to_gateway=io_receivefd(forksock[0]);
#ifdef STATE_DEBUG
	  ctx_for_gatewayfd->myfd=fd_to_gateway;
#endif
	  changestate(ctx_for_gatewayfd,PROXYPOST);
	  if (fd_to_gateway==-1) {
	    buffer_putsflush(buffer_2,"received no file descriptor for CGI\n");
	    free(ctx_for_gatewayfd);
	    return -1;
	  }
	  if (!io_fd_canwrite(fd_to_gateway)) {
	    httperror(ctx_for_sockfd,"502 Gateway Broken",c,*ctx_for_sockfd->r.p=='H'?1:0);
	    io_close(fd_to_gateway);
	    free(ctx_for_gatewayfd);
	    return -1;
	  }
	}
#ifdef SUPPORT_HTTPS
	if (ctx_for_sockfd->t==HTTPSREQUEST)
	  changestate(ctx_for_sockfd,HTTPSPOST);
	else
#endif
	changestate(ctx_for_sockfd,HTTPPOST);
	if (logging) {
	  char bufsfd[FMT_ULONG];
	  char bufs[FMT_ULONG];
	  char bufpid[FMT_ULONG];

	  bufsfd[fmt_ulong(bufsfd,sockfd)]=0;
	  bufs[fmt_ulong(bufs,fd_to_gateway)]=0;
	  bufpid[fmt_ulong(bufpid,pid)]=0;

	  buffer_putmflush(buffer_1,"cgi_fork ",bufsfd," ",bufs," ",bufpid,"\n");
	}
#endif
      }

      ctx_for_gatewayfd->buddy=sockfd;
      ctx_for_sockfd->buddy=fd_to_gateway;
      io_setcookie(fd_to_gateway,ctx_for_gatewayfd);

     /* Have:
      *   - the header and possibly some data left in ctx_for_sockfd->r.
      * Want:
      *   - leave the data (not the header) in ctx_for_sockfd->r.
      *   - set ctx_for_gatewayfd->still_to_copy to Content-Length.
      *   - set ctx_for_sockfd->still_to_copy to Content-Length -
      *     the size of the copied data.  If that is non-zero, set t to
      *     HTTPPOST.
      */

      {
	char* cl=http_header(ctx_for_sockfd,"Content-Length");
	unsigned long long content_length=0;
	if (cl) {
	  char c;
	  if ((c=cl[scan_ulonglong(cl,&content_length)])!='\r' && c!='\n') content_length=0;
	}

	ctx_for_gatewayfd->still_to_copy=content_length;

	/* If the client sent "Expect: 100-continue", do so */
	{
	  char* e=http_header(ctx_for_sockfd,"Expect");
	  if (e && byte_equal(e,4,"100-")) {
	    const char contmsg[]="HTTP/1.1 100 Continue\r\n\r\n";
	    /* if this fails, tough luck.  I'm not bloating my state
	      * engine for this crap. */
#ifdef SUPPORT_HTTPS
	    if (ctx_for_sockfd->t==HTTPSREQUEST)
#if defined(USE_OPENSSL)
	      SSL_write(ctx_for_sockfd->ssl,contmsg,sizeof(contmsg)-1);
#elif defined(USE_POLARSSL)
	      ssl_write(&ctx_for_sockfd->ssl,(const unsigned char*)contmsg,sizeof(contmsg)-1);
#else
#warn fixme update SSL code in http.c
#endif
	    else
#endif
	    io_trywrite(sockfd,contmsg,sizeof(contmsg)-1);
	  }
	}

	/* figure out how much data we have */
	{
	  size_t size_of_header=header_complete(ctx_for_sockfd,sockfd);
	  size_t size_of_data_in_packet=array_bytes(&ctx_for_sockfd->r) - size_of_header - 1;
	    /* the -1 is for the \0 we appended */

//	  printf("proxy_connection: size_of_header=%lu, size_of_data_in_packet=%lu, content_length=%lu\n",size_of_header,size_of_data_in_packet,content_length);

#ifdef SUPPORT_HTTPS
	  if (ctx_for_sockfd->t==HTTPSREQUEST)
	    changestate(ctx_for_sockfd,HTTPSPOST);
	  if (ctx_for_sockfd->t!=HTTPSPOST)
#endif
	  changestate(ctx_for_sockfd,HTTPPOST);

	  /* slight complication: we might have more data already than
	   * we need for this request, if the content length is small
	   * and the client uses pipelining and added the next request
	   * already. */
	  if (size_of_data_in_packet > content_length)
	    size_of_data_in_packet = content_length;

	  if (size_of_data_in_packet) {
	    byte_copy(array_start(&ctx_for_sockfd->r),
		      size_of_data_in_packet,
		      array_start(&ctx_for_sockfd->r)+size_of_header);
	    array_truncate(&ctx_for_sockfd->r,1,size_of_data_in_packet);
	  } else
	    array_trunc(&ctx_for_sockfd->r);
	  ctx_for_sockfd->still_to_copy=content_length;

	  if (ctx_for_gatewayfd->still_to_copy && array_bytes(&ctx_for_sockfd->r))
	    io_wantwrite(fd_to_gateway);
	  else
	    io_wantread(fd_to_gateway);

	  if (ctx_for_sockfd->still_to_copy)
	    io_wantread(sockfd);
	  else
	    io_dontwantread(sockfd);

//	  printf("proxy_connection: ctx_for_sockfd->still_to_copy=%lu, ctx_for_gatewayfd->still_to_copy=%lu\n",ctx_for_sockfd->still_to_copy, ctx_for_gatewayfd->still_to_copy);

	}
      }

      if (timeout_secs)
	io_timeout(fd_to_gateway,next);
      return fd_to_gateway;
    }
    x=x->next;
  }
  return -2;
}

int proxy_write_header(int sockfd,struct http_data* h) {
  /* assume we can write the header in full. */
  /* slight complication: we need to turn keep-alive off and we need to
   * add a X-Forwarded-For header so the handling web server can write
   * the real IP to the log file. */
  struct http_data* H=io_getcookie(h->buddy);
  int i,j=0;
  long hlen=array_bytes(&h->r);
  char* hdr=array_start(&h->r);
  char* newheader=0;
  if (h->proxyproto==HTTP) {
    newheader=alloca(hlen+200);
    for (i=j=0; i<hlen; ) {
      int k=str_chr(hdr+i,'\n');
      if (k==0) break;
      if (case_starts(hdr+i,"Connection: ") || case_starts(hdr+i,"X-Forwarded-For: "))
	i+=k+1;
      else {
	byte_copy(newheader+j,k+1,hdr+i);
	i+=k+1;
	j+=k+1;
      }
    }
    if (j) j-=2;
    H->keepalive=0;
    j+=fmt_str(newheader+j,"Connection: close\r\nX-Forwarded-For: ");
    j+=fmt_ip6c(newheader+j,H->peerip);
    j+=fmt_str(newheader+j,"\r\n\r\n");
  } else if (h->proxyproto==FASTCGI || h->proxyproto==SCGI) {
    newheader=array_start(&h->r);
    j=array_bytes(&h->r);
  }
  if (write(sockfd,newheader,j)!=j)
    return -1;
  if (h->proxyproto==SCGI)
    array_trunc(&h->r);
  H->sent+=j;
  return 0;
}



int proxy_is_readable(int sockfd,struct http_data* H) {
  /* read data from proxy and queue it for writing to browser
   * connection, also add "HTTP/1.0 200 OK" header if necessary */
  char Buf[8194];
  char* buf=Buf+1;
  int i;
  char* x;
  struct http_data* peer=io_getcookie(H->buddy);
  if (!peer) return -1;
  i=read(sockfd,buf,sizeof(Buf)-2);
  if (i==-1) return -1;
  H->sent+=i;
  /* TODO: need to parse fastcgi packets from proxy, remove fastcgi
   * headers */
  if (i==0) {
eof:
    if (logging) {
      char numbuf[FMT_ULONG];
      char r[FMT_ULONG];
      char s[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,sockfd)]=0;
      r[fmt_ulonglong(r,peer->received)]=0;
      s[fmt_ulonglong(s,H->sent)]=0;
      buffer_putmflush(buffer_1,"cgiproxy_read0 ",numbuf," ",r," ",s,"\n");
    }
    if (H->buddy) peer->buddy=-1;
#ifdef SUPPORT_HTTPS
#ifdef USE_OPENSSL
    if (peer->t == HTTPSPOST)
      SSL_shutdown(peer->ssl);
#endif
#endif
    cleanup(sockfd);
    return -3;
  } else {
    int needheader=0;
    size_t cl=0,rs=0;
    int gotone=0;

    if (H->proxyproto==FASTCGI) {
      /* For FastCGI, we get the data in packets, which we need to parse.
      * Which also means we have to deal with partial packets.  We do
      * this by putting the packets in our H->r until we have assembled
      * one. */
      array_catb(&H->r,buf,i);
      if (array_failed(&H->r)) return -1;
nextpacket:
      x=array_start(&H->r);
      rs=array_bytes(&H->r);
      if (rs<8) return 0;	/* not done, need more data */
      /* we have a header */
      errno=EINVAL;
      if (x[0]!=1) return -1;
      /* we expect one of FCGI_STDOUT, FCGI_STDERR, or
	* FCGI_END_REQUEST */
      if (x[1]!=6 && x[1]!=7 && x[1]!=3) return -1;
      /* the request ID must be 1, because that is what we sent */
      if (x[2]!=0 || x[3]!=1) return -1;
      cl=((unsigned char)x[4]<<8)|(unsigned char)x[5];
      if (rs<8+cl+(unsigned char)(x[6])) {
	if (gotone) goto success;
	return 0;	/* not done, need more data */
      }
      /* got enough data for one packet.  look at packet. */
      if (x[1]==3) {
	io_wantwrite(H->buddy);
	H->buddy=-1;
	goto eof;	/* FCGI_END_REQUEST */
      }
      if (x[1]==6) { /* FCGI_STDOUT */
	buf=x+8;
	i=cl;
      }
    }

    if (!H->havefirst) {
      H->havefirst=1;
      if (H->proxyproto==SCGI || H->proxyproto==FASTCGI) {
	if (case_starts(buf,"Status:")) {
	  --buf; ++i;
	  memcpy(buf,"HTTP/1.1 ",9);
	} else
	  needheader=1;
      } else if (byte_diff(buf,5,"HTTP/"))
	/* No "HTTP/1.0 200 OK", need to write our own header. */
	needheader=1;
    }
    if (needheader) {
      size_t j;
      x=malloc(i+100);
      if (!x) goto nomem;
      j=fmt_str(x,"HTTP/1.1 200 Here you go\r\nServer: " RELEASE "\r\n");
      byte_copy(x+j,i,buf);
      i+=j;
    } else {
      x=malloc(i);
      if (!x) goto nomem;
      byte_copy(x,i,buf);
    }
    iob_addbuf_free(&peer->iob,x,i);
    gotone=1;

    if (H->proxyproto==FASTCGI) {
    /* now, if we got this far, we need to remove the packet from the
     * buffer */
      x=array_start(&H->r);
      cl+=8+(unsigned char)(x[6]);
      if (rs>cl) byte_copy(x,rs-cl,x+cl);
      array_truncate(&H->r,1,rs-cl);
      if (rs>cl && rs-cl>=8) goto nextpacket;
    }
  }
success:
  io_dontwantread(sockfd);
  io_wantwrite(H->buddy);
  return 0;
nomem:
  if (logging) {
    char numbuf[FMT_ULONG];
    numbuf[fmt_ulong(numbuf,sockfd)]=0;
    buffer_putmflush(buffer_1,"outofmemory ",numbuf,"\n");
  }
  cleanup(sockfd);
  return -1;
}

int read_http_post(int sockfd,struct http_data* H) {
  /* read post data from browser, write to proxy */
  char buf[8192];
  int i;
  unsigned long long l=H->still_to_copy;
  if (l>sizeof(buf)) l=sizeof(buf);
#ifdef SUPPORT_HTTPS
  if (H->t==HTTPSPOST) {
#ifdef USE_OPENSSL
    i=SSL_read(H->ssl,buf,l);
    if (i<0) {
      i=SSL_get_error(H->ssl,i);
      if (i==SSL_ERROR_WANT_READ || i==SSL_ERROR_WANT_WRITE) {
#elif defined(USE_POLARSSL)
    i=ssl_read(&H->ssl,(unsigned char*)buf,l);
    if (i<0) {
      if (l==POLARSSL_ERR_NET_WANT_READ || l==POLARSSL_ERR_NET_WANT_WRITE) {
#endif
	io_eagain(sockfd);
	if (handle_ssl_error_code((int)sockfd,i,1)==-1)
	  return -1;
      }
      return 0;
    }
#ifdef USE_OPENSSL
    if (i==0 && (H->t == HTTPSPOST || H->t == HTTPSREQUEST))
      SSL_shutdown(H->ssl);
#endif
  } else
#endif
  i=read(sockfd,buf,l);
#ifdef MOREDEBUG
  printf("read_http_post: want to read %ld bytes from %d; got %d\n",(long)l,sockfd,i);
#endif
  if (i<1) return -1;

  H->received+=i;
  H->still_to_copy-=i;
#ifdef MOREDEBUG
  printf("still_to_copy read_http_post: %p %llu -> %llu\n",H,H->still_to_copy+i,H->still_to_copy);
#ifdef STATE_DEBUG
  {
    struct http_data* mybuddy=io_getcookie(H->buddy);
    printf("read_http_post: my state is %s, my buddy's state is %s\n",state2string(H->t),state2string(mybuddy->t));
  }
#endif
#endif
  /* we got some data.  Now, for FastCGI we need to add a header before
   * writing it to the proxy */
  if (H->proxyproto==FASTCGI) {
    char tmp[8]="\x01\x05\x00\x01\x00\x00\x00\x00";
    tmp[4]=i>>8;
    tmp[5]=i&0xff;

    array_catb(&H->r,tmp,8); /* FCGI_Record: FCGI_STDIN (5) */
  }
  array_catb(&H->r,buf,i);
  if (H->proxyproto==FASTCGI && H->still_to_copy==0) {
    array_catb(&H->r,"\x01\x05\x00\x01\x00\x00\x00\x00",8); /* FCGI_Record: FCGI_STDIN (5) */
  }
  if (array_failed(&H->r))
    return -1;
  return 0;
}

#endif




#ifdef SUPPORT_HTACCESS
/* check whether there is a .htaccess file in the current directory.
 * if it is, expect the following format:

Realm
username:password
username2:password2
...

 * Realm is the HTTP realm (transmitted in the http authentication
 * required message and usually displayed by the browser).  Only basic
 * authentication is supported.  Please note that .htaccess files are
 * not looked for in other directories.  If you want subdirectories
 * covered, use hard or symbolic links.  The function returns 0 if the
 * authentication was OK or -1 if authentication is needed (the HTTP
 * response was then already written to the iob). */
int http_dohtaccess(struct http_data* h,const char* filename,int nobody) {
  size_t filesize;
  const char* map;
  const char* s;
  char* auth;
  char* realm;
  int r=0;
  map=mmap_read(filename,&filesize);
  if (!map) return 1;
  for (s=map; (s<map+filesize) && (*s!='\n'); ++s);		/* XXX */
  if (s>=map+filesize) goto done;
  realm=alloca(s-map+1);
  memmove(realm,map,s-map);
  realm[s-map]=0;
  ++s;
  auth=http_header(h,"Authorization");
  if (auth) {
    if (str_start(auth,"Basic ")) {
      char* username,* password;
      char* decoded;
      int i;
      size_t l,dl,ul;
      auth+=6;
      while (*auth==' ' || *auth=='\t') ++auth;
      i=str_chr(auth,'\n');
      if (i && auth[i-1]=='\r') --i;
      decoded=alloca(i+1);
      l=scan_base64(auth,decoded,&dl);
      if (auth[l]!='\n' && auth[l]!='\r') goto needauth;
      decoded[dl]=0;
      l=str_rchr(decoded,':');
      if (decoded[l]!=':') goto needauth;
      username=decoded; ul=l;
      decoded[l]=0; password=decoded+l+1;

      for (l=0; l<filesize; ) {
	while (l<filesize && map[l]!='\n') ++l; if (map[l]=='\n') ++l;
	if (l>=filesize) break;
	if (byte_equal(map+l,ul,username) && map[l+ul]==':') {
	  char* crypted=crypt(password,map+l+ul+1);
	  i=str_len(crypted);
	  if (l+ul+1+i <= filesize)
	    if (byte_equal(map+l+ul+1,i,crypted)) {
	      r=1;
	      goto done;
	    }
	}
      }
    }
  }
needauth:
  httperror_realm(h,"401 Authorization Required","Authorization required to view this web page",realm,nobody);
done:
  mmap_unmap(map,filesize);
  return r;
}
#endif

int http_redirect(struct http_data* h,const char* Filename) {
#ifndef __MINGW32__
  char buf[2048];
  int i;
  if ((i=readlink(Filename,buf,sizeof(buf)))!=-1) {
    buf[i]=0;
    if (strstr(buf,"://")) {
      h->bodybuf=malloc(strlen(buf)+300);
      h->hdrbuf=malloc(strlen(buf)+300);
      if (h->bodybuf && h->hdrbuf) {
	int i;
	i=fmt_str(h->bodybuf,"Look <a href=\"");
	i+=fmt_str(h->bodybuf+i,buf);
	i+=fmt_str(h->bodybuf+i,"\">here</a>!\n");
	h->blen=i;

	i=fmt_str(h->hdrbuf,"HTTP/1.0 301 Go Away\r\nConnection: ");
	i+=fmt_str(h->hdrbuf+i,h->keepalive?"keep-alive":"close");
	i+=fmt_str(h->hdrbuf+i,"\r\nServer: " RELEASE "\r\nContent-Length: ");
	i+=fmt_ulong(h->hdrbuf+i,h->blen);
	i+=fmt_str(h->hdrbuf+i,"\r\nLocation: ");
	i+=fmt_str(h->hdrbuf+i,buf);
	i+=fmt_str(h->hdrbuf+i,"\r\n\r\n");
	h->hlen=i;
	return -4;
      }
      free(h->bodybuf); free(h->hdrbuf);
    }
  }
#endif
  return 0;
}

#ifdef SUPPORT_DIR_REDIRECT
void do_dir_redirect(struct http_data* h,const char* filename,int64 s) {
  char* nh;
  int i;
  char* host=http_header(h,"Host");
#ifdef SUPPORT_HTTPS
  const char* proto=h->t==HTTPSREQUEST?"https://":"http://";
#else
  const char* proto="http://";
#endif
  size_t hl;
  if (!host) return;
  hl=str_chr(host,'\n');
  if (hl && host[hl-1]=='\r') --hl;
  nh=malloc((strlen(filename)+hl)*2+300);
  if (!nh) {
    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,s)]=0;
      buffer_putmflush(buffer_1,"outofmemory ",numbuf,"\n");
    }
    cleanup(s);
    return;
  }
  i=fmt_str(nh,"HTTP/1.0 302 Over There\r\nServer: " RELEASE "\r\nLocation: ");
  i+=fmt_str(nh+i,proto);
  i+=fmt_strn(nh+i,host,hl);
  i+=fmt_str(nh+i,filename);
  i+=fmt_str(nh+i,"/\r\nContent-Type: text/html\r\nContent-Length: ");
  i+=fmt_ulong(nh+i,strlen(filename)+hl+23);
  i+=fmt_str(nh+i,"\r\n\r\n");
  i+=fmt_str(nh+i,"Look <a href=");
  i+=fmt_str(nh+i,proto);
  i+=fmt_strn(nh+i,host,hl);
  i+=fmt_str(nh+i,filename);
  i+=fmt_str(nh+i,"/>here!</a>\n");
  if (logging) {
    char numbuf[FMT_ULONG];
    numbuf[fmt_ulong(numbuf,s)]=0;
    buffer_putmflush(buffer_1,"dir_redirect ",numbuf,"\n");
  }
  iob_addbuf_free(&h->iob,nh,strlen(nh));
}
#endif

int64 http_openfile(struct http_data* h,char* filename,struct stat* ss,int sockfd,int nobody) {
#ifdef SUPPORT_PROXY
  int noproxy=0;
#endif
  char* dir=0;
  char* s;
  char* args;
  size_t i;
  int64 fd;
  int doesgzip;
#ifdef SUPPORT_BZIP2
  int doesbzip2;
#endif

  char* Filename;

  doesgzip=0; h->encoding=NORMAL;
#ifdef SUPPORT_BZIP2
  doesbzip2=0;
#endif
  {
    char* tmp=http_header(h,"Accept-Encoding");
    if (tmp) {	/* yeah this is crude, but it gets the job done */
      int end=str_chr(tmp,'\n');
      for (i=0; i+4<end; ++i)
	if (byte_equal(tmp+i,4,"gzip"))
	  doesgzip=1;
#ifdef SUPPORT_BZIP2
	else if (byte_equal(tmp+i,4,"bzip2"))
	  doesbzip2=1;
#endif
    }
  }

  args=0;
  /* the file name needs to start with a / */
  if (filename[0]!='/') return -1;


  /* first, we need to strip "?.*" from the end */
  i=str_chr(filename,'?');
  Filename=alloca(i+6+(defaultindex?strlen(defaultindex):0));	/* enough space for .gz and .bz2 */
  byte_copy(Filename,i+1,filename);
  if (Filename[i]=='?') { Filename[i]=0; args=filename+i+1; }
  /* second, we need to un-urlencode the file name */
  /* we can do it in-place, the decoded string can never be longer */
  {
    size_t j,src,dst;
    for (src=dst=0;;) {
      j=scan_urlencoded2(Filename+src,Filename+dst,&i);
      src+=j;
      dst+=i;
      if (Filename[src]==0) break;
      Filename[dst++]=Filename[src++];
    }
    Filename[dst]=0;
  }
  /* third, change /. to /: so .procmailrc is visible in ls as
   * :procmailrc, and it also thwarts most web root escape attacks */
  for (i=0; Filename[i]; ++i)
    if (Filename[i]=='/' && Filename[i+1]=='.')
      Filename[i+1]=':';
  /* fourth, try to do some el-cheapo virtual hosting */
  if (!(s=http_header(h,"Host"))) {
makefakeheader:
    /* construct artificial Host header from IP */
    s=alloca(IP6_FMT+7);
    i=fmt_ip6c(s,h->myip);
    i+=fmt_str(s+i,":");
    i+=fmt_ulong(s+i,h->myport);
    s[i]=0;
  } else {
    size_t k;
    char* t;
    for (k=0; s[k] && s[k]!='/' && s[k]>' '; ++k) ;
    t=alloca(k+2);
    memcpy(t,s,k);
    t[k]='\r'; t[k+1]=0;
    s=t;
    if (s[0]=='.' || !s[0]) goto makefakeheader;
    if (virtual_hosts>=0) {
      char* tmp;
      int j=str_chr(s,'\r');
      /* replace port in Host: with actual port */
      if (!s[i=str_chr(s,':')] || i>j || !transproxy) {	/* add :port */
	if (i>j) i=j;
	tmp=alloca(i+7);
	byte_copy(tmp,i,s);
	tmp[i]=':'; ++i;
	i+=fmt_ulong(tmp+i,h->myport);
	tmp[i]=0;
	s=tmp;
      }
    }
  }
#ifdef __MINGW32__
//  printf("chdir(\"%s\") -> %d\n",origdir,chdir(origdir));
  chdir(origdir);
#else
  fchdir(origdir);
#endif

  if (virtual_hosts>=0)
    if (chdir(dir=s)==-1)
      if (chdir(dir="default")==-1) {
	if (virtual_hosts==1) {
	  buffer_putsflush(buffer_2,"chdir FAILED and virtual_hosts is 1\n");
	  return -1;
	} else
	  dir=".";
      }
  if (!dir) dir=".";
  while (Filename[1]=='/') ++Filename;

#ifdef SUPPORT_HTACCESS
  if (http_dohtaccess(h,".htaccess_global",nobody)==0) return -5;
#endif

#ifdef SUPPORT_PROXY
  noproxy=0;
  {
    int res;
    switch ((res=proxy_connection(sockfd,Filename,dir,h,0,args))) {
    case -3: noproxy=1; /* fall through */
    case -2: break;
    case -1: return -1;
    default:
      if (res>=0) {
	h->buddy=res;
	return -3;
      }
    }
  }
#else
  (void)sockfd;		/* shut up gcc warning about unused variable */
#endif
  if (Filename[(i=str_len(Filename))-1] == '/') {
    /* Damn.  Directory. */

    if (defaultindex) {
      strcpy(Filename+i,defaultindex);
      if (stat(Filename+1,ss)==0) {
	/* check if the new filename matches any proxy rule */
#ifdef SUPPORT_PROXY
	if (!noproxy) {
	  int res;
	  switch ((res=proxy_connection(sockfd,Filename,dir,h,0,args))) {
	  case -2: break;
	  case -1: return -1;
	  default:
	    if (res>=0) {
	      h->buddy=res;
	      return -3;
	    }
	  }
	}
#endif
	goto itsafile;
      } else
	Filename[i]=0;
    }

    if (Filename[1] && chdir(Filename+1)==-1) return -1;
#ifdef SUPPORT_HTACCESS
    if (http_dohtaccess(h,".htaccess",nobody)==0) return -5;
#endif
    h->mimetype="text/html";
    if (!open_for_reading(&fd,"index.html",ss)) {
      DIR* d;
      if (errno==ENOENT)
	if (http_redirect(h,"index.html")) return -4;
      if (!directory_index) return -1;
      if (!(d=opendir("."))) return -1;
      if (!http_dirlisting(h,d,Filename,args)) return -1;
#ifdef USE_ZLIB
      if (doesgzip) {
	uLongf destlen=h->blen+30+h->blen/1000;
	unsigned char *compressed=malloc(destlen+15);
	if (!compressed) return -2;
	if (compress2(compressed+8,&destlen,(unsigned char*)h->bodybuf,h->blen,3)==Z_OK && destlen<h->blen) {
	  /* I am absolutely _not_ sure why this works, but we
	   * apparently have to ignore the first two and the last four
	   * bytes of the output of compress2.  I got this from googling
	   * for "compress2 header" and finding some obscure gzip
	   * integration in aolserver */
	  unsigned int crc=crc32(0,0,0);
	  crc=crc32(crc,(unsigned char*)h->bodybuf,h->blen);
	  free(h->bodybuf);
	  h->bodybuf=(char*)compressed;
	  h->encoding=GZIP;
	  byte_zero(compressed,10);
	  compressed[0]=0x1f; compressed[1]=0x8b;
	  compressed[2]=8; /* deflate */
	  compressed[3]=1; /* indicate ASCII */
	  compressed[9]=3; /* OS = Unix */
	  uint32_pack((char*)compressed+10-2-4+destlen,crc);
	  uint32_pack((char*)compressed+14-2-4+destlen,h->blen);
	  h->blen=destlen+18-2-4;
	} else {
	  free(compressed);
	}
      }
#endif
      return -2;
    }
#ifdef SUPPORT_PROXY
    /* if index.html is executable, see if we have a file_executable
     * CGI rule */
    if (!noproxy && (ss->st_mode&S_IXOTH)) {
      char* temp=alloca(strlen(Filename)+10);
      if (pread(fd,temp,4,0)==4) {
	if (byte_equal(temp,2,"#!") || byte_equal(temp,4,"\177ELF")) {
	  int res;
	  i=fmt_str(temp,Filename);
	  i+=fmt_str(temp+i,"index.html");
	  temp[i]=0;
	  switch ((res=proxy_connection(sockfd,temp,dir,h,1,args))) {
	  case -2: break;
	  case -1: return -1;
	  default:
	    if (res>=0) {
	      close(fd);
	      h->buddy=res;
	      return -3;
	    }
	  }
	}
      }
    }
#endif
#ifdef SUPPORT_BZIP2
    if (doesbzip2) {
      int64 gfd;
      if (open_for_reading(&gfd,"index.html.bz2",ss)) {
	io_close(fd);
	fd=gfd;
	h->encoding=BZIP2;
      }
    }
#endif
    if (doesgzip) {
      int64 gfd;
      if (open_for_reading(&gfd,"index.html.gz",ss)) {
	io_close(fd);
	fd=gfd;
	h->encoding=GZIP;
      }
    }
  } else {
itsafile:
#ifdef SUPPORT_HTACCESS
    {
      char* fn=Filename+1;
      char* x=alloca(strlen(fn)+30);
      int lso=str_rchr(fn,'/');
      if (fn[lso]=='/') {
	byte_copy(x,lso+1,fn);
	str_copy(x+lso+1,".htaccess");
	if (http_dohtaccess(h,x,nobody)==0) return -5;
      } else
	if (http_dohtaccess(h,".htaccess",nobody)==0) return -5;
    }
#endif

    /* For /test/t.cgi/fnord open_for_reading fails with ENOTDIR. */
    if (!open_for_reading(&fd,Filename+1,ss)) {
      if (errno==ENOENT)
	if (http_redirect(h,Filename+1)) return -4;
      if (errno==ENOTDIR) {
	/* we have no choice: we need to test /test, then /test/t.cgi,
	 * to find the actual file name.  Fortunately, the CGI code
	 * already does that in forkslave(). */
	/* We could take it on faith here and let the CGI code handle the
	 * error, but that is very inefficient (one fork per 404). */
	char* fn=alloca(strlen(Filename));
	size_t i;
	strcpy(fn,Filename+1);
	for (i=0; fn[i]; ++i) {
	  if (fn[i]=='/') {
	    char c=fn[i];
	    fn[i]=0;
	    if (stat(fn,ss))
	      break;	/* genuine 404, can't happen (should have been ENOENT and not ENOTDIR) */
	    if (!S_ISDIR(ss->st_mode)) {	/* found first non-dir entry, hopefully our CGI */
	      if (!(ss->st_mode&S_IROTH) || !io_readfile(&fd,fn))
		return -1;
	      h->mimetype=mimetype(fn,fd);
	      fn[i]=c;
	      goto foundcgi;
	    }
	    fn[i]=c;
	  }
	}
      }
      return -1;
    }
#ifdef SUPPORT_DIR_REDIRECT
    if (S_ISDIR(ss->st_mode)) {
      io_close(fd);
      /* someone asked for http://example.com/foo
       * when he should have asked for http://example.com/foo/
       * redirect */
      do_dir_redirect(h,Filename,sockfd);
      return -4;
    }
#endif
    h->mimetype=mimetype(Filename,fd);
foundcgi:
#ifdef SUPPORT_PROXY
    if (!noproxy && (ss->st_mode&S_IXOTH)) {
      char temp[5];
      if (
#ifdef SUPPORT_MIMEMAGIC
	  /* no need to call pread twice */
          h->mimetype==magicelfvalue ||
#endif
         ((pread(fd,temp,4,0)==4) && (byte_equal(temp,2,"#!") || byte_equal(temp,4,"\177ELF")))) {
	int res;
	switch ((res=proxy_connection(sockfd,Filename,dir,h,1,args))) {
	case -2: break;
	case -1: return -1;
	default:
	  if (res>=0) {
	    close(fd);
	    h->buddy=res;
	    return -3;
	  }
	}
      }
    }
#endif
    if (h->mimetype==magicelfvalue) h->mimetype="application/octet-stream";
#ifdef DEBUG
    if (logging) {
      buffer_puts(buffer_1,"open_file ");
      buffer_putulong(buffer_1,sockfd);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      buffer_puts(buffer_1,Filename);
      buffer_putnlflush(buffer_1);
    }
#endif
    if (doesgzip
#ifdef SUPPORT_BZIP2
                 || doesbzip2
#endif
                             ) {
      int64 gfd;
      i=str_len(Filename);
#ifdef SUPPORT_BZIP2
      if (doesbzip2) {
	Filename[i+fmt_str(Filename+i,".bz2")]=0;
	if (open_for_reading(&gfd,Filename+1,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=BZIP2;
	}
      }
#endif
      if (doesgzip && h->encoding==NORMAL) {
	Filename[i+fmt_str(Filename+i,".gz")]=0;
	if (open_for_reading(&gfd,Filename+1,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=GZIP;
	}
      }
      Filename[i]=0;
    }
  }
#ifndef __MINGW32__
  if (S_ISDIR(ss->st_mode)) {
    io_close(fd);
    return -1;
  }
#endif
  return fd;
}

#ifdef SUPPORT_FALLBACK_REDIR
const char* redir;

void do_redirect(struct http_data* h,const char* filename,int64 s) {
  char* nh=malloc((strlen(filename)+strlen(redir))*2+300);
  int i;
  if (!nh) {
    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,s)]=0;
      buffer_putmflush(buffer_1,"outofmemory ",numbuf,"\n");
    }
    cleanup(s);
    return;
  }
  i=fmt_str(nh,"HTTP/1.0 302 Over There\r\nServer: " RELEASE "\r\nLocation: ");
  i+=fmt_str(nh+i,redir);
  i+=fmt_str(nh+i,filename);
  i+=fmt_str(nh+i,"\r\nContent-Type: text/html\r\nContent-Length: ");
  i+=fmt_ulong(nh+i,strlen(filename)+strlen(redir)+23);
  i+=fmt_str(nh+i,"\r\n\r\n");
  i+=fmt_str(nh+i,"Look <a href=");
  i+=fmt_str(nh+i,redir);
  i+=fmt_str(nh+i,filename);
  i+=fmt_str(nh+i,">here!</a>\n");
  iob_addbuf_free(&h->iob,nh,strlen(nh));
}
#endif

#ifdef SUPPORT_SERVERSTATUS
void do_server_status(struct http_data* h,int64 s) {
  char* nh=malloc(1000);
  int i,l;
  char buf[FMT_ULONG*10+600];
  if (!nh) {
    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,s)]=0;
      buffer_putmflush(buffer_1,"outofmemory ",numbuf,"\n");
    }
    cleanup(s);
    return;
  }
  i=fmt_str(buf,"<title>Gatling Server Status</title>\n<h2>Open Connections</h2>\nHTTP: ");
  i+=fmt_ulong(buf+i,http_connections);
  i+=fmt_str(buf+i,"<br>\nHTTPS: ");
  i+=fmt_ulong(buf+i,https_connections);
  i+=fmt_str(buf+i,"<br>\nFTP: ");
  i+=fmt_ulong(buf+i,ftp_connections);
  i+=fmt_str(buf+i,"<br>\nSMB: ");
  i+=fmt_ulong(buf+i,smb_connections);
  i+=fmt_str(buf+i,"<p>\n<h2>Per second:</h2>Connections: ");
  i+=fmt_ulong(buf+i,cps);
  i+=fmt_str(buf+i,"<br>\nRequests: ");
  i+=fmt_ulong(buf+i,rps);
  i+=fmt_str(buf+i,"<br>\nEvents: ");
  i+=fmt_ulong(buf+i,eps);
  i+=fmt_str(buf+i,"<br>\nInbound Traffic: ");
  i+=fmt_ulong(buf+i,tin/1024);
  i+=fmt_str(buf+i," KiB<br>\nOutbound Traffic: ");
  i+=fmt_ulong(buf+i,tout/1024);
  i+=fmt_str(buf+i," KiB");
  buf[i]=0;
  l=i;

  i=fmt_str(nh,"HTTP/1.0 200 OK\r\nServer: " RELEASE "\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: ");
  i+=fmt_ulong(nh+i,l);
  i+=fmt_str(nh+i,"\r\n\r\n");
  i+=fmt_str(nh+i,buf);
  iob_addbuf_free(&h->iob,nh,strlen(nh));
  h->keepalive=0;
  io_wantwrite(s);

  if (logging) {
    char buf[IP6_FMT+10];
    int x;
    char* tmp;
    x=fmt_ip6c(buf,h->myip);
    x+=fmt_str(buf+x,"/");
    x+=fmt_ulong(buf+x,h->myport);
    buf[x]=0;
#ifdef SUPPORT_HTTPS
    if (h->t == HTTPSREQUEST)
      buffer_puts(buffer_1,"HTTPS/");
#endif
    buffer_puts(buffer_1,"GET ");
    buffer_putulong(buffer_1,s);
    buffer_puts(buffer_1," ");
    buffer_putlogstr(buffer_1,"server-status");
    buffer_puts(buffer_1," ");
    buffer_putulonglong(buffer_1,l);
    buffer_puts(buffer_1," ");
    buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
    buffer_puts(buffer_1," ");
    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
    buffer_puts(buffer_1," ");
    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
    buffer_putsflush(buffer_1,"\n");
  }
}
#endif

#ifdef SUPPORT_SERVERSTATUS
static int is_private_ip(const unsigned char* ip) {
  if (ip6_isv4mapped(ip))
    return byte_equal(ip+12,4,ip4loopback) ||	/* localhost */
	   (ip[12]==10) ||			/* rfc1918 */
	   (ip[12]==192 && ip[13]==168) ||
	   (ip[12]==172 && (ip[13]>=16 && ip[13]<=31));
  return byte_equal(ip,16,V6loopback) || (ip[0]==0xfe && (ip[1]==0x80 || ip[1]==0xc0));
  /* localhost or link-local or site-local */
}
#endif

static void get_md5_randomness(const uint8_t* randomness,size_t len,char digest[16]) {
  MD5_CTX temp;
  static int initialized;
  if (!initialized) {
    int fd=open("/dev/urandom",O_RDONLY);
    unsigned char buf[16];
    read(fd,buf,16);
    close(fd);
    MD5Init(&md5_ctx);
    MD5Update(&md5_ctx,buf,16);
    initialized=1;
  }
  MD5Update(&md5_ctx,randomness,len);
  memcpy(&temp,&md5_ctx,sizeof(temp));
  MD5Final((uint8_t*)digest,&temp);
}

size_t scan_range(const char* s,unsigned long long* x,size_t maxranges,unsigned long long filesize) {
  unsigned long long start,end;
  size_t used=0;
  /* possible formats: "-5", "1-3", "10-" */
  while (*s!='\r' && *s!='\n' && *s) {
    if (isdigit(*s))
      s+=scan_ulonglong(s,&start);
    else
      start=0;
    end=filesize;
    if (*s=='-') {
      ++s;
      if (isdigit(*s))
	s+=scan_ulonglong(s,&end);
    }
    if (used+1<maxranges) {
      x[used]=start;
      x[used+1]=end;
    } else
      return 0;
    used+=2;
    if (*s==',') {
      ++s;
      continue;
    }
    if (*s=='\r' || *s=='\n' || *s==0)
      return used;
  }
  return 0;
}

static int mytolower(int a) {
  return a>='A' && a<='Z' ? a-'A'+'a' : a;
}

static int header_diff(const char* s,const char* t) {
  /* like str_diff but s may also end with '\r' or '\n' */
  register int j;
  j=0;
  for (;;) {
    if ((j=(mytolower(*s)-mytolower(*t)))) break; if (!*t) break; ++s; ++t;
  }
  if (*s=='\r' || *s=='\n') j=-*t;
  return j;
}

void httpresponse(struct http_data* h,int64 s,long headerlen) {
  int head,post;
#ifdef SUPPORT_PUT
  int put;
#endif
#ifdef SUPPORT_DAV
  int propfind;
#endif
  char* c;
  const char* m;
  time_t ims=0;
  unsigned long long range_first,range_last;
  h->filefd=-1;

  ++rps1;
  array_cat0(&h->r);
  c=array_start(&h->r);
  if (byte_diff(c,5,"GET /") && byte_diff(c,6,"POST /") &&
#ifdef SUPPORT_PUT
      byte_diff(c,5,"PUT /") &&
#endif
#ifdef SUPPORT_DAV
      byte_diff(c,10,"PROPFIND /") &&
#endif
      byte_diff(c,6,"HEAD /")) {
e400:
    httperror(h,"400 Invalid Request","This server does not understand this HTTP verb.",0);

    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,s)]=0;
      buffer_putmflush(buffer_1,"error_400 ",numbuf,"\n");
    }

  } else {
    char *d;
    int64 fd;
    struct stat ss;
    char* tmp;
    head=c[0]=='H';
    post=c[1]=='O';
#ifdef SUPPORT_PUT
    put=c[1]=='U';
#endif
#ifdef SUPPORT_DAV
    if ((propfind=c[1]=='R'))
      c+=5;	// we will advance by 4, so make sure it's 9 total
#endif
    c+=(head||post)?5:4;
    for (d=c; *d!=' '&&*d!='\t'&&*d!='\n'&&*d!='\r'; ++d) ;
    if (*d!=' ') goto e400;
    *d=0;

    if ((m=http_header(h,"Connection"))) {
      if (!header_diff(m,"keep-alive"))
	h->keepalive=1;
      else
	h->keepalive=0;
    } else {
      if (byte_equal(d+1,8,"HTTP/1.0"))
	h->keepalive=0;
      else
	h->keepalive=1;
    }

    if (c[0]!='/') goto e404;
#ifdef SUPPORT_SERVERSTATUS
    if (!strcmp(c,"/server-status") && is_private_ip((const unsigned char*)h->myip)) {
      do_server_status(h,s);
      return;
    }
#endif
    fd=http_openfile(h,c,&ss,s,head);
    if (fd==-1) {
e404:
#ifdef SUPPORT_FALLBACK_REDIR
      if (redir)
	do_redirect(h,c,s);
#endif
      if (logging) {
	char buf[IP6_FMT+10];
	int x;
	x=fmt_ip6c(buf,h->myip);
	x+=fmt_str(buf+x,"/");
	x+=fmt_ulong(buf+x,h->myport);
	buf[x]=0;
#ifdef SUPPORT_HTTPS
	if (h->t == HTTPSREQUEST)
	  buffer_puts(buffer_1,"HTTPS/");
#endif
#ifdef SUPPORT_PUT
	if (put) buffer_puts(buffer_1,"PUT/404 "); else
#endif
	buffer_puts(buffer_1,head?"HEAD/404 ":post?"POST/404 ":"GET/404 ");
	buffer_putulong(buffer_1,s);
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,c);
	buffer_puts(buffer_1," 0 ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	buffer_putsflush(buffer_1,"\n");
      }
#ifdef SUPPORT_FALLBACK_REDIR
      if (redir)
	goto fini;
#endif
      httperror(h,"404 Not Found","No such file or directory.",head);

    } else {
      char* filename=c;
      if (fd==-4) {	/* redirect */
	iob_addbuf_free(&h->iob,h->hdrbuf,h->hlen);
	iob_addbuf_free(&h->iob,h->bodybuf,h->blen);
      } else if (fd==-5) {
	/* 401 -> log nothing. */
      } else if (fd==-2) {
	char* c;
	c=h->hdrbuf=(char*)malloc(250);
	if (!c)
	  httperror(h,"500 Sorry","Out of Memory.",head);
	else {

	  if (logging) {
	    char buf[IP6_FMT+10];
	    int x;
	    x=fmt_ip6c(buf,h->myip);
	    x+=fmt_str(buf+x,"/");
	    x+=fmt_ulong(buf+x,h->myport);
	    buf[x]=0;
#ifdef SUPPORT_HTTPS
	    if (h->t == HTTPSREQUEST)
	      buffer_puts(buffer_1,"HTTPS/");
#endif
	    buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    buffer_putulong(buffer_1,s);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,filename);
	    buffer_puts(buffer_1," ");
	    buffer_putulonglong(buffer_1,h->blen);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	    buffer_putsflush(buffer_1,"\n");
	  }

	  c+=fmt_str(c,"HTTP/1.1 200 Here you go\r\nContent-Type: text/html; charset=utf-8\r\nConnection: ");
	  c+=fmt_str(c,h->keepalive?"keep-alive":"close");
	  c+=fmt_str(c,"\r\nServer: " RELEASE "\r\nContent-Length: ");
	  c+=fmt_ulong(c,h->blen);
	  if (h->encoding!=NORMAL) {
	    c+=fmt_str(c,"\r\nContent-Encoding: ");
#ifdef SUPPORT_BZIP2
	    c+=fmt_str(c,h->encoding==GZIP?"gzip":"bzip2");
#else
	    c+=fmt_str(c,"gzip");
#endif
	  }
	  c+=fmt_str(c,"\r\n\r\n");
	  h->hlen=c-h->hdrbuf;
	  iob_addbuf_free(&h->iob,h->hdrbuf,h->hlen);
	  if (head)
	    free(h->bodybuf);
	  else
	    iob_addbuf_free(&h->iob,h->bodybuf,h->blen);
	}
#ifdef SUPPORT_PROXY
      } else if (fd==-3) {
	return;
#endif
      } else {
	char* multirange=0;
	unsigned long long ranges[20];
	unsigned long long bytes=0;
	size_t n=0,headersize=0;
	char hex[16];
#ifdef DEBUG
	if (logging) {
	  buffer_puts(buffer_1,"filefd ");
	  buffer_putulong(buffer_1,s);
	  buffer_putspace(buffer_1);
	  buffer_putulong(buffer_1,fd);
	  buffer_putnlflush(buffer_1);
	}
#endif
	h->filefd=fd;
	range_first=0; range_last=ss.st_size;
	if ((c=http_header(h,"If-Modified-Since")))
	  if ((unsigned char)(c[scan_httpdate(c,&ims)])>' ')
	    ims=0;
	if ((c=http_header(h,"Range"))) {
	  if (byte_equal(c,6,"bytes=")) {
	    size_t i;
	    c+=6;
	    n=scan_range(c,ranges,sizeof(ranges)/sizeof(ranges[0])/2,ss.st_size-1);

	    /* the ranges could still be bogus, i.e. 4-2, or the sum
	      * could be more than just sending the whole file. */
	    for (i=0; i<n; i+=2) {
	      if (ranges[i]>=ranges[i+1] ||	// zero or less size
	          bytes+(ranges[i+1]-ranges[i]+1) < bytes) {	/* int overflow */
		n=0;
		break;
	      }
	      bytes+=(ranges[i+1]-ranges[i]+1);
	      if (bytes>ss.st_size+1) {
		n=0;
		break;
	      }
	    }

	    if (n) {
	      /* n will be a multiple of two here */
	      if (n==2) {
		/* just one range, common case */
		range_first=ranges[0];
		range_last=ranges[1];
	      } else {
		size_t overhead=(sizeof("\r\n--eba5aaeb1a3913f0ed90259cf85a1ea7\r\nContent-Type: \r\nContent-Range: bytes -/\r\n\r\n")-1+
		  strlen(h->mimetype)+fmt_ulonglong(NULL,ss.st_size))*(n/2)+
		  sizeof("\r\n--eba5aaeb1a3913f0ed90259cf85a1ea7--\r\n")-1;
		for (i=0; i<n; i+=2)
		  overhead+=fmt_ulonglong(NULL,ranges[i])+fmt_ulonglong(NULL,ranges[i+1]);
		if (bytes+overhead<bytes)
		  goto rangekaputt;
		headersize=overhead;
//		printf("bytes=%llu, overhead=%zu, header size=%zu\n",bytes,overhead,headersize);
		bytes+=overhead;
		if (bytes<ss.st_size)
		  multirange=c;
	      }
	    } else {
rangekaputt:
#ifdef DEBUG
	      if (logging) {
		buffer_puts(buffer_1,"bad_range_close ");
		buffer_putulong(buffer_1,s);
		buffer_putspace(buffer_1);
		buffer_putulong(buffer_1,fd);
		buffer_putnlflush(buffer_1);
	      }
#endif
	      io_close(h->filefd); h->filefd=-1;
	      httperror(h,"416 Bad Range","The requested range can not be satisfied.",head);
	      goto fini;
	    }
	  }
	}
	if (range_last<range_first) {
	  /* rfc2616, page 123 */
	  range_first=0; range_last=ss.st_size;
	}
	if (range_last>ss.st_size) range_last=ss.st_size;

	c=h->hdrbuf=(char*)malloc(500);
	if (ss.st_mtime<=ims) {
	  c+=fmt_str(c,"HTTP/1.1 304 Not Changed");
	  head=1; range_last=range_first;
	  io_close(fd); fd=-1;
	  multirange=0;
	} else {
	  if (multirange || range_first || range_last!=ss.st_size)
	    c+=fmt_str(c,"HTTP/1.1 206 Partial Content");
	  else
	    c+=fmt_str(c,"HTTP/1.1 200 Coming Up");
	}

	c+=fmt_str(c,"\r\nAccept-Ranges: bytes\r\nServer: " RELEASE "\r\nContent-Type: ");
	if (multirange) {
	  c+=fmt_str(c,"multipart/byteranges; boundary=");
	  get_md5_randomness((uint8_t*)multirange,str_chr(multirange,'\n'),hex);
	  c+=fmt_hexdump(c,hex,16);
	  c+=fmt_str(c,"\r\nContent-Length: ");
	  c+=fmt_ulonglong(c,bytes);
	} else {
	  c+=fmt_str(c,h->mimetype);
	  c+=fmt_str(c,"\r\nContent-Length: ");
	  if (range_last==ss.st_size) --range_last;
	  c+=fmt_ulonglong(c,range_last-range_first+1);
	}

	c+=fmt_str(c,"\r\nDate: ");
	c+=fmt_httpdate(c,now.sec.x-4611686018427387914ULL);

	c+=fmt_str(c,"\r\nLast-Modified: ");
	c+=fmt_httpdate(c,ss.st_mtime);
	if (h->encoding!=NORMAL) {
	  c+=fmt_str(c,"\r\nContent-Encoding: ");
#ifdef SUPPORT_BZIP2
	  c+=fmt_str(c,h->encoding==GZIP?"gzip":"bzip2");
#else
	  c+=fmt_str(c,"gzip");
#endif
	}
	if (!head && (range_first || range_last!=ss.st_size)) {
	  c+=fmt_str(c,"\r\nContent-Range: bytes ");
	  c+=fmt_ulonglong(c,range_first);
	  c+=fmt_str(c,"-");
	  c+=fmt_ulonglong(c,range_last);
	  c+=fmt_str(c,"/");
	  c+=fmt_ulonglong(c,ss.st_size);
	}
	if (range_first>ss.st_size) {
	  free(h->hdrbuf);
	  httperror(h,"416 Bad Range","The requested range can not be satisfied.",head);
	  buffer_puts(buffer_1,"error_416 ");
	} else {
	  c+=fmt_str(c,"\r\nConnection: ");
	  c+=fmt_str(c,h->keepalive?"keep-alive":"close");
	  c+=fmt_str(c,"\r\n\r\n");
	  iob_addbuf_free(&h->iob,h->hdrbuf,c - h->hdrbuf);
	  if (!head) {
	    if (multirange) {
	      char* buf=malloc(headersize+5);
	      char* c,* x;
	      size_t i,flen;

	      c=buf+fmt_str(buf,"\r\n--");
	      c+=fmt_hexdump(c,hex,16);
	      c+=fmt_str(c,"--\r\n");
	      flen=c-buf;

	      x=c;

	      for (i=0; i<n; i+=2) {
		c=x+fmt_str(x,"\r\n--");
		c+=fmt_hexdump(c,hex,16);
		c+=fmt_str(c,"\r\nContent-Type: ");
		c+=fmt_str(c,h->mimetype);
		c+=fmt_str(c,"\r\nContent-Range: bytes ");
		c+=fmt_ulonglong(c,ranges[i]);
		c+=fmt_str(c,"-");
		c+=fmt_ulonglong(c,ranges[i+1]);
		c+=fmt_str(c,"/");
		c+=fmt_ulonglong(c,ss.st_size);
		c+=fmt_str(c,"\r\n\r\n");
		iob_addbuf(&h->iob,x,c-x);
		if (i+2<n)
		  iob_addfile(&h->iob,fd,ranges[i],ranges[i+1]-ranges[i]+1);
		else
		  iob_addfile_close(&h->iob,fd,ranges[i],ranges[i+1]-ranges[i]+1);
		x=c;
	      }
	      iob_addbuf_free(&h->iob,buf,flen);
	    } else
	      iob_addfile_close(&h->iob,fd,range_first,range_last-range_first+1);
	  } else
	    if (fd!=-1) io_close(fd);
	  if (logging) {
	    if (h->hdrbuf[9]=='3') {
	      buffer_puts(buffer_1,head?"HEAD/304 ":"GET/304 ");
	    } else {
	      buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    }
	  }
	}

	if (logging) {
	  char buf[IP6_FMT+10];
	  int x;
	  x=fmt_ip6c(buf,h->myip);
	  x+=fmt_str(buf+x,"/");
	  x+=fmt_ulong(buf+x,h->myport);
	  buf[x]=0;
	  buffer_putulong(buffer_1,s);
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,filename);
	  switch (h->encoding) {
	  case GZIP: buffer_puts(buffer_1,".gz"); break;
#ifdef SUPPORT_BZIP2
	  case BZIP2: buffer_puts(buffer_1,".bz2");
#endif
	  case NORMAL: break;
	  }
	  buffer_puts(buffer_1," ");
	  buffer_putulonglong(buffer_1,range_last-range_first);
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	  buffer_putsflush(buffer_1,"\n");
	}
	h->filefd=-1;	/* iob_addfile_close closes the file for us, we don't want cleanup to close it again */
      }
    }
  }
fini:
  io_dontwantread(s);
  io_wantwrite(s);
}


#ifdef SUPPORT_PROXY
void handle_read_proxypost(int64 i,struct http_data* h) {
  switch (proxy_is_readable(i,h)) {
  case -1:
    {
      if (logging) {
	char numbuf[FMT_ULONG];
	numbuf[fmt_ulong(numbuf,i)]=0;

	buffer_putmflush(buffer_1,"proxy_read_error ",numbuf," ",strerror(errno),"\nclose/acceptfail ",numbuf,"\n");
      }
      cleanup(i);
    }
    break;
  }
}

void handle_read_httppost(int64 i,struct http_data* h) {
  /* read POST data. */
#ifdef MOREDEBUG
	printf("read POST data state for %d\n",(int)i);
#endif
  if (h->still_to_copy) {
    if (array_bytes(&h->r)>0) {
#ifdef MOREDEBUG
	    printf("  but there was still data in h->r!\n");
#endif
      io_dontwantread(i);
      io_wantwrite(h->buddy);
    } else if (read_http_post(i,h)==-1) {
      if (logging) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_1,"http_postdata_read_error ",a," ",strerror(errno),"\nclose/acceptfail ",a,"\n");
      }
      cleanup(i);
    } else {
#ifdef MOREDEBUG
	    printf("  read something\n");
#endif
      io_dontwantread(i);
      io_wantwrite(h->buddy);
    }
  } else {
    /* should not happen */
    io_dontwantread(i);
#ifdef MOREDEBUG
	  printf("ARGH!!!\n");
#endif
  }
}

void handle_write_proxypost(int64 i,struct http_data* h) {
  struct http_data* H=io_getcookie(h->buddy);
  /* do we have some POST data to write? */
#ifdef MOREDEBUG
	printf("event: write POST data (%llu) to proxy on %d\n",h->still_to_copy,(int)i);
#endif
  if (!array_bytes(&H->r)) {
#ifdef MOREDEBUG
	  printf("  but nothing here to write!\n");
#endif
    io_dontwantwrite(i);	/* nope */
    io_wantread(h->buddy);
  } else {
//	  printf("  yeah!\n");
    if (H) {
      char* c=array_start(&H->r);
      long alen=array_bytes(&H->r);
      long l;
#ifdef MOREDEBUG
      printf("%ld bytes still in H->r (%ld in h->r), still to copy: %lld (%lld in h)\n",alen,(long)array_bytes(&h->r),H->still_to_copy,h->still_to_copy);
#endif

      if (h->proxyproto!=FASTCGI) {
	/* this looks like the right thing to sanity-check but it is not
	 * in the fastcgi case.  For fastcgi, we have to append an 8
	 * byte header for each chunk, and if it's the last chunk, we
	 * have to append another 8 byte header.  So alen can be 8 or 16
	 * bytes off. */
	if (alen>h->still_to_copy) alen=h->still_to_copy;
      }

      if (alen==0) goto nothingmoretocopy;
      l=write(i,c,alen);
#ifdef MOREDEBUG
	    printf("wrote %ld bytes (wanted to write %ld; had %lld still to copy)\n",l,alen,H->still_to_copy);
#endif
      if (l<1) {
	/* ARGH!  Proxy crashed! *groan* */
	if (logging) {
	  buffer_puts(buffer_1,"http_postdata_write_error ");
	  buffer_putulong(buffer_1,i);
	  buffer_putspace(buffer_1);
	  buffer_puterror(buffer_1);
	  buffer_puts(buffer_1,"\nclose/acceptfail ");
	  buffer_putulong(buffer_1,i);
	  buffer_putnlflush(buffer_1);
	}
	cleanup(i);
      } else {
	byte_copy(c,alen-l,c+l);
	array_truncate(&H->r,1,alen-l);
//	      printf("still_to_copy PROXYPOST write handler: %p %llu -> %llu\n",H,H->still_to_copy,H->still_to_copy-l);
	h->still_to_copy-=l;
//	      printf("still_to_copy PROXYPOST write handler: %p %llu -> %llu\n",h,h->still_to_copy,h->still_to_copy-i);
//	      h->still_to_copy-=i;
	if (alen-l==0) {
	  /* we wrote everything we have in the buffer */
	  io_dontwantwrite(i);
	  /* check if we need to copy more data */
	  if (h->still_to_copy)
	    io_wantread(h->buddy);
	}
	if (h->still_to_copy==0) {
	  /* we got all we asked for */
nothingmoretocopy:
	  io_dontwantwrite(i);
	  io_wantread(i);
	  io_dontwantread(h->buddy);
	  io_wantwrite(h->buddy);
	}
      }
    }
  }
}

static void handle_write_error(int64 i,struct http_data* h,int64 r) {
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
      cleanup(i);
      return;
    }
    if (h->buddy==-1) {
      if (logging) {
	char a[FMT_ULONG];
	char r[FMT_ULONG];
	char s[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	r[fmt_ulonglong(r,h->received)]=0;
	s[fmt_ulonglong(s,h->sent)]=0;
	buffer_putmflush(buffer_1,"close/proxydone ",a," ",r," ",s,"\n");
      }
      cleanup(i);
    } else {
      io_dontwantwrite(i);
      io_wantread(h->buddy);
    }
  } else
    h->sent+=r;
}

void handle_write_httppost(int64 i,struct http_data* h) {
  int64 r;
#ifdef SUPPORT_HTTPS
  if (h->t==HTTPSPOST)
    r=iob_write(i,&h->iob,https_write_callback);
  else 
#endif
  r=iob_send(i,&h->iob);
  if (r > 0 && iob_bytesleft(&h->iob)==0) {
    /* We wrote something and there is no more data left in the iob. */
    /* Since we do not buffer the whole data from the proxy, there could
     * be more data incoming from the proxy.  If this was the last
     * batch, then the proxy connection has closed itself and set our
     * buddy to -1. */
    if (h->buddy==-1) {
      if (logging) {
	char a[FMT_ULONG];
	char r[FMT_ULONG];
	char s[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	r[fmt_ulonglong(r,h->received)]=0;
	s[fmt_ulonglong(s,h->sent)]=0;
	buffer_putmflush(buffer_1,"close/proxydone ",a," ",r," ",s,"\n");
      }
#ifdef SUPPORT_HTTPS
#ifdef USE_OPENSSL
      SSL_shutdown(h->ssl);
#endif
#endif
      cleanup(i);
    } else {
      /* The proxy has more data for us */
      io_dontwantwrite(i);
      io_wantread(h->buddy);
    }
    return;
  }
  handle_write_error(i,h,r);
}

void handle_write_proxyslave(int64 i,struct http_data* h) {
  /* the connect() to the proxy just finished or failed */
  struct http_data* H;
  H=io_getcookie(h->buddy);
  if (proxy_write_header(i,h)==-1) {
kaputt:
    if (logging) {
      buffer_puts(buffer_1,"proxy_connect_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/connectfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    H->buddy=-1;
    httperror(H,"502 Gateway Broken","Request relaying error.",0); /* FIXME, what about HEAD? */
    h->buddy=-1;
    free(h);
    io_close(i);
  }
  /* it worked.  We wrote the header.  Now see if there is
    * POST data to write.  h->still_to_copy is Content-Length. */
#ifdef MOREDEBUG
	printf("wrote header to %d for %d; Content-Length: %d\n",(int)i,(int)h->buddy,(int)h->still_to_copy);
#endif
  changestate(h,PROXYPOST);
  array_trunc(&h->r);
  if (h->still_to_copy) {
    size_t l=h->still_to_copy;
    if (l>array_bytes(&H->r)) l=array_bytes(&H->r);
    if (l) {
      /* for FASTCGI, we need to add a header */
      if (H->proxyproto==FASTCGI) {
	char* tmp,* cur;
	cur=array_start(&H->r);
	while (l) {	/* this basically can't happen */
	  size_t chunk=l;
	  if (chunk>32768) chunk=32768;
	  tmp=malloc(8);
	  if (!tmp) goto kaputt;
	  memcpy(tmp,"\x01\x05\x00\x01\x00\x00\x00\x00",8);
	  tmp[4]=chunk>>8;
	  tmp[5]=chunk&0xff;
	  iob_addbuf_free(&H->iob,tmp,8);
	  iob_addbuf(&H->iob,cur,chunk);
	  cur+=chunk;
	  l-=chunk;
	}
      } else {
	iob_addbuf(&H->iob,array_start(&H->r),l);
	H->r.initialized=0;
      }
    }
    handle_write_error(i,H,iob_send(i,&H->iob));
  } else {
    io_dontwantwrite(i);
    io_wantread(i);
  }
}

#endif

#ifdef SUPPORT_CGI
/* gatling is expected to have 10000 file descriptors open.
 * so forking off CGIs is bound to be expensive because after the fork
 * all the file descriptors have to be closed.  So this code makes
 * gatling fork off a child first thing in main().  gatling has a Unix
 * domain socket open to the child.  When gatling needs to start a CGI,
 * it sends a message to the child.  The child then creates a new socket
 * pair, sets up the CGI environment, forks a grandchild, and passes the
 * socket to the grandchild back to gatling over the Unix domain socket. */
char fsbuf[8192];

static const char *cgivars[] = {
  "GATEWAY_INTERFACE=",
  "SERVER_PROTOCOL=",
  "SERVER_SOFTWARE=",
  "SERVER_NAME=",
  "SERVER_PORT=",
  "REQUEST_METHOD=",
  "REQUEST_URI=",
  "SCRIPT_NAME=",
  "REMOTE_ADDR=",
  "REMOTE_PORT=",
  "REMOTE_IDENT=",
  "AUTH_TYPE=",
  "CONTENT_TYPE=",
  "CONTENT_LENGTH=",
  "QUERY_STRING=",
  "PATH_INFO=",
  "PATH_TRANSLATED=",
  "REMOTE_USER=",
  0
};

int cgienvneeded(const char* httpreq,size_t reqlen) {
  int i,j,envc;
  for (i=envc=0; _envp[i]; ++i) {
    int found=0;
    if (str_start(_envp[i],"HTTP_"))
      found=1;
    else
      for (j=0; cgivars[j]; ++j)
	if (str_start(_envp[i],cgivars[j])) { found=1; break; }
    if (!found) ++envc;
  }

  /* now collect all normal HTTP headers */

  {
    const char* x=httpreq;
    const char* max=x+reqlen;
    for (;x<max && *x!='\n';++x) ;	/* Skip GET */
    for (;x<max;++x)
      if (*x=='\n')
	++envc;
  }
  return envc;
}

extern int switch_uid();

void forkslave(int fd,buffer* in,int savedir,const char* chroot_to) {
  /* receive query, create socketpair, fork, set up environment,
   * pass file descriptor of our side of socketpair */

  /* protocol:
   * in:
   *   uint32 reqlen,dirlen,ralen
   *   char httprequest[reqlen]
   *   char dir[dirlen]		// "www.fefe.de:80"
   *   char remoteaddr[ralen]
   *   uint16 remoteport
   *   uint16 myport
   * out:
   *   uint32 code,alen
   *   char answer[alen]

   * reqlen==0 means sshd mode.  In this case a connection on port 443
   * came in, ssh forwarding is activated, and the timeout expired
   * before the client sent anything.  Fork an sshd, and pass the
   * descriptor.
   */

  uint32 i,reqlen,dirlen,code,ralen;
  uint16 port,myport;
  const char* msg="protocol error";

  code=1;
  if (read(fd,(char*)&reqlen,4)!=4) goto error;

//  printf("CGI: reqlen %u\n",reqlen);

#ifdef SUPPORT_HTTPS
  if (reqlen==0) { /* SSH MODE */
    int s,r;
    if ((s=io_receivefd(fd))==-1) goto error;
#ifdef sgi
    r=fork();
#else
    r=vfork();
#endif
    if (r==-1) { close(s); msg="vfork failed"; goto error; }
    if (r==0) { /* child */
      /* sshd might be something like /opt/diet/bin/sshd -u0 */
      /* so tokenize and add -i (inetd mode) */
      size_t args,i;
      char** argv;
      close(savedir);
      for (i=0,args=3; sshd[i]; ++i)
	if (sshd[i]==' ') ++args;
      argv=malloc(args*sizeof(argv[0]));
      argv[0]=sshd; args=1;
      for (i=0; sshd[i]; ++i) {
	if (sshd[i]==' ') {
	  do {
	    sshd[i]=0;
	    ++i;
	  } while (sshd[i]==' ');
	  argv[args]=sshd+i;
	  ++args;
	}
      }
      argv[args]="-i";
      argv[args+1]=0;
      dup2(s,0);
      dup2(s,1);
      close(s);
      close(fd);
      execvp(argv[0],argv);
      exit(127);
    }
    close(s);
    return;
  }
#endif

  if (chroot_to) { chdir(chroot_to); chroot(chroot_to); }
  if (switch_uid()==-1) return;

  if (buffer_get(in,(char*)&dirlen,4)==4 &&
      buffer_get(in,(char*)&ralen,4)==4) {
//    printf("CGI: dirlen %u, ralen %u\n",dirlen,ralen);
    if (dirlen<PATH_MAX && reqlen<MAX_HEADER_SIZE) {
      char* httpreq=alloca(reqlen+1);
      char* path=alloca(dirlen+1);
      char* remoteaddr=alloca(ralen+1);
      char* servername,* httpversion,* authtype,* contenttype,* contentlength,* remoteuser;
      char* path_translated;
#ifdef SUPPORT_HTTPS
      char ssl;
#endif

      if (buffer_get(in,httpreq,reqlen) == reqlen &&
	  buffer_get(in,path,dirlen) == dirlen &&
	  buffer_get(in,remoteaddr,ralen) == ralen &&
	  buffer_get(in,(char*)&port,2) == 2 &&
	  buffer_get(in,(char*)&myport,2) == 2
#ifdef SUPPORT_HTTPS
	  && buffer_get(in,&ssl,1) == 1
#endif
	  ) {

	httpreq[reqlen]=0;
	path[dirlen]=0;
	remoteaddr[ralen]=0;

	if (dirlen==0 || chdir(path)==0) {
	  /* now find cgi */
	  char* cginame,* origcginame;

	  origcginame=cginame=httpreq+5+(httpreq[0]=='P');
	  while (*cginame=='/') ++cginame;
	  for (i=0; cginame+i<httpreq+reqlen; ++i)
	    if (cginame[i]==' ' || cginame[i]=='\r' || cginame[i]=='\n') break;

	  if (cginame[i]==' ') {
	    char* args,* pathinfo;
	    int j,k;
	    struct stat ss;
	    cginame[i]=0; args=0; pathinfo=0;

	    httpversion=alloca(30+(j=str_chr(cginame+i+1,'\n')));
	    k=fmt_str(httpversion,"SERVER_PROTOCOL=");
	    byte_copy(httpversion+k,j,cginame+i+1);
	    if (j && httpversion[k+j-1]=='\r') --j; httpversion[k+j]=0;

	    /* now cginame is something like "test/t.cgi?foo=bar"
	     * but it might also be "test/t.cgi/something/else" or even
	     * "test/t.cgi/something/?uid=23" */

	    /* extract ?foo=bar */
	    j=str_chr(cginame,'?');
	    if (cginame[j]=='?') {
	      args=cginame+j+1;
	      cginame[j]=0;
	      i=j;
	    }

	    /* now cginame is test/t.cgi/something */
	    if (stat(cginame,&ss)==0)
	      /* no "/something" */
	      pathinfo=0;
	    else {
	      errno=0;
	      /* try paths */
	      for (j=0; j<i; ++j) {
		if (cginame[j]=='/') {
		  cginame[j]=0;
		  if (stat(cginame,&ss)==0 && !S_ISDIR(ss.st_mode)) {
		    pathinfo=cginame+j+1;
		    break;
		  }
		  cginame[j]='/';
		  if (errno==ENOENT || errno==ENOTDIR) {
		    msg="404";
		    goto error;
		  }
		}
	      }
	    }

	    {
	      char* x=http_header_blob(httpreq,reqlen,"Host");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
	      } else {
		x=remoteaddr; j=str_len(x);
	      }
	      servername=alloca(30+j+1);
	      i=fmt_str(servername,"SERVER_NAME=");
	      byte_copy(servername+i,j,x);
	      servername[i+j]=0;

	      if (pathinfo) {
		size_t pilen;
		scan_urlencoded2(pathinfo,pathinfo,&pilen); pathinfo[pilen]=0;
		path_translated=alloca(PATH_MAX+30);
		i=fmt_str(path_translated,"PATH_TRANSLATED=");
		if (!realpath(pathinfo,path_translated+i))
		  path_translated=0;
	      } else
		path_translated=0;

	      x=http_header_blob(httpreq,reqlen,"Authorization");
	      if (x) {
		int k;
		remoteuser=0;

		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		k=str_chr(x,' ');
		if (k<j) {
		  size_t dl;
		  remoteuser=alloca(20+k-j);
		  i=fmt_str(remoteuser,"REMOTE_USER=");
		  scan_base64(x+k+1,remoteuser+i,&dl);
		  remoteuser[i+dl]=0;
		  dl=str_chr(remoteuser+i,':');
		  if (remoteuser[i+dl]==':') remoteuser[i+dl]=0;
		  j=k;
		}
		authtype=alloca(20+j+1);
		i=fmt_str(authtype,"AUTH_TYPE=");
		byte_copy(authtype+i,j,x);
		authtype[i+j]=0;
	      } else
		authtype=remoteuser=0;

	      x=http_header_blob(httpreq,reqlen,"Content-Type");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		contenttype=alloca(30+j+1);
		i=fmt_str(contenttype,"CONTENT_TYPE=");
		byte_copy(contenttype+i,j,x);
		contenttype[i+j]=0;
	      } else
		contenttype=0;

	      x=http_header_blob(httpreq,reqlen,"Content-Length");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		contentlength=alloca(30+j+1);
		i=fmt_str(contentlength,"CONTENT_LENGTH=");
		byte_copy(contentlength+i,j,x);
		contentlength[i+j]=0;
	      } else
		contentlength=0;
	    }

	    {
	      int sock[2];
	      if (socketpair(AF_UNIX,SOCK_STREAM,0,sock)==0) {
#ifdef sgi
		int r=fork();
#else
		int r=vfork();
#endif
		if (r==-1)
		  msg="vfork failed!";
		else if (r==0) {
		  /* child */
		  pid_t pid;
		  close(savedir);
		  code=0;
		  write(fd,&code,4);
		  write(fd,&code,4);
		  pid=getpid();
		  write(fd,&pid,sizeof(pid));
		  if (cginame[(j=strlen(cginame))-1]=='/') {	/* can happen in the -C+x case */
		    char* temp=alloca(j+10);
		    j=fmt_str(temp,cginame);
		    j+=fmt_str(temp+j,"index.html");
		    temp[j]=0;
		    cginame=temp;
		  }
		  if (io_passfd(fd,sock[0])==0) {
		    char* argv[]={cginame,0};
		    char** envp;
		    int envc;

		    envc=cgienvneeded(httpreq,reqlen);

		    envp=(char**)alloca(sizeof(char*)*(envc+21));
		    envc=0;

#ifdef SUPPORT_HTTPS
		    if (ssl)
		      envp[envc++]="HTTPS=1";
#endif

		    for (i=0; _envp[i]; ++i) {
		      int found=0;
		      if (str_start(_envp[i],"HTTP_"))
			found=1;
		      else
			for (j=0; cgivars[j]; ++j)
			  if (str_start(_envp[i],cgivars[j])) { found=1; break; }
		      if (!found) envp[envc++]=_envp[i];
		    }
		    envp[envc++]="SERVER_SOFTWARE=" RELEASE;
		    envp[envc++]=servername;
		    envp[envc++]="GATEWAY_INTERFACE=CGI/1.1";
		    envp[envc++]=httpversion;

		    envp[envc]=alloca(30);
		    i=fmt_str(envp[envc],"SERVER_PORT=");
		    i+=fmt_ulong(envp[envc]+i,myport);
		    envp[envc][i]=0;
		    ++envc;

		    envp[envc++]=httpreq[0]=='G'?"REQUEST_METHOD=GET":"REQUEST_METHOD=POST";
		    if (pathinfo) envp[envc++]=fmt_strm_alloca("PATH_INFO=",pathinfo);
		    if (path_translated) envp[envc++]=path_translated;

		    envp[envc]=alloca(30+str_len(origcginame));
		    i=fmt_str(envp[envc],"SCRIPT_NAME=");
		    i+=fmt_str(envp[envc]+i,origcginame-1);
		    envp[envc][i]=0;
		    ++envc;

		    if (args) {
		      envp[envc]=alloca(30+str_len(args));
		      i=fmt_str(envp[envc],"QUERY_STRING=");
		      i+=fmt_str(envp[envc]+i,args);
		      envp[envc][i]=0;
		      ++envc;
		    }

		    envp[envc]=alloca(30+str_len(remoteaddr));
		    i=fmt_str(envp[envc],"REMOTE_ADDR=");
		    i+=fmt_str(envp[envc]+i,remoteaddr);
		    envp[envc][i]=0;
		    ++envc;

		    envp[envc]=alloca(30);
		    i=fmt_str(envp[envc],"REMOTE_PORT=");
		    i+=fmt_ulong(envp[envc]+i,port);
		    envp[envc][i]=0;
		    ++envc;

		    if (authtype) envp[envc++]=authtype;
		    if (remoteuser) envp[envc++]=remoteuser;
		    if (contenttype) envp[envc++]=contenttype;
		    if (contentlength) envp[envc++]=contentlength;

/* walk through all the headers in the http request and put them in the
 * environment, e.g. Host: foo:80 -> HTTP_HOST=foo:80 */
		    {
		      char* x=httpreq;
		      char* max=x+reqlen;
		      char* y;

		      for (;x<max && *x!='\n';++x) ;	/* Skip GET */

		      for (y=++x;x<max;++x)
			if (*x=='\n') {

			  if (x>y && x[-1]=='\r') --x;

			  if (x>y) {
			    char* s=alloca(x-y+7);
			    int i,j;

			    byte_copy(s,5,"HTTP_");
			    j=5;
			    for (i=0; i<x-y; ++i) {
			      if (y[i]==':') {
				++i;
				while (i<x-y && (y[i]==' ' || y[i]=='\t')) ++i;
				s[j]='='; ++j;
				for (; i<x-y; ++i) {
				  s[j]=y[i];
				  ++j;
				}
				s[j]=0;
				envp[envc]=s;
				++envc;
				break;
			      }
			      if (y[i]=='-')
				s[j]='_';
			      else if (y[i]>='a' && y[i]<='z')
				s[j]=y[i]-'a'+'A';
			      else if (y[i]>='A' && y[i]<='Z')
				s[j]=y[i];
			      else {
				s=0; break;
			      }
			      ++j;
			    }
			  }
			  if (*x=='\r') ++x;
			  y=x+1;
			}
		    }

		    envp[envc]=0;

		    dup2(sock[1],0);
		    dup2(sock[1],1);
		    dup2(sock[1],2);
		    close(sock[0]); close(sock[1]); close(fd);

		    {
		      char* path,* file;
		      path=cginame;
		      file=strrchr(path,'/');
		      if (file) {
			*file=0;
			++file;
			chdir(path);
			cginame=file;
		      }
		      if (switch_uid()==0)
			execve(cginame,argv,envp);
		    }
		  }
		  {
		    static char e[]="HTTP/1.0 503 Gateway Broken\r\nServer: " RELEASE "\r\nContent-Length: 15\r\nContent-Type: text/html\r\n\r\nGateway Broken.";
		    write(1,e,sizeof(e)-1);
		  }
		  exit(127);
		} else {
		  /* father */
		  close(sock[0]);
		  close(sock[1]);
		  return;
		}
	      } else
		msg="socketpair failed!";
	    }

	  }
	}
      }
    }
  }
error:
  if (write(fd,&code,4)!=4) exit(0);
  code=strlen(msg);
  write(fd,&code,4);
  {
    pid_t pid=0;
    write(fd,&pid,sizeof(pid));
  }
  write(fd,msg,code);
}
#endif

