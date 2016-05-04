#include "gatling.h"

#include "io.h"
#include "byte.h"
#include "str.h"
#include "ip6.h"
#include "fmt.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "havealloca.h"

size_t max_handles=100;

int open_for_reading(int64* fd,const char* name,struct stat* SS) {
  /* only allow reading of world readable files */
  if (io_readfile(fd,name)) {
#ifdef __MINGW32__
    SS->st_size=GetFileSize((HANDLE)(uintptr_t)*fd,0);
#else
    struct stat ss;
    if (!SS) SS=&ss;
    if (fstat(*fd,SS)==-1 || !(SS->st_mode&S_IROTH)) {
      close(*fd);
      *fd=-1;
      return 0;
    }
#endif
    return 1;
  }
  return 0;
}

int open_for_writing(int64* fd,const char* name) {
  /* only allow creating files in world writable directories */
  const char* c;
  char* x;
  struct stat ss;
  c=name+str_rchr(name,'/');
//  if (!*c) return 0;	/* no slashes?  There's something fishy */
  if (!*c) {
    x=".";
  } else {
    x=alloca(c-name+1);
    byte_copy(x,c-name,name); x[c-name]=0;
  }
  if (stat(x,&ss)==-1) return 0;	/* better safe than sorry */
  if (!(ss.st_mode&S_IWOTH)) return 0;
  return io_createfile(fd,name);
}

/* "/foo" -> "/foo"
 * "/foo/./" -> "/foo"
 * "/foo/.." -> "/" */
int canonpath(char* s) {
  int i,j;	/* i: read index, j: write index */
  char c;
  for (i=j=0; (c=s[i]); ++i) {
    if (c=='/') {
      while (s[i+1]=='/') ++i;			/* "//" */
    } else if (c=='.' && j && s[j-1]=='/') {
      if (s[i+1]=='.' && (s[i+2]=='/' || s[i+2]==0)) {		/* "/../" */
	if (j>1)
	  for (j-=2; s[j]!='/' && j>0; --j);	/* remove previous dir */
	else
	  j=0;
	/* s = "/foo/.."
	 *      ^j   ^i
	 */
	++i;
	continue;
      } else if (s[i+1]=='/' || s[i+1]==0) {	/* "/./" */
	++i;
	continue;
      } else
	c=':';
    }
    if (!(s[j]=c)) break; ++j;
  }
  if (j && s[j-1]=='/') --j;
  if (!j) { s[0]='/'; j=1; }
  s[j]=0;
  return j;
}

struct handle* alloc_handle(struct handles* h) {
  size_t i;
  for (i=0; i<h->u; ++i)
    if (h->h[i].fd==-1)
      return &h->h[i];
  if (h->u>=h->a) {
    void* x;
    x=realloc(h->h,(h->a+10)*sizeof(h->h[0]));
    if (!x) return 0;
    h->h=x;
    for (i=0; i<10; ++i) {
      h->h[h->a+i].filename=0;
      h->h[h->a+i].fd=-1;
    }
    h->a+=10;
  }
  if (h->u>=max_handles)
    return 0;
  h->h[h->u].handle=h->u+1;
  return &h->h[h->u++];
}

struct handle* deref_handle(struct handles* h,uint32_t handle) {
  size_t i;
  for (i=0; i<h->u; ++i)
    if (h->h[i].handle==handle)
      return &h->h[i];
  return 0;
}

void close_handle(struct handle* h) {
  if (h->fd!=-1) {
    close(h->fd);
    free(h->filename);
    h->fd=-1;
    h->filename=0;
  }
}

void close_all_handles(struct handles* h) {
  size_t i;
  for (i=0; i<h->u; ++i) {
    if (h->h[i].fd!=-1)
      close(h->h[i].fd);
    free(h->h[i].filename);
  }
  h->u=0;
  h->a=0;
  free(h->h);
  h->h=0;
}

int ip_vhost(struct http_data* h) {
  char* y;
  int i;

  /* construct artificial Host header from IP */
  y=alloca(IP6_FMT+7);
  i=fmt_ip6c(y,h->myip);
  i+=fmt_str(y+i,":");
  i+=fmt_ulong(y+i,h->myport);
  y[i]=0;

#ifdef __MINGW32__
//  printf("chdir(\"%s\") -> %d\n",origdir,chdir(origdir));
  chdir(origdir);
#else
  fchdir(origdir);
#endif
  if (virtual_hosts>=0) {
    if (chdir(y)==-1)
      if (chdir("default")==-1)
	if (virtual_hosts==1) {
	  h->hdrbuf="425 no such virtual host.\r\n";
	  return -1;
	}
  }
  return 0;
}

#ifdef STATE_DEBUG
const char* state2string(enum conntype t) {
  switch (t) {
  case HTTPSERVER6: return "HTTPSERVER6";
  case HTTPSERVER4: return "HTTPSERVER4";
  case HTTPREQUEST: return "HTTPREQUEST";

#ifdef SUPPORT_FTP
  case FTPSERVER6: return "FTPSERVER6";
  case FTPSERVER4: return "FTPSERVER4";
  case FTPCONTROL6: return "FTPCONTROL6";
  case FTPCONTROL4: return "FTPCONTROL4";
  case FTPPASSIVE: return "FTPPASSIVE";
  case FTPACTIVE: return "FTPACTIVE";
  case FTPSLAVE: return "FTPSLAVE";
#endif

#ifdef SUPPORT_SMB
  case SMBSERVER6: return "SMBSERVER6";
  case SMBSERVER4: return "SMBSERVER4";
  case SMBREQUEST: return "SMBREQUEST";
#endif

#ifdef SUPPORT_PROXY
  case PROXYSLAVE: return "PROXYSLAVE";
  case PROXYPOST: return "PROXYPOST";
  case HTTPPOST: return "HTTPPOST";
#endif

#ifdef SUPPORT_HTTPS
  case HTTPSSERVER6: return "HTTPSSERVER6";
  case HTTPSSERVER4: return "HTTPSSERVER4";
  case HTTPSACCEPT: return "HTTPSACCEPT";
  case HTTPSACCEPT_CHECK: return "HTTPSACCEPT_CHECK";
  case HTTPSREQUEST: return "HTTPSREQUEST";
  case HTTPSRESPONSE: return "HTTPSRESPONSE";
  case HTTPSPOST: return "HTTPSPOST";
#endif

  case PUNISHMENT: return "PUNISHMENT";

  default: return "[invalid]";
  }
};
#endif

