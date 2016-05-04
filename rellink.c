/* Make links relative after mirroring.
 * For example, mirroring http://a.b/c/d.html gets "a.b/c/d.html",
 * but the links in d.html need to be adjusted, so that in d.html,
 * "/foo" becomes "../foo" */

#include <stralloc.h>
#include <buffer.h>
#include <errmsg.h>
#include <fmt.h>
#include <str.h>
#include <ctype.h>
#include <byte.h>
#include <scan.h>
#include <case.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <utime.h>
#include <string.h>
#include "havealloca.h"

static int canonicalize(stralloc* url,const char* baseurl) {
  /* for the comments, assume baseurl is "http://www.fefe.de/x/y.html" */
  int l=strlen(baseurl);
  char* dest=alloca(url->len+l+2);
  char* x=dest;
  if (stralloc_0(url)==0) return 0;
  if (url->s[0]=='#') {
    /* "#bar" -> "http://www.fefe.de/x/y.html#bar" */
    l=str_chr(baseurl,'#');
    byte_copy(x,l,baseurl);
    byte_copy(x+l,url->len+1,url->s);
  } else if (url->s[0]=='?') {
    /* "?bar" -> "http://www.fefe.de/x/y.html?bar" */
    for (l=0; baseurl[l]; ++l)
      if (baseurl[l]=='?' || baseurl[l]=='#')
	break;
    byte_copy(x,l,baseurl);
    byte_copy(x+l,url->len+1,url->s);
  } else if (url->s[0]=='/') {
    if (url->s[1]=='/') {
      /* "//fnord.fefe.de/bla.html" -> "http://fnord.fefe.de/bla.html" */
      l=str_chr(baseurl,':');
      if (baseurl[l]==':') ++l;
      byte_copy(x,l,baseurl);
      byte_copy(x+l,url->len+1,url->s);
    } else {
      /* "/bla.html" -> "http://www.fefe.de/bla.html" */
      l=str_chr(baseurl,':');
      if (baseurl[l]==':' && baseurl[l+1]=='/' && baseurl[l+2]=='/')
	l+=3;
      l+=str_chr(baseurl+l,'/');
      byte_copy(x,l,baseurl);
      byte_copy(x+l,url->len+1,url->s);
    }
  } else if (strstr(url->s,"://")) {
    /* "http://foo/bar" -> "http://foo/bar" */
    byte_copy(x,url->len+1,url->s);
  } else {
    /* "z.html" -> "http://www.fefe.de/x/z.html" */
    int k;
    for (k=l=0; baseurl[k]; ++k) {
      if (baseurl[k]=='/') l=k+1;
      if (baseurl[k]=='?') break;
    }
    byte_copy(x,l,baseurl);
    byte_copy(x+l,url->len+1,url->s);
  }
  return stralloc_copys(url,x);
}

static char* mmap_read_stat(const char* filename,struct stat* ss) {
  int fd=open(filename,O_RDONLY);
  char* map;
  map=0;
  if (fd>=0) {
    if (fstat(fd,ss)==0) {
      map=mmap(0,ss->st_size,PROT_READ,MAP_SHARED,fd,0);
      if (map==(char*)-1)
	map=0;
    }
    close(fd);
  }
  return map;
}

static int stralloc_istag(stralloc* sa,const char* in) {
  char* a;
  int l;
  l=strlen(in);
  a=sa->s;
  if (sa->len<l+2) return 0;
  if (*a != '<') return 0;
  ++a;
  if (!case_equalb(a,l,in)) return 0;
  a+=l;
  if (*a==' ' || *a=='\t' || *a=='\n' || *a=='\r' || *a=='>') return 1;
  return 0;
}

static int extractparam(stralloc* tag,const char* wanted,stralloc* before,stralloc* arg,stralloc* after) {
  int l=strlen(wanted);
  char* x,* max,* y;
  if (tag->len<l+4) return 0;

  max=tag->s+tag->len; y=0;
  x=tag->s;
  if (*x != '<') return 0;
  ++x;
  for (; x<max && !isspace(*x); ++x) ;
  for (; x<max && isspace(*x); ++x) ;
  for (; x<max-l; ++x) {
    if (max-x>l && case_equalb(x,l,wanted) && x[l]=='=') {
      x+=l+1;
      if (stralloc_copyb(before,tag->s,x-tag->s)==0) return 0;
      if (*x=='"') {
	++x;
	y=x;
	for (; x<max && *x!='"'; ++x) ;
	if (stralloc_copyb(arg,y,x-y)==0) return 0;
	++x;
      } else {
	y=x;
	for (; x<max && !isspace(*x) && *x!='>'; ++x) ;
	if (stralloc_copyb(arg,y,x-y)==0) return 0;
      }
      y=x;
      if (stralloc_copyb(after,y,max-y)==0) return 0;
      return 1;
    }
  }
  return 0;
}

static int mangleurl(stralloc* tag,const char* baseurl) {
  char* x;
  const char* y;
  static stralloc before,arg,after,tmp;
  int found;
  struct stat ss;
  found=0;
  if (stralloc_istag(tag,"a") || stralloc_istag(tag,"link"))
    found=1;
  else if (stralloc_istag(tag,"img") || stralloc_istag(tag,"frame"))
    found=2;
  if (!found) return 0;
  if (extractparam(tag,found==1?"href":"src",&before,&arg,&after)) {
    if (stralloc_starts(&arg,"/") ||
	stralloc_starts(&arg,"http://") ||
	stralloc_starts(&arg,"https://")) {
      canonicalize(&arg,baseurl);
    } else
      return 0;	/* url was already relative */
    if (stralloc_0(&arg)==0) return -1;
    stralloc_chop(&arg);
    x=arg.s+7; if (*x=='/') ++x;
    y=baseurl+7; if (*y=='/') ++y;

    /* now x is something like
      * "www.spiegel.de/img/0,1020,525770,00.jpg"
      * and baseurl is something like
      * "www.spiegel.de/panorama/0,1518,378421,00.html"
      * and we want to change x into "../img/0,1020,525770,00.jpg" */
    if (stat(x,&ss)!=0) return 0;

    for (;;) {
      int i=str_chr(x,'/');
      int j=str_chr(y,'/');
      if (i>0 && i==j && byte_equal(x,i,y)) {
	x+=i+1;
	y+=i+1;
	while (*x=='/') ++x;
	while (*y=='/') ++y;
      } else
	break;
    }
    stralloc_zero(&tmp);
    for (;;) {
      int i=str_chr(y,'/');
      if (y[i]=='/') {
	y+=i+1;
	while (*y=='/') ++y;
	if (stralloc_cats(&tmp,"../")==0) return -1;
      } else
	break;
    }
    {
      int i,needquote;
      for (i=needquote=0; x[i]; ++i)
	if (!isalnum(x[i]) && x[i]!='/' && x[i]!='_' && x[i]!='.') needquote=1;
      if (needquote) {
	if (stralloc_cats(&before,"\"")==0 ||
	    stralloc_cat(&before,&tmp)==0 ||
	    stralloc_cats(&before,x)==0 ||
	    stralloc_cats(&before,"\"")==0) return -1;
      } else
	if (stralloc_cat(&before,&tmp)==0 ||
	    stralloc_cats(&before,x)==0) return -1;
    }
    if (stralloc_cat(&before,&after)==0) return -1;
    if (stralloc_copy(tag,&before)==0) return -1;
  }
  return 0;
}

/* usage: rellink "http://www.nytimes.com/2005/10/06/international/middleeast/06cnd-prexy.html?ex=1129262400&en=30e300dafe83d0fc&ei=5065&partner=MYWAY" downloaded-data.html */
int main(int argc,char* argv[]) {
  char* baseurl;
  char* map,* max,* x;
  struct stat ss;
  static stralloc sa;
  if (argc!=3)
    die(0,"usage: rellink http://base/url downloaded-data.html");
  errmsg_iam("rellink");
  baseurl=argv[1];

  map=mmap_read_stat(argv[2],&ss);
  if (map==0)
    diesys(111,"open \"",argv[2],"\" failed");

  max=map+ss.st_size;
  for (x=map; x<max; ) {
    stralloc tag;
    /* copy non-tag */
    for (; x<max && *x!='<'; ++x)
      if (stralloc_append(&sa,x)==0)
nomem:
	die(111,"out of memory");

    if (x>=max) break;
    stralloc_copys(&tag,"");

    {
      int indq,insq,ok;
      indq=insq=ok=0;
      for (; x<max; ++x) {
	if (*x == '\'') insq^=1; else
	if (*x == '"') indq^=1;
	if (stralloc_append(&tag,x)==0) goto nomem;
	if (*x == '>' && !insq && !indq) { ok=1; ++x; break; }
      }
      if (ok)
	if (mangleurl(&tag,baseurl)==-1) goto nomem;
    }
    if (stralloc_cat(&sa,&tag)==0) goto nomem;
  }
  if (sa.len == ss.st_size && byte_equal(sa.s,ss.st_size,map)) return 0;
  munmap(map,ss.st_size);
  {
    struct utimbuf utb;
    int fd=open(argv[2],O_WRONLY|O_TRUNC,0600);
    if (fd==-1) die(111,"open(\"",argv[2],"\")");
    write(fd,sa.s,sa.len);
    close(fd);
    utb.actime=ss.st_atime;
    utb.modtime=ss.st_mtime;
    utime(argv[2],&utb);
  }
  return 0;
}
