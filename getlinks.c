#include <stralloc.h>
#include <buffer.h>
#include <errmsg.h>
#include <fmt.h>
#include <str.h>
#include <ctype.h>
#include <byte.h>
#include <scan.h>
#include <string.h>
#include "havealloca.h"

buffer* in;
int ungotten=-1;
static unsigned long line;

static int get() {
  char c;
  if (ungotten!=-1) {
    c=ungotten;
    ungotten=-1;
  } else {
    switch (buffer_getc(in,&c)) {
    case -1: diesys(1,"read error");
    case 0: return -1;
    }
  }
  if (c=='\n') ++line;
  return c;
}

static void unget(unsigned char c) {
  if (ungotten!=-1) die(1,">1 unget");
  if (c=='\n') --line;
  ungotten=c;
}

static int expectchar2(const char* s) {
  int r;
  r=get();
  if (r==-1) return -1;
  if (!s[str_chr(s,r)]) { unget(r); return 0; }
  return r;
}

static int expectchar(const char* s) {	/* expect one char out of s */
  int r;
  r=get();
  if (r==-1) return -1;
  if (!s[str_chr(s,r)]) { unget(r); return 0; }
  return 1;
}

static int eatwhitespace() {
  int r;
  while ((r=expectchar("\r\n\t "))==1);
  return r;
}

static int expect(const char* s) {
  int i,r;
  char buf[3];
  buf[2]=0;
  if (eatwhitespace()==-1) return -1;
  for (i=0; s[i]; ++i) {
    buf[0]=s[i]; if (buf[0]>='a' && buf[0]<='z') buf[0]-='a'-'A';
    buf[1]=s[i]; if (buf[1]>='A' && buf[1]<='A') buf[1]+='a'-'A';
    if ((r=expectchar(buf)) != 1) return r;
  }
  return 1;
}

static int readstring(stralloc* sa) {
  int r;
  int dq;
  if (eatwhitespace()==-1) return -1;
  stralloc_zero(sa);
  memset(sa->s,0,sa->a);
  if ((r=get())==-1) return -1;
  if (r=='\'' || r=='"') dq=r; else { dq=' '; unget(r); }
  while ((r=get())!=-1) {
    char c=r;
    if (r==dq || (dq==' ' && r=='>')) {
      if (r=='>') unget(r);
      return 1;
    }
    if (stralloc_append(sa,&c)==0) return -1;
  }
  return r;
}

static int readtoken(stralloc* sa) {
  int r;
  eatwhitespace();
  stralloc_zero(sa);
  memset(sa->s,0,sa->a);
  while ((r=get())!=-1) {
    char c=r;
    if (!isalnum(r) && r!=':' && r!='-' && r!='_') {
      unget(r);
      return 1;
    }
    if (c>='A' && c<='Z') c+='a'-'A';
    if (stralloc_append(sa,&c)==0) return -1;
  }
  return r;
}

struct param {
  const char* name;
  stralloc sa;
};

static int tag(int* special,stralloc* sa) {
  int r,spec;
again:
  stralloc_zero(sa); spec=0; if (special) *special=0;
  memset(sa->s,0,sa->a);
  if ((r=expect("<"))!=1) return r;
  if ((r=expectchar2("?!/"))) {
    if (r==-1) return -1;
    if (special) *special=r;
    spec=r;
  }
  if ((r=get())==-1) return -1;
  if (r=='-' && spec=='!') {
    int dashes;
    /* handle comments */
    if ((r=get())==-1) return -1;
    if (r!='-') return -1;
    dashes=0;
    for (;;) {
      if ((r=get())==-1) return -1;
      if (r=='>' && dashes>=2) {
	if (eatwhitespace()==-1) return -1;
	while ((r=get())!='<' && r!=-1) ;
	unget(r);
	goto again;
      }
      if (r=='-') ++dashes; else dashes=0;
    }
  }
#if 0
  if (r=='[') {
    int brackets;
    /* handle CDATA */
    if (expect("CDATA[")!=1) return -1;
    if (stralloc_cats(sa,"[CDATA[")==0) return -1;
    brackets=0;
    for (;;) {
      char c;
      if ((r=get())==-1) return -1;
      if (r=='>' && brackets==2) { unget(r); return 1; }
      if (r==']') ++brackets; else brackets=0;
      c=r;
      if (stralloc_append(sa,&c)==0) return -1;
    }
  }
#endif
  unget(r);
#if 1
  return readtoken(sa);
#else
  r=readtoken(sa);
  if (r>0) {
    buffer_puts(buffer_2,"got token \"");
    buffer_putsa(buffer_2,sa);
    buffer_putsflush(buffer_2,"\"\n");
  }
  return r;
#endif
}

static int params(struct param* P) {
  struct param* p;
  static stralloc sa;

  for (p=P; p->name; ++p) stralloc_zero(&p->sa);
  for (;;) {
    int r,found;
    if (eatwhitespace()==-1)
      return -1;
    if ((r=get())=='>') return 1;
    if (r=='/') {
      if ((r=get())=='>')
	return 1;
      else
	break;
    }
    unget(r);
    if (!isalnum(r)) return r;
    if ((r=readtoken(&sa))!=1)
      return r;
    for (found=0, p=P; p->name; ++p) {
      if (stralloc_equals(&sa,p->name)) {
	if (eatwhitespace()==-1)
	  return -1;
	if ((r=get())=='=') {
	  if ((r=readstring(&p->sa))!=1)
	    return r;
	  found=1;
	  break;
	} else
	  unget(r);
      }
    }
    if (!found) {

#if 0
      buffer_puts(buffer_2,"Unexpected param \"");
      buffer_putsa(buffer_2,&sa);
      buffer_putsflush(buffer_2,"\" found.  Ignoring...\n");
#endif

      eatwhitespace();
      if ((r=get())=='=') {
	if (readstring(&sa)==-1)
	  return -1;
      } else
	unget(r);
    }
  }
  return 1;
}

struct param href[] = {
  { "href", { 0 } },
  { 0, { 0 } }
};

struct param src[] = {
  { "src", { 0 } },
  { "lowsrc", { 0 } },
  { 0, { 0 } }
};

static void canonicalize(stralloc* url,const char* baseurl) {
  /* for the comments, assume baseurl is "http://www.fefe.de/x/y.html" */
  int l=str_len(baseurl);
  char* dest=alloca(url->len+l+2);
  char* x=dest;
  if (stralloc_0(url)==0) return;
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
  stralloc_copys(url,x);
  buffer_puts(buffer_1,x);
  buffer_putnlflush(buffer_1);
}

int main(int argc,char* argv[]) {
  const char* flags;
  char* baseurl;
  int r;
  int _a,_i,_f,_c;
  if (argc!=3)
    die(0,"usage: getlinks flags http://base/url < downloaded-data.html\n"
	  "	flags: a=A HREF, i=IMG SRC, f=FRAME SRC, c=LINK REL (CSS)");
  errmsg_iam("getlinks");
  flags=argv[1];
  baseurl=argv[2];

  _a=flags[str_chr(flags,'a')]=='a';
  _i=flags[str_chr(flags,'i')]=='i';
  _f=flags[str_chr(flags,'f')]=='f';
  _c=flags[str_chr(flags,'c')]=='c';

  in=buffer_0;

  for (;;) {
    int special;
    static stralloc t;
    if ((r=get())==-1) break;
    if (r!='<') continue;
    unget(r);
    if (tag(&special,&t)==-1) break;

#if 0
    buffer_puts(buffer_2,"tag: ");
    buffer_putsa(buffer_2,&t);
    buffer_putnlflush(buffer_2);
#endif

    if ((_a && stralloc_equals(&t,"a")) ||
	(_c && stralloc_equals(&t,"link"))) {
      if (params(href)==-1) break;
      if (href[0].sa.len)
	canonicalize(&href[0].sa,baseurl);
    } else if ((_i && stralloc_equals(&t,"img")) ||
	       (_f && stralloc_equals(&t,"frame"))) {
      if (params(src)==-1) break;
      if (src[0].sa.len)
	canonicalize(&src[0].sa,baseurl);
      if (t.s[0]=='i' && src[1].sa.len)
	canonicalize(&src[1].sa,baseurl);
    } else if (stralloc_equals(&t,"base")) {
      if (params(href)==-1) break;
      if (href[0].sa.len) {
	baseurl=malloc(href[0].sa.len+1);
	memcpy(baseurl,href[0].sa.s,href[0].sa.len);
	baseurl[href[0].sa.len]=0;
      }
    } else
      if (params(href+1)==-1) break;
    while ((r=get())!='<' && r!=-1) ;
    unget(r);
  }
  buffer_flush(buffer_1);
  return 0;
}
